use crate::agent::{Agent, SshKey};
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::io::{Read, Write};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task;

pub struct FilteredSocket {
    path: PathBuf,
    allowed_fingerprints: HashSet<String>,
    denied_fingerprints: HashSet<String>,
    agent: Agent,
}

impl FilteredSocket {
    pub fn new(
        path: PathBuf,
        allowed: Vec<String>,
        denied: Vec<String>,
        agent: Agent,
    ) -> Self {
        Self {
            path,
            allowed_fingerprints: allowed.into_iter().collect(),
            denied_fingerprints: denied.into_iter().collect(),
            agent,
        }
    }

    fn is_key_allowed(&self, key: &SshKey) -> bool {
        // If in denied list, reject
        if self.denied_fingerprints.contains(&key.fingerprint) {
            return false;
        }

        // If allowed list is empty, allow all (except denied)
        if self.allowed_fingerprints.is_empty() {
            return true;
        }

        // Otherwise, must be in allowed list
        self.allowed_fingerprints.contains(&key.fingerprint)
    }

    fn filter_identities_response(&self, response: &[u8]) -> Result<Vec<u8>> {
        if response.len() < 5 || response[4] != 12 {
            // Not SSH_AGENT_IDENTITIES_ANSWER
            return Ok(response.to_vec());
        }

        // Get all keys from upstream
        let all_keys = self.agent.list_keys()?;
        let filtered_keys: Vec<&SshKey> = all_keys
            .iter()
            .filter(|k| self.is_key_allowed(k))
            .collect();

        // Rebuild response with filtered keys
        let mut new_response = Vec::new();
        
        // Response type
        new_response.push(12); // SSH_AGENT_IDENTITIES_ANSWER
        
        // Number of keys
        let num_keys = filtered_keys.len() as u32;
        new_response.extend_from_slice(&num_keys.to_be_bytes());

        for key in filtered_keys {
            // Key blob length
            let blob_len = key.blob.len() as u32;
            new_response.extend_from_slice(&blob_len.to_be_bytes());
            
            // Key blob
            new_response.extend_from_slice(&key.blob);
            
            // Comment length
            let comment_len = key.comment.len() as u32;
            new_response.extend_from_slice(&comment_len.to_be_bytes());
            
            // Comment
            new_response.extend_from_slice(key.comment.as_bytes());
        }

        // Prepend total length
        let total_len = new_response.len() as u32;
        let mut final_response = total_len.to_be_bytes().to_vec();
        final_response.extend_from_slice(&new_response);

        Ok(final_response)
    }

    fn should_filter_request(&self, request: &[u8]) -> bool {
        // Check if this is a sign request (SSH_AGENTC_SIGN_REQUEST = 13)
        if request.len() > 4 && request[4] == 13 {
            // We need to check if the key being used is allowed
            return true;
        }
        false
    }

    fn filter_sign_request(&self, request: &[u8]) -> Result<Option<Vec<u8>>> {
        if request.len() < 9 {
            return Ok(None);
        }

        // Parse key blob from sign request
        let blob_len = u32::from_be_bytes([
            request[5],
            request[6],
            request[7],
            request[8],
        ]) as usize;

        if request.len() < 9 + blob_len {
            return Ok(None);
        }

        let blob = &request[9..9 + blob_len];
        
        // Get all keys and check if this blob is allowed
        let all_keys = self.agent.list_keys()?;
        for key in &all_keys {
            if key.blob == blob {
                if !self.is_key_allowed(key) {
                    // Return failure response
                    let failure_response = vec![0, 0, 0, 1, 5]; // SSH_AGENT_FAILURE
                    return Ok(Some(failure_response));
                }
                break;
            }
        }

        Ok(None)
    }

    fn handle_client(&self, mut stream: UnixStream) -> Result<()> {
        // Maximum message size (1MB should be more than enough for SSH agent)
        const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;
        
        loop {
            // Read request length
            let mut len_buf = [0u8; 4];
            match stream.read_exact(&mut len_buf) {
                Ok(_) => {},
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }

            let msg_len = u32::from_be_bytes(len_buf);
            
            // Validate message size to prevent DoS
            if msg_len > MAX_MESSAGE_SIZE {
                eprintln!("Message too large: {} bytes (max: {})", msg_len, MAX_MESSAGE_SIZE);
                return Err(anyhow::anyhow!("Message exceeds maximum size"));
            }
            
            // Read request
            let mut request = vec![0u8; msg_len as usize];
            stream.read_exact(&mut request)?;

            // Full request with length prefix
            let mut full_request = len_buf.to_vec();
            full_request.extend_from_slice(&request);

            // Check if this is a list identities request
            let is_list = !request.is_empty() && request[0] == 11;

            // Check if this is a sign request that needs filtering
            if self.should_filter_request(&full_request) {
                if let Some(failure) = self.filter_sign_request(&full_request)? {
                    stream.write_all(&failure)?;
                    stream.flush()?;
                    continue;
                }
            }

            // Forward to upstream
            let response = self.agent.forward_request(&full_request)?;

            // Filter response if it's a list identities response
            let final_response = if is_list {
                self.filter_identities_response(&response)?
            } else {
                response
            };

            stream.write_all(&final_response)?;
            stream.flush()?;
        }

        Ok(())
    }

    pub async fn start(&self) -> Result<()> {
        // Maximum concurrent connections per socket
        const MAX_CONCURRENT_CONNECTIONS: usize = 100;
        
        // Remove socket file if it exists
        if self.path.exists() {
            std::fs::remove_file(&self.path)
                .with_context(|| format!("Failed to remove existing socket at {:?}", self.path))?;
        }

        // Create parent directory if needed
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {:?}", parent))?;
        }

        let listener = UnixListener::bind(&self.path)
            .with_context(|| format!("Failed to bind socket at {:?}", self.path))?;

        println!("Listening on socket: {:?}", self.path);

        // Clone what we need for the task
        let path = self.path.clone();
        let allowed = self.allowed_fingerprints.clone();
        let denied = self.denied_fingerprints.clone();
        let agent = self.agent.clone();
        
        // Semaphore to limit concurrent connections
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

        task::spawn_blocking(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let socket = FilteredSocket {
                            path: path.clone(),
                            allowed_fingerprints: allowed.clone(),
                            denied_fingerprints: denied.clone(),
                            agent: agent.clone(),
                        };
                        
                        // Try to acquire a permit from the semaphore
                        let sem_clone = semaphore.clone();
                        match sem_clone.try_acquire_owned() {
                            Ok(permit) => {
                                std::thread::spawn(move || {
                                    // Permit will be automatically released when dropped
                                    let _permit = permit;
                                    if let Err(e) = socket.handle_client(stream) {
                                        eprintln!("Error handling client: {}", e);
                                    }
                                });
                            }
                            Err(_) => {
                                eprintln!("Connection limit reached, rejecting connection");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Connection error: {}", e);
                    }
                }
            }
        });

        Ok(())
    }
}

impl Drop for FilteredSocket {
    fn drop(&mut self) {
        // Clean up socket file
        let _ = std::fs::remove_file(&self.path);
    }
}
