use anyhow::{Context, Result};
use sha2::{Sha256, Digest};
use std::os::unix::net::UnixStream;
use std::io::{Read, Write};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine;

#[derive(Debug, Clone)]
pub struct SshKey {
    pub key_type: String,
    pub blob: Vec<u8>,
    pub comment: String,
    pub fingerprint: String,
}

impl SshKey {
    pub fn from_blob(key_type: String, blob: Vec<u8>, comment: String) -> Self {
        let fingerprint = Self::calculate_fingerprint(&blob);
        Self {
            key_type,
            blob,
            comment,
            fingerprint,
        }
    }

    fn calculate_fingerprint(blob: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(blob);
        let hash = hasher.finalize();
        
        format!("SHA256:{}", STANDARD_NO_PAD.encode(&hash))
    }
}

#[derive(Clone)]
pub struct Agent {
    upstream_path: String,
}

impl Agent {
    pub fn new(upstream_path: String) -> Self {
        Self { upstream_path }
    }

    fn connect(&self) -> Result<UnixStream> {
        let path = if self.upstream_path.is_empty() {
            std::env::var("SSH_AUTH_SOCK")
                .context("SSH_AUTH_SOCK not set and no upstream path provided")?
        } else {
            self.upstream_path.clone()
        };

        UnixStream::connect(&path)
            .with_context(|| format!("Failed to connect to SSH agent at {}", path))
    }

    pub fn list_keys(&self) -> Result<Vec<SshKey>> {
        let mut stream = self.connect()?;
        
        // SSH_AGENTC_REQUEST_IDENTITIES
        let request: [u8; 5] = [0, 0, 0, 1, 11];
        stream.write_all(&request)?;
        stream.flush()?;

        // Read response
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let msg_len = u32::from_be_bytes(len_buf);

        let mut msg_buf = vec![0u8; msg_len as usize];
        stream.read_exact(&mut msg_buf)?;

        // Parse response
        if msg_buf.is_empty() || msg_buf[0] != 12 {
            // SSH_AGENT_IDENTITIES_ANSWER
            return Err(anyhow::anyhow!("Unexpected response from SSH agent"));
        }

        let mut keys = Vec::new();
        let mut pos = 1;

        // Read number of keys
        if msg_buf.len() < pos + 4 {
            return Ok(keys);
        }
        let num_keys = u32::from_be_bytes([
            msg_buf[pos],
            msg_buf[pos + 1],
            msg_buf[pos + 2],
            msg_buf[pos + 3],
        ]);
        pos += 4;

        for _ in 0..num_keys {
            if msg_buf.len() < pos + 4 {
                break;
            }

            // Read key blob length
            let blob_len = u32::from_be_bytes([
                msg_buf[pos],
                msg_buf[pos + 1],
                msg_buf[pos + 2],
                msg_buf[pos + 3],
            ]) as usize;
            pos += 4;

            if msg_buf.len() < pos + blob_len {
                break;
            }

            // Read key blob
            let blob = msg_buf[pos..pos + blob_len].to_vec();
            pos += blob_len;

            // Parse key type from blob
            let key_type = if blob.len() > 4 {
                let type_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
                if blob.len() >= 4 + type_len {
                    String::from_utf8_lossy(&blob[4..4 + type_len]).to_string()
                } else {
                    "unknown".to_string()
                }
            } else {
                "unknown".to_string()
            };

            // Read comment length
            if msg_buf.len() < pos + 4 {
                break;
            }
            let comment_len = u32::from_be_bytes([
                msg_buf[pos],
                msg_buf[pos + 1],
                msg_buf[pos + 2],
                msg_buf[pos + 3],
            ]) as usize;
            pos += 4;

            if msg_buf.len() < pos + comment_len {
                break;
            }

            // Read comment
            let comment = String::from_utf8_lossy(&msg_buf[pos..pos + comment_len]).to_string();
            pos += comment_len;

            keys.push(SshKey::from_blob(key_type, blob, comment));
        }

        Ok(keys)
    }

    pub fn forward_request(&self, request: &[u8]) -> Result<Vec<u8>> {
        let mut stream = self.connect()?;
        
        stream.write_all(request)?;
        stream.flush()?;

        // Read response length
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let msg_len = u32::from_be_bytes(len_buf);

        // Read response
        let mut response = vec![0u8; msg_len as usize];
        stream.read_exact(&mut response)?;

        // Prepend length
        let mut full_response = len_buf.to_vec();
        full_response.extend_from_slice(&response);

        Ok(full_response)
    }
}
