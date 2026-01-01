use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "ssh-agent-router")]
#[command(about = "SSH agent router with key filtering capabilities")]
#[command(long_about = "Create multiple SSH authentication sockets with usage restrictions from a single upstream SSH agent.\n\nExamples:\n  ssh-agent-router /tmp/work.sock:SHA256:abc123,SHA256:def456 /tmp/personal.sock:SHA256:xyz789\n  ssh-agent-router -- /tmp/work.sock SHA256:abc123,SHA256:def456 -- /tmp/personal.sock SHA256:xyz789")]
pub struct Cli {
    /// Path to upstream SSH agent socket (default: $SSH_AUTH_SOCK)
    #[arg(long, default_value = "", value_name = "PATH")]
    pub upstream: String,

    /// Socket configurations in format: path:fingerprint1,fingerprint2,-fingerprint3
    /// Or use space-separated format: path fingerprint1,fingerprint2,-fingerprint3
    /// 
    /// Examples:
    ///   /tmp/work.sock:SHA256:abc123,SHA256:def456
    ///   /tmp/personal.sock:SHA256:xyz789,-SHA256:blocked
    ///   -- /tmp/work.sock SHA256:abc123 -- /tmp/personal.sock SHA256:xyz789
    #[arg(value_name = "SOCKET_CONFIG", trailing_var_arg = true)]
    pub sockets: Vec<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List all created sockets
    ListSocks,
    
    /// List all available keys from upstream
    ListKeys,
    
    /// List both sockets and keys
    List,
    
    /// Show router status
    Status,
    
    /// TUI-based configuration editor
    Config {
        /// Enable enhanced mode
        #[arg(long)]
        enhanced: bool,
    },
    
    /// Upgrade the application
    Upgrade {
        /// Enable auto-upgrade
        #[arg(long)]
        auto_upgrade: bool,
    },
    
    /// Register auto-start on system boot (macOS: launchd)
    RegisterAutostart,

    /// Unregister auto-start on system boot
    UnregisterAutostart,

    /// Start the background service
    Start,

    /// Stop the background service
    Stop,
}

#[derive(Debug, Clone)]
pub struct SocketConfig {
    pub path: PathBuf,
    pub allowed_fingerprints: Vec<String>,
    pub denied_fingerprints: Vec<String>,
}

impl SocketConfig {
    pub fn parse(config_str: &str) -> anyhow::Result<Self> {
        let parts: Vec<&str> = config_str.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!(
                "Invalid socket config format. Expected 'path:fingerprint1,fingerprint2'"
            ));
        }

        let path = PathBuf::from(parts[0]);
        let fingerprints: Vec<&str> = parts[1].split(',').collect();
        
        let mut allowed = Vec::new();
        let mut denied = Vec::new();
        
        for fp in fingerprints {
            let fp = fp.trim();
            if fp.is_empty() {
                continue;
            }
            if fp.starts_with('-') {
                denied.push(fp[1..].to_string());
            } else {
                allowed.push(fp.to_string());
            }
        }

        Ok(SocketConfig {
            path,
            allowed_fingerprints: allowed,
            denied_fingerprints: denied,
        })
    }
    
    /// Parse from space-separated arguments (alternative format)
    /// Format: path fingerprint1,fingerprint2,...
    pub fn parse_spaced(args: &[String]) -> anyhow::Result<Vec<Self>> {
        let mut configs = Vec::new();
        let mut i = 0;
        
        while i < args.len() {
            // Skip "--" separators
            if args[i] == "--" {
                i += 1;
                continue;
            }
            
            // We need at least path and fingerprints
            if i + 1 >= args.len() {
                // Try parsing as colon-separated format
                configs.push(Self::parse(&args[i])?);
                i += 1;
                continue;
            }
            
            let path = PathBuf::from(&args[i]);
            let fingerprints: Vec<&str> = args[i + 1].split(',').collect();
            
            let mut allowed = Vec::new();
            let mut denied = Vec::new();
            
            for fp in fingerprints {
                let fp = fp.trim();
                if fp.is_empty() {
                    continue;
                }
                if fp.starts_with('-') {
                    denied.push(fp[1..].to_string());
                } else {
                    allowed.push(fp.to_string());
                }
            }

            configs.push(SocketConfig {
                path,
                allowed_fingerprints: allowed,
                denied_fingerprints: denied,
            });
            
            i += 2;
        }
        
        Ok(configs)
    }
}

