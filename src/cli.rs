use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "ssh-agent-router")]
#[command(about = "SSH agent router with key filtering capabilities", long_about = None)]
pub struct Cli {
    /// Path to upstream SSH agent socket (default: $SSH_AUTH_SOCK)
    #[arg(long, default_value = "", value_name = "PATH")]
    pub upstream: String,

    /// Socket configurations in format: path:fingerprint1,fingerprint2,-fingerprint3
    #[arg(value_name = "SOCKET_CONFIG")]
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
    
    /// Register auto-start on system boot
    RegisterAutostart,
    
    /// Unregister auto-start on system boot
    UnregisterAutostart,
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
}
