use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;
use anyhow::{Context, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to upstream SSH agent socket
    #[serde(default = "default_upstream")]
    pub upstream: String,
    
    /// Socket configurations
    #[serde(default)]
    pub sockets: Vec<SocketEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocketEntry {
    /// Path to the socket file
    pub path: PathBuf,
    
    /// Allowed key fingerprints (whitelist)
    #[serde(default)]
    pub allowed: Vec<String>,
    
    /// Denied key fingerprints (blacklist)
    #[serde(default)]
    pub denied: Vec<String>,
}

fn default_upstream() -> String {
    std::env::var("SSH_AUTH_SOCK").unwrap_or_default()
}

impl Config {
    /// Get the config file path
    pub fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .context("Failed to get config directory")?
            .join("ssh-agent-router");
        
        fs::create_dir_all(&config_dir)
            .context("Failed to create config directory")?;
        
        Ok(config_dir.join("config.toml"))
    }

    /// Load config from the default location
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        
        if !path.exists() {
            return Ok(Self::default());
        }
        
        let content = fs::read_to_string(&path)
            .context("Failed to read config file")?;
        
        toml::from_str(&content)
            .context("Failed to parse config file")
    }

    /// Save config to the default location
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        let content = toml::to_string_pretty(self)
            .context("Failed to serialize config")?;
        
        fs::write(&path, content)
            .context("Failed to write config file")
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            upstream: default_upstream(),
            sockets: Vec::new(),
        }
    }
}
