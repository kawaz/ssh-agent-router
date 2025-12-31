use std::path::PathBuf;

// Test the CLI parsing module
#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn test_socket_config_parse_colon_format() {
        // Test basic colon-separated format
        let config_str = "/tmp/test.sock:SHA256:abc123,SHA256:def456";
        let config = ssh_agent_router::cli::SocketConfig::parse(config_str).unwrap();
        
        assert_eq!(config.path, PathBuf::from("/tmp/test.sock"));
        assert_eq!(config.allowed_fingerprints.len(), 2);
        assert_eq!(config.allowed_fingerprints[0], "SHA256:abc123");
        assert_eq!(config.allowed_fingerprints[1], "SHA256:def456");
        assert_eq!(config.denied_fingerprints.len(), 0);
    }

    #[test]
    fn test_socket_config_parse_with_denied() {
        // Test with denied fingerprints
        let config_str = "/tmp/test.sock:SHA256:allowed,-SHA256:denied";
        let config = ssh_agent_router::cli::SocketConfig::parse(config_str).unwrap();
        
        assert_eq!(config.path, PathBuf::from("/tmp/test.sock"));
        assert_eq!(config.allowed_fingerprints.len(), 1);
        assert_eq!(config.allowed_fingerprints[0], "SHA256:allowed");
        assert_eq!(config.denied_fingerprints.len(), 1);
        assert_eq!(config.denied_fingerprints[0], "SHA256:denied");
    }

    #[test]
    fn test_socket_config_parse_spaced_format() {
        // Test space-separated format with -- separators
        let args = vec![
            "--".to_string(),
            "/tmp/work.sock".to_string(),
            "SHA256:abc123,SHA256:def456".to_string(),
            "--".to_string(),
            "/tmp/personal.sock".to_string(),
            "SHA256:xyz789".to_string(),
        ];
        
        let configs = ssh_agent_router::cli::SocketConfig::parse_spaced(&args).unwrap();
        
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].path, PathBuf::from("/tmp/work.sock"));
        assert_eq!(configs[0].allowed_fingerprints.len(), 2);
        assert_eq!(configs[1].path, PathBuf::from("/tmp/personal.sock"));
        assert_eq!(configs[1].allowed_fingerprints.len(), 1);
    }

    #[test]
    fn test_socket_config_invalid_format() {
        // Test invalid format (no colon)
        let config_str = "/tmp/test.sock";
        let result = ssh_agent_router::cli::SocketConfig::parse(config_str);
        
        assert!(result.is_err());
    }
}

// Note: Full integration tests would require a running SSH agent
// These are unit tests for the parsing logic only
