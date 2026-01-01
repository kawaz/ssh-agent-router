use anyhow::Result;
use clap::Parser;
use ssh_agent_router::cli::{Cli, Commands, SocketConfig};
use ssh_agent_router::config::{self, Config};
use ssh_agent_router::agent::Agent;
use ssh_agent_router::socket::FilteredSocket;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle subcommands
    if let Some(command) = cli.command {
        return handle_command(command).await;
    }

    // Load configuration
    let config = if cli.sockets.is_empty() {
        // No arguments provided, load from config file
        Config::load()?
    } else {
        // Use command-line arguments
        let mut cfg = Config::default();
        cfg.upstream = if cli.upstream.is_empty() {
            std::env::var("SSH_AUTH_SOCK").unwrap_or_default()
        } else {
            cli.upstream.clone()
        };

        // Try to parse as space-separated format first
        let socket_configs = if cli.sockets.iter().any(|s| s.contains(':')) {
            // Colon-separated format
            cli.sockets.iter()
                .map(|s| SocketConfig::parse(s))
                .collect::<Result<Vec<_>>>()?
        } else {
            // Space-separated format (with -- separators)
            SocketConfig::parse_spaced(&cli.sockets)?
        };

        for socket_cfg in socket_configs {
            cfg.sockets.push(config::SocketEntry {
                path: socket_cfg.path,
                allowed: socket_cfg.allowed_fingerprints,
                denied: socket_cfg.denied_fingerprints,
            });
        }
        cfg
    };

    if config.sockets.is_empty() {
        eprintln!("No sockets configured. Use --help for usage information.");
        eprintln!("Or run 'ssh-agent-router config' to create a configuration.");
        return Ok(());
    }

    // Start the router
    println!("Starting SSH Agent Router");
    println!("Upstream: {}", config.upstream);
    println!("Configured sockets: {}", config.sockets.len());

    let agent = Agent::new(config.upstream.clone());

    // Create all filtered sockets
    let mut sockets = Vec::new();
    for socket_entry in config.sockets {
        let filtered_socket = Arc::new(FilteredSocket::new(
            socket_entry.path.clone(),
            socket_entry.allowed,
            socket_entry.denied,
            agent.clone(),
        ));
        
        println!("Starting socket: {:?}", socket_entry.path);
        filtered_socket.start().await?;
        sockets.push(filtered_socket);
    }

    println!("\nSSH Agent Router is running in foreground mode.");
    println!("Press Ctrl+C to stop.");

    // Keep running
    tokio::signal::ctrl_c().await?;
    println!("\nShutting down...");

    Ok(())
}

async fn handle_command(command: Commands) -> Result<()> {
    match command {
        Commands::ListSocks => {
            let config = Config::load()?;
            println!("Configured sockets:");
            for (i, socket) in config.sockets.iter().enumerate() {
                println!("  {}. {:?}", i + 1, socket.path);
                if !socket.allowed.is_empty() {
                    println!("     Allowed: {}", socket.allowed.join(", "));
                }
                if !socket.denied.is_empty() {
                    println!("     Denied: {}", socket.denied.join(", "));
                }
            }
        }
        Commands::ListKeys => {
            let config = Config::load()?;
            let agent = Agent::new(config.upstream);
            let keys = agent.list_keys()?;
            
            println!("Available keys from upstream:");
            for (i, key) in keys.iter().enumerate() {
                println!("  {}. {} ({})", i + 1, key.fingerprint, key.key_type);
                println!("     Comment: {}", key.comment);
            }
        }
        Commands::List => {
            // List sockets
            let config = Config::load()?;
            println!("Configured sockets:");
            for (i, socket) in config.sockets.iter().enumerate() {
                println!("  {}. {:?}", i + 1, socket.path);
                if !socket.allowed.is_empty() {
                    println!("     Allowed: {}", socket.allowed.join(", "));
                }
                if !socket.denied.is_empty() {
                    println!("     Denied: {}", socket.denied.join(", "));
                }
            }
            
            println!();
            
            // List keys
            let agent = Agent::new(config.upstream);
            let keys = agent.list_keys()?;
            
            println!("Available keys from upstream:");
            for (i, key) in keys.iter().enumerate() {
                println!("  {}. {} ({})", i + 1, key.fingerprint, key.key_type);
                println!("     Comment: {}", key.comment);
            }
        }
        Commands::Status => {
            let config = Config::load()?;
            println!("SSH Agent Router Status");
            println!("=======================");
            println!("Upstream: {}", config.upstream);
            println!("Configured sockets: {}", config.sockets.len());

            // Try to connect to upstream
            let agent = Agent::new(config.upstream.clone());
            match agent.list_keys() {
                Ok(keys) => {
                    println!("Upstream status: Connected");
                    println!("Available keys: {}", keys.len());
                }
                Err(e) => {
                    println!("Upstream status: Error - {}", e);
                }
            }

            // Show service status on macOS
            #[cfg(target_os = "macos")]
            {
                println!();
                println!("Service Status (launchd)");
                println!("------------------------");
                match ssh_agent_router::launchd::status() {
                    Ok(status) => println!("Status: {}", status),
                    Err(e) => println!("Status: Error - {}", e),
                }
                match ssh_agent_router::launchd::plist_path() {
                    Ok(path) => println!("Plist: {:?}", path),
                    Err(_) => {}
                }
            }
        }
        Commands::Config { enhanced } => {
            println!("Configuration editor");
            if enhanced {
                println!("Enhanced mode enabled");
            }
            
            let config = Config::load()?;
            let agent = Agent::new(config.upstream.clone());
            
            // Show current configuration
            println!("\nCurrent configuration:");
            println!("Upstream: {}", config.upstream);
            println!("Sockets: {}", config.sockets.len());
            
            // List available keys
            println!("\nAvailable keys from upstream:");
            match agent.list_keys() {
                Ok(keys) => {
                    for (i, key) in keys.iter().enumerate() {
                        println!("  {}. {} ({})", i + 1, key.fingerprint, key.key_type);
                        println!("     Comment: {}", key.comment);
                    }
                }
                Err(e) => {
                    println!("Error listing keys: {}", e);
                }
            }
            
            println!("\nNote: Full TUI configuration editor is planned for future releases.");
            println!("For now, please edit the configuration file manually at:");
            println!("{:?}", Config::config_path()?);
        }
        Commands::Upgrade { auto_upgrade } => {
            println!("Upgrade command");
            if auto_upgrade {
                println!("Auto-upgrade enabled");
            }
            println!("Note: Self-upgrade functionality is planned for future releases.");
        }
        Commands::RegisterAutostart => {
            #[cfg(target_os = "macos")]
            {
                ssh_agent_router::launchd::register()?;
            }
            #[cfg(target_os = "linux")]
            {
                println!("Note: Linux systemd support is planned for future releases.");
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                println!("Auto-start registration is not supported on this platform.");
            }
        }
        Commands::UnregisterAutostart => {
            #[cfg(target_os = "macos")]
            {
                ssh_agent_router::launchd::unregister()?;
            }
            #[cfg(target_os = "linux")]
            {
                println!("Note: Linux systemd support is planned for future releases.");
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                println!("Auto-start unregistration is not supported on this platform.");
            }
        }
        Commands::Start => {
            #[cfg(target_os = "macos")]
            {
                ssh_agent_router::launchd::start()?;
            }
            #[cfg(not(target_os = "macos"))]
            {
                println!("Service start is not supported on this platform.");
                println!("Run 'ssh-agent-router' directly to start the router.");
            }
        }
        Commands::Stop => {
            #[cfg(target_os = "macos")]
            {
                ssh_agent_router::launchd::stop()?;
            }
            #[cfg(not(target_os = "macos"))]
            {
                println!("Service stop is not supported on this platform.");
            }
        }
    }

    Ok(())
}
