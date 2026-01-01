use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const LABEL: &str = "com.github.kawaz.ssh-agent-router";

/// Get the LaunchAgents directory path
fn launch_agents_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Failed to get home directory")?;
    Ok(home.join("Library/LaunchAgents"))
}

/// Get the plist file path
pub fn plist_path() -> Result<PathBuf> {
    Ok(launch_agents_dir()?.join(format!("{}.plist", LABEL)))
}

/// Get the current executable path
fn executable_path() -> Result<PathBuf> {
    std::env::current_exe().context("Failed to get current executable path")
}

/// Generate the launchd plist content
fn generate_plist() -> Result<String> {
    let exe_path = executable_path()?;
    let config_path = crate::config::Config::config_path()?;

    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/ssh-agent-router.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/ssh-agent-router.err</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>SSH_AUTH_SOCK</key>
        <string>/tmp/ssh-agent.sock</string>
    </dict>
    <key>WatchPaths</key>
    <array>
        <string>{config_path}</string>
    </array>
</dict>
</plist>
"#,
        label = LABEL,
        exe_path = exe_path.display(),
        config_path = config_path.display()
    ))
}

/// Register the service with launchd
pub fn register() -> Result<()> {
    let plist = plist_path()?;
    let agents_dir = launch_agents_dir()?;

    // Create LaunchAgents directory if it doesn't exist
    fs::create_dir_all(&agents_dir)
        .with_context(|| format!("Failed to create directory: {:?}", agents_dir))?;

    // Generate and write plist
    let content = generate_plist()?;
    fs::write(&plist, &content)
        .with_context(|| format!("Failed to write plist file: {:?}", plist))?;

    println!("Created plist: {:?}", plist);

    // Load the service
    let output = Command::new("launchctl")
        .args(["load", "-w"])
        .arg(&plist)
        .output()
        .context("Failed to execute launchctl load")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("launchctl load failed: {}", stderr);
    }

    println!("Service registered and loaded: {}", LABEL);
    println!("\nThe service will start automatically at login.");
    println!("Use 'ssh-agent-router start' to start it now.");

    Ok(())
}

/// Unregister the service from launchd
pub fn unregister() -> Result<()> {
    let plist = plist_path()?;

    if !plist.exists() {
        println!("Service is not registered (plist not found)");
        return Ok(());
    }

    // Stop the service first (ignore errors)
    let _ = Command::new("launchctl")
        .args(["stop", LABEL])
        .output();

    // Unload the service
    let output = Command::new("launchctl")
        .args(["unload", "-w"])
        .arg(&plist)
        .output()
        .context("Failed to execute launchctl unload")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "not loaded" errors
        if !stderr.contains("Could not find specified service") {
            eprintln!("Warning: launchctl unload: {}", stderr);
        }
    }

    // Remove plist file
    fs::remove_file(&plist)
        .with_context(|| format!("Failed to remove plist file: {:?}", plist))?;

    println!("Service unregistered: {}", LABEL);

    Ok(())
}

/// Start the service
pub fn start() -> Result<()> {
    let plist = plist_path()?;

    if !plist.exists() {
        anyhow::bail!(
            "Service is not registered. Run 'ssh-agent-router register-autostart' first."
        );
    }

    let output = Command::new("launchctl")
        .args(["start", LABEL])
        .output()
        .context("Failed to execute launchctl start")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("launchctl start failed: {}", stderr);
    }

    println!("Service started: {}", LABEL);

    Ok(())
}

/// Stop the service
pub fn stop() -> Result<()> {
    let output = Command::new("launchctl")
        .args(["stop", LABEL])
        .output()
        .context("Failed to execute launchctl stop")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Check if service is simply not running
        if stderr.contains("Could not find specified service") {
            println!("Service is not running");
            return Ok(());
        }
        anyhow::bail!("launchctl stop failed: {}", stderr);
    }

    println!("Service stopped: {}", LABEL);

    Ok(())
}

/// Check if the service is running
pub fn is_running() -> Result<bool> {
    let output = Command::new("launchctl")
        .args(["list", LABEL])
        .output()
        .context("Failed to execute launchctl list")?;

    Ok(output.status.success())
}

/// Get service status
pub fn status() -> Result<String> {
    let plist = plist_path()?;

    if !plist.exists() {
        return Ok("Not registered".to_string());
    }

    let output = Command::new("launchctl")
        .args(["list", LABEL])
        .output()
        .context("Failed to execute launchctl list")?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse PID from output (format: "PID\tStatus\tLabel")
        if let Some(line) = stdout.lines().next() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 1 {
                let pid = parts[0].trim();
                if pid == "-" {
                    return Ok("Registered (not running)".to_string());
                } else {
                    return Ok(format!("Running (PID: {})", pid));
                }
            }
        }
        Ok("Registered".to_string())
    } else {
        Ok("Registered (not loaded)".to_string())
    }
}
