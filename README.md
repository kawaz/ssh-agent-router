# ssh-agent-router

A program that creates multiple SSH authentication sockets with usage restrictions from a single upstream SSH agent. This allows you to control which SSH keys are available to different applications or contexts.

## Quick Start

1. **Build the project**:
   ```bash
   cargo build --release
   ```

2. **Get your SSH key fingerprints**:
   ```bash
   ssh-add -l
   ```

3. **Run with inline configuration**:
   ```bash
   ./target/release/ssh-agent-router \
     /tmp/work.sock:SHA256:your_work_key_fp \
     /tmp/personal.sock:SHA256:your_personal_key_fp
   ```

4. **Use the filtered socket**:
   ```bash
   export SSH_AUTH_SOCK=/tmp/work.sock
   ssh git@github.com  # Will only use work key
   ```

## Features

- **Key Filtering**: Create multiple sockets, each with its own set of allowed/denied keys
- **Command-line Interface**: Quick setup with command-line arguments
- **Configuration File**: Store your configuration in TOML format for easy management
- **Foreground Execution**: Runs in the foreground for easy monitoring
- **Subcommands**: List sockets, list keys, show status, and more
- **Security**: Message size limits and connection throttling to prevent DoS attacks

## Installation

Build from source:

```bash
cargo build --release
```

The binary will be available at `target/release/ssh-agent-router`.

## Usage

### Command-line Mode

Run with inline socket configurations:

```bash
ssh-agent-router \
  /tmp/work.sock:SHA256:abc123,SHA256:def456 \
  /tmp/personal.sock:SHA256:xyz789,-SHA256:abc123 \
  /tmp/restricted.sock:-SHA256:blocked
```

This creates three sockets:
- `/tmp/work.sock`: Only allows keys with fingerprints `SHA256:abc123` and `SHA256:def456`
- `/tmp/personal.sock`: Allows `SHA256:xyz789` but denies `SHA256:abc123`
- `/tmp/restricted.sock`: Allows all keys except `SHA256:blocked`

Specify a custom upstream socket:

```bash
ssh-agent-router --upstream /path/to/ssh-agent.sock /tmp/filtered.sock:SHA256:abc123
```

### Configuration File Mode

Create a configuration file at `~/.config/ssh-agent-router/config.toml`:

```toml
# Path to the upstream SSH agent socket
# Default: value of SSH_AUTH_SOCK environment variable
upstream = "/tmp/ssh-agent.sock"

# Socket configurations
[[sockets]]
path = "/tmp/ssh-router-work.sock"
allowed = ["SHA256:abc123", "SHA256:def456"]
denied = []

[[sockets]]
path = "/tmp/ssh-router-personal.sock"
allowed = ["SHA256:xyz789"]
denied = ["SHA256:abc123"]

[[sockets]]
path = "/tmp/ssh-router-all.sock"
allowed = []
denied = ["SHA256:blocked"]
```

Then run without arguments:

```bash
ssh-agent-router
```

## Subcommands

### list-socks

List all configured sockets:

```bash
ssh-agent-router list-socks
```

### list-keys

List all available keys from the upstream agent:

```bash
ssh-agent-router list-keys
```

### list

List both sockets and keys:

```bash
ssh-agent-router list
```

### status

Show router status and upstream connection:

```bash
ssh-agent-router status
```

### config

Interactive configuration editor (enhanced mode available):

```bash
ssh-agent-router config
ssh-agent-router config --enhanced
```

### upgrade

Self-upgrade functionality:

```bash
ssh-agent-router upgrade
ssh-agent-router upgrade --auto-upgrade
```

### Auto-start Management

Register/unregister auto-start on system boot:

```bash
ssh-agent-router register-autostart
ssh-agent-router unregister-autostart
```

## How It Works

1. **Upstream Connection**: Connects to the upstream SSH agent (specified or from `SSH_AUTH_SOCK`)
2. **Socket Creation**: Creates Unix domain sockets at the specified paths
3. **Request Filtering**: 
   - When a client requests a list of identities, only keys matching the filter rules are returned
   - When a client requests a signature, the request is rejected if the key is not allowed
4. **Foreground Operation**: Runs in the foreground, logging activity and handling Ctrl+C gracefully

## Key Fingerprint Format

Key fingerprints are in the SSH format:

```
SHA256:base64encodedfingerprint
```

You can get your key fingerprints using:

```bash
ssh-add -l
```

## Examples

### Example 1: Work vs Personal Keys

```bash
# Separate work and personal keys
ssh-agent-router \
  /tmp/work.sock:SHA256:work_key_fp1,SHA256:work_key_fp2 \
  /tmp/personal.sock:SHA256:personal_key_fp
```

Then use in different shells:

```bash
# In work terminal
export SSH_AUTH_SOCK=/tmp/work.sock
git pull  # Uses work keys only

# In personal terminal
export SSH_AUTH_SOCK=/tmp/personal.sock
git pull  # Uses personal keys only
```

### Example 2: Restricted Access

```bash
# Create a socket that denies a specific key
ssh-agent-router /tmp/safe.sock:-SHA256:compromised_key_fp
```

### Example 3: Multiple Restrictions

```bash
# Combine allowed and denied lists
ssh-agent-router /tmp/filtered.sock:SHA256:allowed1,SHA256:allowed2,-SHA256:denied1
```

## Future Enhancements

- Full TUI configuration editor with key selection
- Self-upgrade functionality
- OS-specific auto-start registration (launchd for macOS, systemd for Linux)
- Enhanced configuration management

## License

MIT License - see LICENSE file for details.
