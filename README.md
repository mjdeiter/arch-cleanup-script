Here's your updated README.md with all emojis removed from the Features list, Audit section, and everywhere else.

````markdown name=README.md url=https://github.com/mjdeiter/arch-cleanup-script/blob/bd59946dfe3eb37c8a77e3a1e759bc2a807a8a5c/README.md
# CachyOS System Cleanup Script

Enterprise-grade system maintenance script for CachyOS and Arch-based Linux distributions. Automates package updates, cache cleaning, orphan removal, and system cleanup with robust error handling and safety features.

## Features

- **Package Management**: Update system packages (pacman/yay), clean package cache, remove orphans
- **Log Cleanup**: Clean system logs and journald entries with configurable retention
- **Cache Management**: Clean user caches, trash folders, and temporary directories
- **Safety First**: Dry-run mode, interactive confirmations, whitelist support, snapshot backups
- **Parallel Execution**: Safe parallel task execution with proper pacman lock serialization
- **History Tracking**: JSON-based cleanup history with statistics
- **Cron Integration**: Easy automated scheduling
- **Export Reports**: JSON and CSV output formats

## Requirements

### Required Dependencies
```bash
pacman find du grep sed awk date mktemp tar flock
```

### Optional Dependencies
```bash
# For enhanced features
sudo pacman -S bc cronie jq logrotate
```

## Installation

### Quick Install
```bash
# Download script
wget https://raw.githubusercontent.com/yourusername/cachyos-cleanup/main/cachyos_cleanup.sh

# Make executable
chmod +x cachyos_cleanup.sh

# Move to system path (optional)
sudo mv cachyos_cleanup.sh /usr/local/bin/cachyos-cleanup
```

### From Source
```bash
git clone https://github.com/yourusername/cachyos-cleanup.git
cd cachyos-cleanup
chmod +x cachyos_cleanup.sh
sudo ./cachyos_cleanup.sh
```

## Usage

### Basic Usage
```bash
# Run full cleanup
sudo ./cachyos_cleanup.sh

# Interactive mode (confirm each operation)
sudo ./cachyos_cleanup.sh -i

# Dry run (preview changes only)
sudo ./cachyos_cleanup.sh --analyze

# Verbose output
sudo ./cachyos_cleanup.sh -v
```

### Selective Cleaning
```bash
# Only clean cache and orphans
sudo ./cachyos_cleanup.sh --clean-cache --clean-orphans

# Skip system updates
sudo ./cachyos_cleanup.sh --skip-update

# Disable specific tasks
sudo ./cachyos_cleanup.sh --no-logs --no-user-cache
```

### Automation
```bash
# Install daily cron job
sudo ./cachyos_cleanup.sh --install-cron @daily

# Install weekly cron job
sudo ./cachyos_cleanup.sh --install-cron @weekly

# Custom schedule (2 AM daily)
sudo ./cachyos_cleanup.sh --install-cron "0 2 * * *"

# Remove cron job
sudo ./cachyos_cleanup.sh --remove-cron
```

### Reports & History
```bash
# Export JSON report
sudo ./cachyos_cleanup.sh --json

# Export CSV report
sudo ./cachyos_cleanup.sh --csv

# View cleanup history
sudo ./cachyos_cleanup.sh --history
```

## Configuration

### Create Config File
```bash
sudo ./cachyos_cleanup.sh --create-config
```

### Edit Configuration
```bash
sudo nano /etc/cachyos-cleanup.conf
```

### Key Settings
```bash
# Log retention (days, range: 1-365)
LOG_RETENTION_DAYS=7

# Package cache versions to keep (range: 1-10)
CACHE_VERSIONS=3

# Minimum free disk space warning threshold (%)
MIN_DISK_SPACE_PERCENT=5

# Maximum system load threshold (normalized)
MAX_LOAD_THRESHOLD=0.8

# Enable history tracking
ENABLE_HISTORY=true

# Enable automatic snapshots before cleanup
ENABLE_BACKUPS=true

# Parallel cleanup jobs (range: 1-32)
PARALLEL_JOBS=4

# Logging level (DEBUG, INFO, WARN, ERROR)
LOG_LEVEL=INFO
```

## Command-Line Options

### General Options
| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message |
| `--version` | Show script version |
| `-v, --verbose` | Enable verbose logging (DEBUG level) |

### Execution Modes
| Option | Description |
|--------|-------------|
| `-i, --interactive` | Ask for confirmation before each operation |
| `-n, --non-interactive` | Run without user confirmations |
| `-a, --analyze` | Analyze system without making changes |
| `--dry-run` | Preview all changes without executing |

### Selective Cleaning
| Option | Description |
|--------|-------------|
| `--skip-update` | Skip system package updates |
| `--clean-packages` | Enable package updates only |
| `--clean-cache` | Enable package cache cleanup only |
| `--clean-orphans` | Enable orphan package removal only |
| `--clean-logs` | Enable system log cleanup only |
| `--clean-user-cache` | Enable user cache cleanup only |
| `--no-packages` | Disable package updates |
| `--no-cache` | Disable cache cleanup |
| `--no-orphans` | Disable orphan removal |
| `--no-logs` | Disable log cleanup |
| `--no-user-cache` | Disable user cache cleanup |

### Advanced Options
| Option | Description |
|--------|-------------|
| `--create-config` | Create sample configuration file |
| `--no-emoji` | Disable emoji output |
| `--history` | Show cleanup history |
| `--json` | Export cleanup report as JSON |
| `--csv` | Export cleanup report as CSV |
| `--install-cron [SCHEDULE]` | Install cron job |
| `--remove-cron` | Remove cron job |

## Safety Features

### Pacman Lock Serialization
All pacman/yay/paccache operations are serialized to prevent lock conflicts. The script uses `flock` to ensure safe concurrent execution.

### Snapshot Backups
Before cleanup, the script creates snapshots of:
- Package list
- Configuration files
- Data directory

Snapshots are stored in `/var/lib/cachyos-cleanup/snapshots/`

### Whitelist Support
Create `/var/lib/cachyos-cleanup/whitelist.conf` to exclude paths from cleanup:
```bash
/var/log/important.log
/home/user/.cache/keep-this
```

### Safe /var/tmp Cleanup
Uses `systemd-tmpfiles --clean` and age-based filtering (7 days) instead of aggressive deletion.

## Examples

### Weekly Maintenance
```bash
#!/bin/bash
# Run weekly cleanup with updates
sudo cachyos-cleanup -n --skip-update
```

### Monthly Deep Clean
```bash
#!/bin/bash
# Monthly deep clean with all features
sudo cachyos-cleanup -v --json --csv
```

### Cron-Friendly Run
```bash
# Colors/emoji auto-disabled when not a TTY
sudo cachyos-cleanup -n > /var/log/cleanup.log 2>&1
```

## Output Example

```
╔══════════════════════════════════════════════════════════╗
║              CLEANUP EXECUTION SUMMARY                  ║
╚══════════════════════════════════════════════════════════╝

PACKAGE STATISTICS
   Before: 1826 packages
   After:  1820 packages
   Removed: 6 packages
   Orphans removed: 3
   Updates available: 0
   Packages updated: 15

STORAGE STATISTICS
   Space freed: 245 MB
   Disk before: 35%
   Disk after: 33%

EXECUTION STATISTICS
   Total execution time: 12 seconds
   Errors encountered: 0
```

## Troubleshooting

### Permission Denied
Script must run as root:
```bash
sudo ./cachyos_cleanup.sh
```

### Missing Dependencies
Install required packages:
```bash
sudo pacman -S util-linux coreutils findutils grep sed gawk tar
```

### Pacman Lock Error
Wait for other pacman operations to finish, or:
```bash
sudo rm /var/lib/pacman/db.lck
```

### Cron Job Not Running
Ensure cronie is enabled:
```bash
sudo systemctl enable --now cronie
sudo systemctl status cronie
```

## Architecture

### File Locations
- **Script**: `/usr/local/bin/cachyos-cleanup.sh`
- **Config**: `/etc/cachyos-cleanup.conf`
- **Data**: `/var/lib/cachyos-cleanup/`
- **Snapshots**: `/var/lib/cachyos-cleanup/snapshots/`
- **History**: `/var/lib/cachyos-cleanup/cleanup-history.json`
- **Logs**: `/tmp/cachyos-cleanup-*.log` (ephemeral)

### Security
- Data directories use mode 700 (owner-only access)
- Temp files created with secure permissions (600)
- Whitelist support for protected paths
- Snapshot backups before destructive operations
- Input validation and sanitization

## Audit Compliance

**v3.2.0 External Audit Fixes:**
- Serialized pacman operations (no lock conflicts)
- Snapshot self-exclusion (no recursive tar issues)
- Synchronized stats IPC with flock
- Whitelist enforcement on all cleanup operations
- Safe /var/tmp cleanup with age filtering
- Journald support via `journalctl --vacuum-time`
- TTY detection for cron-friendly output
- Stricter directory permissions
- Signal trap handling (INT/TERM/EXIT)

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test thoroughly on CachyOS/Arch
4. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/cachyos-cleanup/issues)
- **Wiki**: [Documentation](https://github.com/yourusername/cachyos-cleanup/wiki)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/cachyos-cleanup/discussions)

## Changelog

### v3.2.0 (2025-12-07)
- Serialized all pacman/yay operations with lock wrapper
- Fixed snapshot self-inclusion with tar exclusions
- Added synchronized stats IPC with flock
- Implemented whitelist enforcement
- Safe /var/tmp cleanup with systemd-tmpfiles
- Added journald cleanup support
- Auto-disable colors/emoji for non-TTY
- Expanded dependency checks
- Added INT/TERM signal traps

### v3.1.0 (2025-12-06)
- Stats IPC mechanism for parallel tasks
- Secure temp file creation
- Config value range validation
- Atomic snapshot cleanup with locking
- Improved error handling

### v3.0.0 (2025-12-05)
- Initial enterprise edition release
- Parallel execution support
- History tracking
- Cron integration
- JSON/CSV export

## Acknowledgments

Built for the CachyOS community with feedback from system administrators and security auditors.

---

**Note**: Always test in a safe environment before deploying to production systems.
````
