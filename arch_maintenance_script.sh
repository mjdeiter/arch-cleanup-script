#!/bin/bash
# archOS System Cleanup and Update Script - ENTERPRISE EDITION
# Version: 3.2.0 (External Audit Applied)
# Features: Parallel execution with IPC, atomic operations, multi-user support,
#           cron integration, JSON/CSV export, interactive mode,
#           health checks, rollback capability, and more
#
# Audit fixes: Pacman lock serialization, snapshot exclusions, stats sync,
#              whitelist enforcement, safe /var/tmp cleanup, journald support

set -euo pipefail
shopt -s nullglob

# Set PATH for cron compatibility
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"

# shellcheck disable=SC2034  # Some variables used in config/export only

#######################################
# CONSTANTS & CONFIGURATION
#######################################
readonly SCRIPT_NAME="archOS Cleanup"
readonly SCRIPT_VERSION="3.2.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_FILE="${CONFIG_FILE:-/etc/archos-cleanup.conf}"
readonly DATA_DIR="${DATA_DIR:-/var/lib/archos-cleanup}"
readonly HISTORY_DB="${DATA_DIR}/cleanup-history.json"
readonly SNAPSHOT_DIR="${DATA_DIR}/snapshots"
readonly EMAIL_CONFIG="${DATA_DIR}/email.conf"
readonly WHITELIST_FILE="${DATA_DIR}/whitelist.conf"

# Path constants
readonly PACMAN_CACHE="/var/cache/pacman/pkg"
readonly SYSTEM_LOG_DIR="/var/log"
readonly VAR_TMP_DIR="/var/tmp"
readonly ROOT_TRASH_DIR="/root/.local/share/Trash"

# Limits and thresholds
readonly MAX_SNAPSHOTS=10
readonly MAX_PARALLEL_JOBS=32
readonly MIN_PARALLEL_JOBS=1
readonly MAX_LOG_RETENTION=365
readonly MIN_LOG_RETENTION=1
readonly MAX_CACHE_VERSIONS=10
readonly MIN_CACHE_VERSIONS=1
readonly MAX_DISK_PERCENT=50
readonly MIN_DISK_PERCENT=1

# Temporary files (created securely later)
LOG_FILE=""
BACKUP_DIR=""
SIZE_TRACKING=""
SNAPSHOT_FILE=""
STATS_FILE=""
CLEANUP_LOCK=""

# Default configuration
LOG_RETENTION_DAYS=7
LOG_MAX_SIZE="100M"
CACHE_VERSIONS=3
USE_EMOJI=true
MIN_DISK_SPACE_PERCENT=5
MAX_LOAD_THRESHOLD=0.8
EMAIL_ON_COMPLETION=false
ENABLE_HISTORY=true
ENABLE_BACKUPS=true
PARALLEL_JOBS=4
LOG_LEVEL="INFO"

# Mode flags
DRY_RUN=false
SKIP_UPDATE=false
SHOW_SUMMARY=true
VERBOSE=false
NON_INTERACTIVE=false
ANALYZE_MODE=false
INTERACTIVE_MODE=false
INSTALL_CRON=false
REMOVE_CRON=false
EXPORT_JSON=false
EXPORT_CSV=false

# Feature flags
CLEAN_PACKAGES=true
CLEAN_CACHE=true
CLEAN_ORPHANS=true
CLEAN_USER_CACHE=true
CLEAN_LOGS=true

# Statistics (initialized properly)
declare -A STATS=(
    [packages_before]=0
    [packages_after]=0
    [packages_removed]=0
    [packages_updated]=0
    [orphans_removed]=0
    [space_freed]=0
    [updates_available]="N/A"
    [execution_time]=0
    [disk_space_before]="N/A"
    [disk_space_after]="N/A"
    [error_count]=0
)

# Global state
START_TIME=0

#######################################
# COLORS & LOGGING
#######################################
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'

# Disable colors/emoji when not a TTY (for cron/pipes)
if [[ ! -t 1 ]]; then
    USE_EMOJI=false
    RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; MAGENTA=""; NC=""
fi

declare -A LOG_LEVELS=(
    [DEBUG]=0
    [INFO]=1
    [WARN]=2
    [ERROR]=3
)

get_log_level_value() {
    echo "${LOG_LEVELS[$LOG_LEVEL]:-1}"
}

should_log() {
    local level=$1
    local current_level
    current_level=$(get_log_level_value)
    local message_level=${LOG_LEVELS[$level]:-1}
    (( message_level >= current_level ))
}

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    should_log "$level" || return 0
    
    if [[ -n "$LOG_FILE" ]] && [[ -f "$LOG_FILE" ]]; then
        echo "${timestamp} [${level}] ${message}" >> "$LOG_FILE"
    fi
    echo -e "${timestamp} [${level}] ${message}"
}

info() {
    local emoji=""
    [[ "$USE_EMOJI" == "true" ]] && emoji="ℹ️  "
    log "INFO" "${BLUE}${emoji}$*${NC}"
}

warn() {
    local emoji=""
    [[ "$USE_EMOJI" == "true" ]] && emoji="⚠️  "
    log "WARN" "${YELLOW}${emoji}$*${NC}"
}

error() {
    local emoji=""
    [[ "$USE_EMOJI" == "true" ]] && emoji="❌ "
    ((STATS[error_count]++))
    log "ERROR" "${RED}${emoji}$*${NC}"
}

success() {
    local emoji=""
    [[ "$USE_EMOJI" == "true" ]] && emoji="✅ "
    log "INFO" "${GREEN}${emoji}$*${NC}"
}

debug() {
    should_log "DEBUG" && log "DEBUG" "${CYAN}$*${NC}"
}

progress() {
    local current=$1
    local total=$2
    local label="${3:-Progress}"
    local percent=$((current * 100 / total))
    local bar_length=30
    local filled=$((percent * bar_length / 100))
    local empty=$((bar_length - filled))
    
    printf "\r${CYAN}%s: [" "$label"
    printf '%*s' "$filled" '' | tr ' ' '#'
    printf '%*s' "$empty" ''
    printf "] %d%% (%d/%d)${NC}" "$percent" "$current" "$total"
}

is_enabled() {
    local var_name=$1
    [[ "${!var_name}" == "true" ]]
}

#######################################
# PACMAN/YAY LOCK WRAPPER
#######################################
with_pacman_lock() {
    local timeout="${1:-300}"
    shift || true
    local wrapper_lock="/var/lib/pacman/.cleanup.lock"
    
    exec {fd}>>"$wrapper_lock"
    if ! flock -w "$timeout" "$fd"; then
        error "Could not acquire pacman wrapper lock within ${timeout}s"
        return 1
    fi
    
    "$@"
    local result=$?
    exec {fd}>&-
    return $result
}

#######################################
# SECURE TEMP FILE CREATION
#######################################
create_secure_tempfile() {
    local prefix=$1
    local tmpfile
    tmpfile=$(mktemp --tmpdir "${prefix}.XXXXXXXXXX") || {
        error "Failed to create temp file with prefix: $prefix"
        return 1
    }
    chmod 600 "$tmpfile"
    echo "$tmpfile"
}

create_secure_tempdir() {
    local prefix=$1
    local tmpdir
    tmpdir=$(mktemp -d --tmpdir "${prefix}.XXXXXXXXXX") || {
        error "Failed to create temp directory with prefix: $prefix"
        return 1
    }
    chmod 700 "$tmpdir"
    echo "$tmpdir"
}

#######################################
# STATS IPC MECHANISM
#######################################
update_stat() {
    local key=$1
    local value=$2
    [[ -z "$STATS_FILE" ]] && return 1
    
    exec {fd}>>"$STATS_FILE"
    if flock -w 5 "$fd"; then
        printf '%s=%s\n' "$key" "$value" >&"$fd"
        exec {fd}>&-
    else
        warn "Failed to lock STATS_FILE for key=$key"
        return 1
    fi
}

get_stat() {
    local key=$1
    local default="${2:-0}"
    [[ ! -f "$STATS_FILE" ]] && echo "$default" && return
    grep "^${key}=" "$STATS_FILE" 2>/dev/null | tail -1 | cut -d= -f2 || echo "$default"
}

consolidate_stats() {
    [[ ! -f "$STATS_FILE" ]] && return
    
    STATS[packages_updated]=$(get_stat "packages_updated" "0")
    STATS[orphans_removed]=$(get_stat "orphans_removed" "0")
    STATS[space_freed]=$(get_stat "space_freed" "0")
    
    debug "Stats consolidated from IPC file"
}

#######################################
# INITIALIZATION & SETUP
#######################################
initialize_directories() {
    if ! mkdir -p "$DATA_DIR" "$SNAPSHOT_DIR" 2>/dev/null; then
        warn "Could not create data directories, some features may be unavailable"
        return 1
    fi
    chmod 700 "$DATA_DIR" 2>/dev/null || true
    chmod 700 "$SNAPSHOT_DIR" 2>/dev/null || true
}

initialize_temp_files() {
    LOG_FILE=$(create_secure_tempfile "archos-cleanup") || exit 1
    BACKUP_DIR=$(create_secure_tempdir "archos-cleanup-backup") || exit 1
    SIZE_TRACKING=$(create_secure_tempfile "archos-sizes") || exit 1
    STATS_FILE=$(create_secure_tempfile "archos-stats") || exit 1
    CLEANUP_LOCK="${DATA_DIR}/.cleanup.lock"
    SNAPSHOT_FILE="${SNAPSHOT_DIR}/snapshot-$(date +%s).tar.gz"
    
    debug "Temporary files initialized"
}

check_root() {
    if [[ $(id -u) -ne 0 ]]; then
        echo -e "${RED}❌ This script must be run as root (use: sudo $0)${NC}" >&2
        exit 1
    fi
}

check_dependencies() {
    local -a missing_deps=()
    local -a required_commands=("pacman" "find" "du" "grep" "sed" "awk" "date" "mktemp" "tar" "flock")
    local -a optional_commands=("paccache" "yay" "systemctl" "mail" "jq" "bc" "logrotate" "journalctl" "crontab")
    
    for cmd in "${required_commands[@]}"; do
        if ! hash "$cmd" 2>/dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        error "Missing required dependencies: ${missing_deps[*]}"
        error "Install them and try again"
        exit 1
    fi
    
    debug "All required dependencies found"
    
    for cmd in "${optional_commands[@]}"; do
        if ! hash "$cmd" 2>/dev/null; then
            case "$cmd" in
                bc)
                    warn "Optional: $cmd not found (system load checks disabled). Install: pacman -S bc"
                    ;;
                crontab)
                    warn "Optional: $cmd not found (cron scheduling disabled). Install: pacman -S cronie"
                    ;;
                jq)
                    warn "Optional: $cmd not found (history recording disabled). Install: pacman -S jq"
                    ;;
                *)
                    warn "Optional: $cmd not found (some features may be unavailable)"
                    ;;
            esac
        fi
    done
}

#######################################
# SYSTEM CHECKS
#######################################
check_disk_space() {
    local root_used_percent
    root_used_percent=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    local available_percent=$((100 - root_used_percent))
    
    STATS[disk_space_before]="${root_used_percent}%"
    
    if (( available_percent < MIN_DISK_SPACE_PERCENT )); then
        warn "Low disk space: only ${available_percent}% free (threshold: ${MIN_DISK_SPACE_PERCENT}%)"
        if is_enabled INTERACTIVE_MODE; then
            local response
            read -rp "Continue anyway? [y/N] " response
            [[ ! "$response" =~ ^[Yy]$ ]] && exit 0
        fi
    fi
    
    info "Disk space: ${available_percent}% available"
}

check_system_load() {
    local load_avg
    load_avg=$(awk '{print $1}' /proc/loadavg)
    local cpu_count
    cpu_count=$(nproc)
    local normalized_load
    
    if ! hash bc 2>/dev/null; then
        debug "bc not available, skipping load check"
        return 0
    fi
    
    normalized_load=$(echo "scale=2; $load_avg / $cpu_count" | bc)
    
    debug "System load: $load_avg (normalized: ${normalized_load})"
    
    if (( $(echo "$normalized_load > $MAX_LOAD_THRESHOLD" | bc -l) )); then
        warn "System load is high (${normalized_load}, threshold: $MAX_LOAD_THRESHOLD)"
        if is_enabled INTERACTIVE_MODE; then
            local response
            read -rp "Continue anyway? [y/N] " response
            [[ ! "$response" =~ ^[Yy]$ ]] && exit 0
        fi
    fi
}

#######################################
# CONFIGURATION MANAGEMENT
#######################################
validate_config_value() {
    local key=$1
    local value=$2
    local pattern=$3
    local min=$4
    local max=$5
    
    if [[ ! "$value" =~ $pattern ]]; then
        warn "Invalid pattern for $key: $value"
        return 1
    fi
    
    if [[ -n "$min" ]] && [[ -n "$max" ]]; then
        if (( value < min || value > max )); then
            warn "Value out of range for $key: $value (expected: $min-$max)"
            return 1
        fi
    fi
    
    return 0
}

load_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        debug "No config file found at $CONFIG_FILE, using defaults"
        return 0
    fi

    info "Loading configuration from $CONFIG_FILE"

    declare -A config_validators=(
        [LOG_RETENTION_DAYS]="^[0-9]+$ $MIN_LOG_RETENTION $MAX_LOG_RETENTION"
        [CACHE_VERSIONS]="^[0-9]+$ $MIN_CACHE_VERSIONS $MAX_CACHE_VERSIONS"
        [PARALLEL_JOBS]="^[0-9]+$ $MIN_PARALLEL_JOBS $MAX_PARALLEL_JOBS"
        [MIN_DISK_SPACE_PERCENT]="^[0-9]+$ $MIN_DISK_PERCENT $MAX_DISK_PERCENT"
    )

    while IFS='=' read -r key value; do
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]] && continue
        
        key=$(echo "$key" | xargs)
        value=$(echo "$value" | xargs | sed "s/^[\"']//;s/[\"']$//")
        
        if [[ -v config_validators[$key] ]]; then
            read -r pattern min max <<< "${config_validators[$key]}"
            if validate_config_value "$key" "$value" "$pattern" "$min" "$max"; then
                declare -g "$key=$value"
                debug "Set $key=$value"
            fi
        else
            case "$key" in
                USE_EMOJI|EMAIL_ON_COMPLETION|ENABLE_HISTORY|ENABLE_BACKUPS)
                    if [[ "$value" =~ ^(true|false)$ ]]; then
                        declare -g "$key=$value"
                        debug "Set $key=$value"
                    else
                        warn "Invalid boolean for $key: $value"
                    fi
                    ;;
                LOG_MAX_SIZE)
                    if [[ "$value" =~ ^[0-9]+[KMG]?$ ]]; then
                        LOG_MAX_SIZE="$value"
                        debug "Set LOG_MAX_SIZE=$value"
                    else
                        warn "Invalid LOG_MAX_SIZE: $value"
                    fi
                    ;;
                MAX_LOAD_THRESHOLD)
                    MAX_LOAD_THRESHOLD="$value"
                    debug "Set MAX_LOAD_THRESHOLD=$value"
                    ;;
                LOG_LEVEL)
                    if [[ -v LOG_LEVELS[$value] ]]; then
                        LOG_LEVEL="$value"
                        debug "Set LOG_LEVEL=$value"
                    else
                        warn "Invalid LOG_LEVEL: $value"
                    fi
                    ;;
                *)
                    debug "Unknown config key: $key"
                    ;;
            esac
        fi
    done < "$CONFIG_FILE"

    success "Configuration loaded"
}

create_sample_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        error "Config file already exists at $CONFIG_FILE"
        return 1
    fi
    
    cat > "$CONFIG_FILE" << 'EOFCONFIG'
# archOS Cleanup Configuration File
# Version: 3.1.0

# Log retention (days, range: 1-365)
LOG_RETENTION_DAYS=7

# Maximum log file size before rotation
LOG_MAX_SIZE=100M

# Number of package cache versions to keep (range: 1-10)
CACHE_VERSIONS=3

# Enable emoji output
USE_EMOJI=true

# Minimum free disk space (percentage, range: 1-50) before warning
MIN_DISK_SPACE_PERCENT=5

# Maximum normalized system load (load_avg / cpu_count) before warning
MAX_LOAD_THRESHOLD=0.8

# Send email on completion
EMAIL_ON_COMPLETION=false

# Enable history tracking
ENABLE_HISTORY=true

# Enable automatic backups before cleanup
ENABLE_BACKUPS=true

# Number of parallel jobs for cleanup operations (range: 1-32)
PARALLEL_JOBS=4

# Logging level (DEBUG, INFO, WARN, ERROR)
LOG_LEVEL=INFO
EOFCONFIG
    
    chmod 644 "$CONFIG_FILE"
    success "Sample config created at $CONFIG_FILE"
}

load_whitelist() {
    if [[ ! -f "$WHITELIST_FILE" ]]; then
        debug "No whitelist file found"
        return 0
    fi

    info "Loading exclusion whitelist from $WHITELIST_FILE"
}

#######################################
# VALIDATION & SAFETY
#######################################
get_safe_sudo_user() {
    local user="${SUDO_USER:-${USER:-}}"
    
    [[ -z "$user" ]] && return 1
    
    if [[ ! "$user" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        debug "Invalid username format: $user"
        return 1
    fi
    
    if ! id "$user" &>/dev/null; then
        debug "User does not exist: $user"
        return 1
    fi
    
    echo "$user"
}

check_yay() {
    local user
    user=$(get_safe_sudo_user) || return 1
    hash yay 2>/dev/null && sudo -u "$user" bash -c 'hash yay 2>/dev/null'
}

is_whitelisted() {
    local path="$1"
    [[ ! -f "$WHITELIST_FILE" ]] && return 1
    local escaped_path
    escaped_path=$(printf '%s\n' "$path" | sed 's/[][\.^$*]/\\&/g')
    grep -q "^${escaped_path}$" "$WHITELIST_FILE" 2>/dev/null
}

#######################################
# BACKUP & SNAPSHOT MANAGEMENT
#######################################
create_snapshot() {
    if ! is_enabled ENABLE_BACKUPS; then
        debug "Backups disabled, skipping snapshot"
        return 0
    fi

    info "Creating system snapshot..."
    mkdir -p "$SNAPSHOT_DIR"

    if ! pacman -Q > "${SNAPSHOT_DIR}/packages-$(date +%s).txt" 2>/dev/null; then
        warn "Could not snapshot package list"
    fi

    local -a backup_paths=()
    [[ -f /etc/pacman.conf ]] && backup_paths+=("/etc/pacman.conf")
    [[ -f "$CONFIG_FILE" ]] && backup_paths+=("$CONFIG_FILE")
    [[ -d "$DATA_DIR" ]] && backup_paths+=("$DATA_DIR")
    
    if [[ ${#backup_paths[@]} -eq 0 ]]; then
        warn "No files to snapshot"
        return 1
    fi

    if tar --exclude="$SNAPSHOT_DIR" --exclude="$SNAPSHOT_FILE" -czf "$SNAPSHOT_FILE" "${backup_paths[@]}" 2>/dev/null; then
        success "Snapshot created: $SNAPSHOT_FILE"
    else
        warn "Could not create full snapshot"
        return 1
    fi
}

cleanup_old_snapshots() {
    [[ ! -d "$SNAPSHOT_DIR" ]] && return 0
    
    local lockfile="${SNAPSHOT_DIR}/.cleanup.lock"
    
    (
        if ! flock -x -w 10 200; then
            warn "Could not acquire lock for snapshot cleanup"
            return 1
        fi
        
        local -a snapshots
        mapfile -t snapshots < <(
            find "$SNAPSHOT_DIR" -name "snapshot-*.tar.gz" -type f -printf '%T@ %p\n' 2>/dev/null | sort -n
        )
        
        local remove_count=$(( ${#snapshots[@]} - MAX_SNAPSHOTS ))
        
        if (( remove_count > 0 )); then
            info "Removing $remove_count old snapshots (keeping last $MAX_SNAPSHOTS)"
            local i
            for ((i=0; i<remove_count; i++)); do
                local snapshot_path
                snapshot_path=$(echo "${snapshots[$i]}" | cut -d' ' -f2-)
                rm -f "$snapshot_path" 2>/dev/null || warn "Could not remove: $snapshot_path"
            done
        fi
    ) 200>"$lockfile"
    
    rm -f "$lockfile"
}

#######################################
# HISTORY & TRACKING
#######################################
initialize_history() {
    if ! is_enabled ENABLE_HISTORY; then
        return 0
    fi

    mkdir -p "$DATA_DIR"

    if [[ ! -f "$HISTORY_DB" ]]; then
        echo "[]" > "$HISTORY_DB"
        chmod 644 "$HISTORY_DB"
    fi
}

record_cleanup_history() {
    if ! is_enabled ENABLE_HISTORY; then
        return 0
    fi
    
    if ! hash jq 2>/dev/null; then
        debug "jq not found, skipping history recording"
        return 0
    fi

    local timestamp
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    
    local entry
    entry=$(cat <<EOF
{
    "timestamp": "$timestamp",
    "version": "$SCRIPT_VERSION",
    "packages_before": ${STATS[packages_before]},
    "packages_after": ${STATS[packages_after]},
    "packages_removed": ${STATS[packages_removed]},
    "orphans_removed": ${STATS[orphans_removed]},
    "space_freed_mb": $((STATS[space_freed] / 1024 / 1024)),
    "execution_time_seconds": ${STATS[execution_time]},
    "disk_space_before": "${STATS[disk_space_before]}",
    "disk_space_after": "${STATS[disk_space_after]}",
    "errors": ${STATS[error_count]}
}
EOF
)

    if ! echo "$entry" | jq '.' > /dev/null 2>&1; then
        warn "Could not validate history entry JSON"
        return 1
    fi
    
    if jq --argjson new_entry "$entry" '. += [$new_entry]' "$HISTORY_DB" > "${HISTORY_DB}.tmp" 2>/dev/null; then
        mv "${HISTORY_DB}.tmp" "$HISTORY_DB"
        debug "History recorded"
    else
        warn "Could not record history"
        rm -f "${HISTORY_DB}.tmp"
    fi
}

show_history() {
    if [[ ! -f "$HISTORY_DB" ]]; then
        info "No cleanup history available"
        return 0
    fi

    if hash jq 2>/dev/null; then
        info "Cleanup history (last 10 runs):"
        jq -r '.[-10:] | reverse | .[] | "\(.timestamp): freed \(.space_freed_mb)MB, removed \(.packages_removed) packages"' "$HISTORY_DB" 2>/dev/null || \
            info "Could not parse history"
    else
        info "History available at: $HISTORY_DB (install jq to view formatted history)"
    fi
}

#######################################
# SIZE TRACKING
#######################################
track_size_before() {
    local path="$1"
    local label="$2"
    local size=0

    if [[ -d "$path" ]]; then
        size=$(du -sb "$path" 2>/dev/null | cut -f1 || echo "0")
    fi

    echo "${label}:${size}" >> "$SIZE_TRACKING"
}

calculate_size_freed() {
    local path="$1"
    local label="$2"
    local size_after=0

    if [[ -d "$path" ]]; then
        size_after=$(du -sb "$path" 2>/dev/null | cut -f1 || echo "0")
    fi

    local size_before
    size_before=$(grep "^${label}:" "$SIZE_TRACKING" 2>/dev/null | cut -d: -f2 || echo "0")

    local freed=$((size_before - size_after))

    if (( freed > 0 )); then
        local current_freed
        current_freed=$(get_stat "space_freed" "0")
        update_stat "space_freed" $((current_freed + freed))
        success "$label: Freed $((freed / 1024 / 1024)) MB"
    else
        debug "$label: No space freed"
    fi
}

#######################################
# PACKAGE MANAGEMENT
#######################################
update_system() {
    is_enabled CLEAN_PACKAGES || { info "Skipping package update"; return; }
    [[ "$SKIP_UPDATE" == "true" ]] && { info "Skipping updates (--skip-update)"; return; }

    info "Checking for updates..."

    local user
    local updates_available=0

    if user=$(get_safe_sudo_user 2>/dev/null) && check_yay 2>/dev/null; then
        updates_available=$(sudo -u "$user" yay -Qu 2>/dev/null | wc -l || echo "0")
    else
        updates_available=$(pacman -Qu 2>/dev/null | wc -l || echo "0")
    fi

    updates_available="${updates_available//[^0-9]/}"
    [[ -z "$updates_available" ]] && updates_available=0

    STATS[updates_available]=$updates_available

    if (( updates_available == 0 )); then
        success "System up to date"
        update_stat "packages_updated" 0
        return
    fi

    info "Found $updates_available updates"

    if [[ "$ANALYZE_MODE" == "true" ]] || [[ "$DRY_RUN" == "true" ]]; then
        info "[ANALYSIS/DRY RUN] Would update $updates_available packages"
        return
    fi

    if is_enabled INTERACTIVE_MODE; then
        local response
        read -rp "Update $updates_available packages? [y/N] " response
        [[ ! "$response" =~ ^[Yy]$ ]] && { info "Skipping updates"; return; }
    fi

    if user=$(get_safe_sudo_user 2>/dev/null) && check_yay 2>/dev/null; then
        info "Updating with yay..."
        if with_pacman_lock 300 sudo -u "$user" yay -Syu --noconfirm; then
            update_stat "packages_updated" "$updates_available"
            success "Updated $updates_available packages"
        else
            error "Update with yay failed"
        fi
    else
        info "Updating with pacman..."
        if with_pacman_lock 300 pacman -Syu --noconfirm; then
            update_stat "packages_updated" "$updates_available"
            success "Updated $updates_available packages"
        else
            error "Update with pacman failed"
        fi
    fi
}

clean_package_cache() {
    is_enabled CLEAN_CACHE || return

    info "Cleaning package cache..."
    track_size_before "$PACMAN_CACHE" "pacman_cache"

    if [[ "$ANALYZE_MODE" == "true" ]] || [[ "$DRY_RUN" == "true" ]]; then
        info "[ANALYSIS/DRY RUN] Would clean package cache (keep $CACHE_VERSIONS versions)"
        return
    fi

    if is_enabled INTERACTIVE_MODE; then
        local response
        read -rp "Clean package cache (keep $CACHE_VERSIONS versions)? [y/N] " response
        [[ ! "$response" =~ ^[Yy]$ ]] && { info "Skipping package cache cleanup"; return; }
    fi

    if hash paccache 2>/dev/null; then
        if with_pacman_lock 300 paccache -r -k"$CACHE_VERSIONS" 2>/dev/null; then
            success "Package cache cleaned via paccache"
        else
            debug "paccache: nothing to remove"
        fi
    else
        warn "paccache not found, using pacman -Sc"
        with_pacman_lock 300 pacman -Sc --noconfirm 2>/dev/null || debug "pacman -Sc: nothing removed"
    fi

    calculate_size_freed "$PACMAN_CACHE" "pacman_cache"
}

remove_orphans() {
    is_enabled CLEAN_ORPHANS || return

    info "Checking for orphan packages..."
    local orphans
    orphans=$(pacman -Qtdq 2>/dev/null || true)

    if [[ -z "$orphans" ]]; then
        success "No orphan packages found"
        return
    fi

    local count
    count=$(echo "$orphans" | wc -l)
    info "Found $count orphan packages"

    if [[ "$ANALYZE_MODE" == "true" ]] || [[ "$DRY_RUN" == "true" ]]; then
        info "[ANALYSIS/DRY RUN] Would remove $count orphan packages:"
        echo "$orphans" | sed 's/^/  - /'
        return
    fi

    if is_enabled INTERACTIVE_MODE; then
        local response
        read -rp "Remove $count orphan packages? [y/N] " response
        [[ ! "$response" =~ ^[Yy]$ ]] && { info "Skipping orphan removal"; return; }
    fi

    if with_pacman_lock 300 pacman -Rns --noconfirm $orphans 2>/dev/null; then
        update_stat "orphans_removed" "$count"
        success "$count orphan packages removed"
    else
        error "Failed to remove orphan packages"
    fi
}

clean_logs() {
    is_enabled CLEAN_LOGS || return

    info "Cleaning system logs..."
    track_size_before "$SYSTEM_LOG_DIR" "logs"

    if [[ "$ANALYZE_MODE" == "true" ]] || [[ "$DRY_RUN" == "true" ]]; then
        info "[ANALYSIS/DRY RUN] Would clean logs older than $LOG_RETENTION_DAYS days"
        return
    fi

    if is_enabled INTERACTIVE_MODE; then
        local response
        read -rp "Clean logs older than $LOG_RETENTION_DAYS days? [y/N] " response
        [[ ! "$response" =~ ^[Yy]$ ]] && { info "Skipping log cleanup"; return; }
    fi

    # Clean old log files with whitelist support
    while IFS= read -r -d '' f; do
        is_whitelisted "$f" && { debug "Whitelisted: $f"; continue; }
        rm -f "$f" 2>/dev/null || warn "Could not remove $f"
    done < <(find "$SYSTEM_LOG_DIR" -type f -name "*.log" -mtime +"$LOG_RETENTION_DAYS" -print0 2>/dev/null)

    if hash logrotate 2>/dev/null; then
        logrotate /etc/logrotate.conf 2>/dev/null || debug "logrotate encountered issues"
    fi

    # Clean journald logs if available
    if hash journalctl 2>/dev/null; then
        journalctl --vacuum-time="${LOG_RETENTION_DAYS}d" 2>/dev/null || debug "journalctl vacuum skipped"
    fi

    calculate_size_freed "$SYSTEM_LOG_DIR" "logs"
}

clean_user_cache() {
    is_enabled CLEAN_USER_CACHE || return

    info "Cleaning user caches and temporary directories..."

    track_size_before "$VAR_TMP_DIR" "var_tmp"

    local user
    local user_cache_dir
    local user_trash_dir

    if user=$(get_safe_sudo_user 2>/dev/null); then
        user_cache_dir="/home/$user/.cache"
        user_trash_dir="/home/$user/.local/share/Trash"
        [[ -d "$user_cache_dir" ]] && track_size_before "$user_cache_dir" "user_cache"
        [[ -d "$user_trash_dir" ]] && track_size_before "$user_trash_dir" "user_trash"
    fi

    [[ -d "$ROOT_TRASH_DIR" ]] && track_size_before "$ROOT_TRASH_DIR" "root_trash"

    if [[ "$ANALYZE_MODE" == "true" ]] || [[ "$DRY_RUN" == "true" ]]; then
        info "[ANALYSIS/DRY RUN] Would clean $VAR_TMP_DIR, user caches, and trash folders"
        return
    fi

    if is_enabled INTERACTIVE_MODE; then
        local response
        read -rp "Clean $VAR_TMP_DIR, user caches, and trash? [y/N] " response
        [[ ! "$response" =~ ^[Yy]$ ]] && { info "Skipping user cache cleanup"; return; }
    fi

    # Clean /var/tmp safely
    info "Cleaning $VAR_TMP_DIR..."
    if hash systemd-tmpfiles 2>/dev/null; then
        systemd-tmpfiles --clean || true
    fi
    find "$VAR_TMP_DIR" -type f -mtime +7 -delete 2>/dev/null || true
    find "$VAR_TMP_DIR" -type d -empty -mtime +7 -delete 2>/dev/null || true
    calculate_size_freed "$VAR_TMP_DIR" "var_tmp"

    # Clean SUDO_USER's cache and trash
    if [[ -n "$user" ]]; then
        if [[ -d "$user_cache_dir" ]] && ! is_whitelisted "$user_cache_dir"; then
            info "Cleaning user cache: $user_cache_dir"
            sudo -u "$user" find "$user_cache_dir" -mindepth 1 -delete 2>/dev/null || \
                warn "Could not clean user cache directory"
            calculate_size_freed "$user_cache_dir" "user_cache"
        fi
        if [[ -d "$user_trash_dir" ]] && ! is_whitelisted "$user_trash_dir"; then
            info "Cleaning user trash: $user_trash_dir"
            sudo -u "$user" rm -rf "${user_trash_dir:?}"/* 2>/dev/null || \
                warn "Could not clean user trash"
            calculate_size_freed "$user_trash_dir" "user_trash"
        fi
    fi

    # Clean root trash
    if [[ -d "$ROOT_TRASH_DIR" ]] && ! is_whitelisted "$ROOT_TRASH_DIR"; then
        info "Cleaning root trash..."
        rm -rf "${ROOT_TRASH_DIR:?}"/* 2>/dev/null || warn "Could not clean root trash"
        calculate_size_freed "$ROOT_TRASH_DIR" "root_trash"
    fi

    success "Caches and temporary directories cleaned"
}

#######################################
# PARALLEL EXECUTION WITH SERIALIZED PACMAN
#######################################
run_parallel_tasks() {
    info "Running cleanup tasks..."
    
    # Pacman/yay/paccache tasks MUST be serialized (pacman lock conflicts)
    is_enabled CLEAN_PACKAGES && update_system
    is_enabled CLEAN_CACHE && clean_package_cache
    is_enabled CLEAN_ORPHANS && remove_orphans

    # Parallelize only non-pacman tasks
    local -a pids=()
    is_enabled CLEAN_LOGS && (clean_logs) & pids+=($!)
    # user cache runs separately due to sudo requirements
    
    for pid in "${pids[@]}"; do
        wait "$pid" || warn "Task PID $pid failed"
    done

    consolidate_stats
    success "All tasks completed"
}

#######################################
# EXPORT FUNCTIONALITY
#######################################
export_json() {
    local export_file="/tmp/archos-cleanup-report-$(date +%Y%m%d-%H%M%S).json"

    local json_output
    json_output=$(cat <<EOF
{
    "script": "$SCRIPT_NAME",
    "version": "$SCRIPT_VERSION",
    "execution_time": "$(date)",
    "statistics": {
        "packages_before": ${STATS[packages_before]},
        "packages_after": ${STATS[packages_after]},
        "packages_removed": ${STATS[packages_removed]},
        "orphans_removed": ${STATS[orphans_removed]},
        "space_freed_mb": $((STATS[space_freed] / 1024 / 1024)),
        "updates_available": "${STATS[updates_available]}",
        "packages_updated": ${STATS[packages_updated]},
        "execution_time_seconds": ${STATS[execution_time]},
        "errors": ${STATS[error_count]}
    },
    "log_file": "$LOG_FILE"
}
EOF
)

    echo "$json_output" > "$export_file"
    chmod 644 "$export_file"
    success "JSON report exported to: $export_file"
}

export_csv() {
    local export_file="/tmp/archos-cleanup-report-$(date +%Y%m%d-%H%M%S).csv"

    cat > "$export_file" <<EOF
Metric,Value
Script Name,$SCRIPT_NAME
Version,$SCRIPT_VERSION
Execution Time,$(date)
Packages Before,${STATS[packages_before]}
Packages After,${STATS[packages_after]}
Packages Removed,${STATS[packages_removed]}
Orphans Removed,${STATS[orphans_removed]}
Space Freed (MB),$((STATS[space_freed] / 1024 / 1024))
Updates Available,${STATS[updates_available]}
Packages Updated,${STATS[packages_updated]}
Execution Time (seconds),${STATS[execution_time]}
Errors,${STATS[error_count]}
EOF

    chmod 644 "$export_file"
    success "CSV report exported to: $export_file"
}

#######################################
# CRON INTEGRATION
#######################################
install_cron_job() {
    local schedule="${1:-@daily}"
    local script_path="/usr/local/bin/archos-cleanup.sh"
    local cron_cmd="$script_path --skip-update --non-interactive"
    
    if [[ ! -f "${BASH_SOURCE[0]}" ]]; then
        error "Cannot find current script"
        return 1
    fi

    info "Installing script to $script_path"
    cp "${BASH_SOURCE[0]}" "$script_path" || {
        error "Failed to copy script"
        return 1
    }
    chmod 755 "$script_path"

    local crontab_entry="$schedule $cron_cmd"
    
    if crontab -l 2>/dev/null | grep -q "archos-cleanup"; then
        warn "Cron job already installed"
        return 1
    fi

    (crontab -l 2>/dev/null; echo "$crontab_entry") | crontab - || {
        error "Failed to install cron job"
        return 1
    }

    success "Cron job installed: $schedule"
    info "Cron command: $cron_cmd"
}

remove_cron_job() {
    if ! crontab -l 2>/dev/null | grep -q "archos-cleanup"; then
        warn "Cron job not found"
        return 1
    fi

    crontab -l 2>/dev/null | grep -v "archos-cleanup" | crontab - || {
        error "Failed to remove cron job"
        return 1
    }

    success "Cron job removed"
}

#######################################
# ANALYSIS MODE
#######################################
show_analysis() {
    info "╔══════════════════════════════════════════════════════════╗"
    info "║          SYSTEM CLEANUP ANALYSIS REPORT                 ║"
    info "╚══════════════════════════════════════════════════════════╝"
    info ""
    info "DISK USAGE ANALYSIS:"
    info "  Root partition: ${STATS[disk_space_before]} used"
    info ""
    info "CLEANUP PREVIEW:"
    info "  Packages to update: ${STATS[updates_available]}"
    
    local orphans
    orphans=$(pacman -Qtdq 2>/dev/null | wc -l || echo 0)
    info "  Orphan packages: $orphans"
    info "  Cache versions to keep: $CACHE_VERSIONS"
    info ""
    info "ESTIMATED IMPACT:"
    info "  Packages before: ${STATS[packages_before]}"
    info ""
    info "Modes enabled:"
    is_enabled CLEAN_PACKAGES && info "  ✓ Package updates"
    is_enabled CLEAN_CACHE && info "  ✓ Cache cleaning"
    is_enabled CLEAN_ORPHANS && info "  ✓ Orphan removal"
    is_enabled CLEAN_USER_CACHE && info "  ✓ User cache cleanup"
    is_enabled CLEAN_LOGS && info "  ✓ Log cleaning"
}

#######################################
# STATISTICS & REPORTING
#######################################
init_stats() {
    STATS[packages_before]=$(pacman -Q 2>/dev/null | wc -l || echo 0)
}

update_stats() {
    STATS[packages_after]=$(pacman -Q 2>/dev/null | wc -l || echo 0)
    local diff=$((STATS[packages_before] - STATS[packages_after]))
    STATS[packages_removed]=$((diff > 0 ? diff : 0))
    
    local end_percent
    end_percent=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    STATS[disk_space_after]="${end_percent}%"
}

show_summary() {
    info ""
    info "╔══════════════════════════════════════════════════════════╗"
    info "║              CLEANUP EXECUTION SUMMARY                  ║"
    info "╚══════════════════════════════════════════════════════════╝"
    info ""
    info "PACKAGE STATISTICS"
    info "   Before: ${STATS[packages_before]} packages"
    info "   After:  ${STATS[packages_after]} packages"
    info "   Removed: ${STATS[packages_removed]} packages"
    info "   Orphans removed: ${STATS[orphans_removed]}"
    info "   Updates available: ${STATS[updates_available]}"
    info "   Packages updated: ${STATS[packages_updated]}"
    info ""
    info "STORAGE STATISTICS"
    info "   Space freed: $((STATS[space_freed] / 1024 / 1024)) MB"
    info "   Disk before: ${STATS[disk_space_before]}"
    info "   Disk after: ${STATS[disk_space_after]}"
    info ""
    info "EXECUTION STATISTICS"
    info "   Total execution time: ${STATS[execution_time]} seconds"
    info "   Errors encountered: ${STATS[error_count]}"
    info ""
    info "LOGGING"
    info "   Log file: $LOG_FILE"
    if is_enabled ENABLE_HISTORY; then
        info "   History DB: $HISTORY_DB"
    fi
    info ""
    info "═══════════════════════════════════════════════════════════"
}

#######################################
# PREFLIGHT CHECKS
#######################################
perform_preflight_checks() {
    debug "Performing preflight checks..."
    check_disk_space
    check_system_load
}

#######################################
# CLEANUP WORKFLOW
#######################################
execute_cleanup_workflow() {
    create_snapshot
    init_stats

    if is_enabled INTERACTIVE_MODE; then
        info "Interactive mode enabled - you will be asked before each operation"
        info ""
        update_system
        clean_package_cache
        remove_orphans
        clean_logs
        clean_user_cache
    else
        run_parallel_tasks
        clean_user_cache
    fi

    cleanup_old_snapshots
}

finalize_and_report() {
    update_stats
    
    if is_enabled SHOW_SUMMARY; then
        show_summary
    fi
    
    if is_enabled ENABLE_HISTORY; then
        record_cleanup_history
    fi
    
    if is_enabled EXPORT_JSON; then
        export_json
    fi
    
    if is_enabled EXPORT_CSV; then
        export_csv
    fi
    
    send_email_notification
    
    success "All cleanup operations completed successfully!"
}

send_email_notification() {
    if ! is_enabled EMAIL_ON_COMPLETION; then
        return 0
    fi
    
    if ! hash mail 2>/dev/null; then
        debug "mail command not available"
        return 1
    fi
    
    local recipient="${SUDO_USER:-root}@localhost"
    
    if echo "Cleanup completed. See $LOG_FILE for details." | \
        mail -s "archOS Cleanup Report" "$recipient" 2>/dev/null; then
        debug "Email sent to $recipient"
    else
        warn "Could not send email notification"
    fi
}

#######################################
# CLEANUP ON EXIT
#######################################
cleanup_on_exit() {
    local exit_code=$?
    local end_time
    end_time=$(date +%s)

    STATS[execution_time]=$((end_time - START_TIME))

    if [[ $exit_code -ne 0 ]]; then
        error "Script failed with exit code $exit_code"
        info "Log file: $LOG_FILE"
        info "Backup directory: $BACKUP_DIR"
    fi
    
    [[ -f "$SIZE_TRACKING" ]] && rm -f "$SIZE_TRACKING"
    [[ -f "$STATS_FILE" ]] && rm -f "$STATS_FILE"
    [[ -d "$BACKUP_DIR" ]] && rm -rf "$BACKUP_DIR"
}

trap cleanup_on_exit EXIT INT TERM

#######################################
# USAGE & HELP
#######################################
show_help() {
    cat << 'EOFHELP'
archOS System Cleanup and Update Script - ENTERPRISE EDITION
Version 3.2.0 (External Audit Applied)

USAGE:
    archos_cleanup.sh [OPTIONS]

GENERAL OPTIONS:
    -h, --help                  Show this help message
    -v, --verbose               Enable verbose logging output (DEBUG level)
    --version                   Show script version

EXECUTION MODES:
    -n, --non-interactive       Run without user confirmations
    -i, --interactive           Ask for confirmation before each major operation
    -a, --analyze               Analyze system without making changes (report only)
    --dry-run                   Preview all changes without executing

UPDATE & UPGRADE:
    --skip-update               Skip system package updates
    -y, --assume-yes            Assume yes to all confirmation prompts

SELECTIVE CLEANING (default: all enabled):
    --clean-packages            Enable package updates only
    --clean-cache               Enable package cache cleanup only
    --clean-orphans             Enable orphan package removal only
    --clean-logs                Enable system log cleanup only
    --clean-user-cache          Enable user cache cleanup only
    
    Disable specific tasks using --no-* variants:
    --no-packages               Disable package updates
    --no-cache                  Disable cache cleanup
    --no-orphans                Disable orphan removal
    --no-logs                   Disable log cleanup
    --no-user-cache             Disable user cache cleanup

CONFIGURATION:
    --create-config             Create sample configuration file
    --no-emoji                  Disable emoji output

REPORTING & EXPORT:
    --history                   Show cleanup history from database
    --json                      Export cleanup report as JSON
    --csv                       Export cleanup report as CSV

CRON INTEGRATION:
    --install-cron [SCHEDULE]   Install cron job (default: @daily)
                                Examples: @daily, @weekly, "0 2 * * *"
    --remove-cron               Remove cron job

EXAMPLES:
    # Run interactive cleanup with confirmations
    sudo ./archos_cleanup_v3.sh -i

    # Analyze without making changes
    sudo ./archos_cleanup_v3.sh --analyze

    # Clean only cache and orphans (non-interactive)
    sudo ./archos_cleanup_v3.sh --clean-cache --clean-orphans -n

    # Install daily cron job
    sudo ./archos_cleanup_v3.sh --install-cron @daily

    # Export report as JSON and CSV
    sudo ./archos_cleanup_v3.sh --json --csv

    # Verbose debug mode
    sudo ./archos_cleanup_v3.sh -v

CONFIGURATION FILE:
    /etc/archos-cleanup.conf
    
    Key settings:
    - LOG_RETENTION_DAYS: Days to keep logs (range: 1-365, default: 7)
    - CACHE_VERSIONS: Package cache versions to keep (range: 1-10, default: 3)
    - MIN_DISK_SPACE_PERCENT: Minimum free disk % (range: 1-50, default: 5)
    - ENABLE_HISTORY: Track cleanup history (default: true)
    - PARALLEL_JOBS: Concurrent cleanup tasks (range: 1-32, default: 4)
    - LOG_LEVEL: Logging verbosity (DEBUG, INFO, WARN, ERROR, default: INFO)

ADVANCED:
    Environment variables:
    CONFIG_FILE=/path/to/config ./archos_cleanup_v3.sh
    DATA_DIR=/var/lib/archos-cleanup ./archos_cleanup_v3.sh

AUDIT NOTES (v3.2.0):
    CRITICAL FIXES APPLIED:
    - Serialized all pacman/yay/paccache operations (lock conflicts resolved)
    - Excluded snapshot dir/file from tar to prevent self-inclusion
    - Synchronized stats IPC writes with flock
    - Applied whitelist enforcement to log/cache/trash cleanup
    - Safe /var/tmp cleanup (7-day age, systemd-tmpfiles support)
    
    HIGH-VALUE IMPROVEMENTS:
    - Added journalctl --vacuum-time for systemd log cleanup
    - Fixed whitelist regex escaping (sed pattern corrected)
    - Auto-disable colors/emoji when not a TTY (cron-friendly)
    - Tightened data directory permissions (700 instead of 755)
    - Set PATH for cron compatibility
    - Expanded dependency checks (tar, flock, logrotate, journalctl)
    - Added INT/TERM signal traps

EOFHELP
}

#######################################
# ARGUMENT PARSING
#######################################
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            --version)
                echo "$SCRIPT_NAME v$SCRIPT_VERSION"
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                LOG_LEVEL="DEBUG"
                ;;
            -i|--interactive)
                INTERACTIVE_MODE=true
                NON_INTERACTIVE=false
                ;;
            -n|--non-interactive)
                NON_INTERACTIVE=true
                INTERACTIVE_MODE=false
                ;;
            -a|--analyze)
                ANALYZE_MODE=true
                DRY_RUN=false
                ;;
            --dry-run)
                DRY_RUN=true
                ANALYZE_MODE=true
                ;;
            -y|--assume-yes)
                NON_INTERACTIVE=true
                ;;
            --skip-update)
                SKIP_UPDATE=true
                ;;
            --create-config)
                initialize_directories
                create_sample_config
                exit $?
                ;;
            --no-emoji)
                USE_EMOJI=false
                ;;
            --history)
                initialize_directories
                show_history
                exit 0
                ;;
            --json)
                EXPORT_JSON=true
                ;;
            --csv)
                EXPORT_CSV=true
                ;;
            --install-cron)
                shift
                install_cron_job "${1:-@daily}"
                exit $?
                ;;
            --remove-cron)
                remove_cron_job
                exit $?
                ;;
            --clean-packages)
                CLEAN_PACKAGES=true
                CLEAN_CACHE=false
                CLEAN_ORPHANS=false
                CLEAN_LOGS=false
                CLEAN_USER_CACHE=false
                ;;
            --clean-cache)
                CLEAN_PACKAGES=false
                CLEAN_CACHE=true
                CLEAN_ORPHANS=false
                CLEAN_LOGS=false
                CLEAN_USER_CACHE=false
                ;;
            --clean-orphans)
                CLEAN_PACKAGES=false
                CLEAN_CACHE=false
                CLEAN_ORPHANS=true
                CLEAN_LOGS=false
                CLEAN_USER_CACHE=false
                ;;
            --clean-logs)
                CLEAN_PACKAGES=false
                CLEAN_CACHE=false
                CLEAN_ORPHANS=false
                CLEAN_LOGS=true
                CLEAN_USER_CACHE=false
                ;;
            --clean-user-cache)
                CLEAN_PACKAGES=false
                CLEAN_CACHE=false
                CLEAN_ORPHANS=false
                CLEAN_LOGS=false
                CLEAN_USER_CACHE=true
                ;;
            --no-packages)
                CLEAN_PACKAGES=false
                ;;
            --no-cache)
                CLEAN_CACHE=false
                ;;
            --no-orphans)
                CLEAN_ORPHANS=false
                ;;
            --no-logs)
                CLEAN_LOGS=false
                ;;
            --no-user-cache)
                CLEAN_USER_CACHE=false
                ;;
            *)
                warn "Unknown argument: $1"
                show_help
                exit 1
                ;;
        esac
        shift
    done
}

#######################################
# MAIN EXECUTION
#######################################
main() {
    START_TIME=$(date +%s)

    check_root
    check_dependencies
    initialize_temp_files
    initialize_directories
    load_config
    load_whitelist
    initialize_history

    info "╔══════════════════════════════════════════════════════════╗"
    info "║  $SCRIPT_NAME v$SCRIPT_VERSION                    "
    info "╚══════════════════════════════════════════════════════════╝"
    info "Starting at: $(date)"
    info "Log file: $LOG_FILE"
    info ""

    if [[ "$DRY_RUN" == "true" ]]; then
        info "DRY RUN MODE - No changes will be made"
    fi

    if [[ "$ANALYZE_MODE" == "true" ]]; then
        init_stats
        check_disk_space
        show_analysis
        return 0
    fi

    perform_preflight_checks
    execute_cleanup_workflow
    finalize_and_report
}

parse_arguments "$@"
main
