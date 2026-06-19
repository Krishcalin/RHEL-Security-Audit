#!/bin/bash
# ============================================================================
# RHEL 8 Security Audit Collector
# ----------------------------------------------------------------------------
# Captures the configuration files and runtime command outputs needed by the
# offline analyzer (rhel8_scanner.py). Produces a single .tar.gz bundle that
# can be transferred off the host for review.
#
# Usage:   sudo ./collect_rhel8.sh [output_dir]
# Default: writes to /tmp/rhel8-audit-<hostname>-<timestamp>.tar.gz
#
# Safe to run on production: only reads files and runs query-only commands
# (rpm -q, systemctl list-unit-files, sysctl -a, auditctl -l, etc.). Does not
# install anything, change configuration, or transmit data anywhere.
# ============================================================================

set -u  # -e omitted: a failed grab on one file must not abort the whole run

# ----------------------------------------------------------------------------
# Argument and environment setup
# ----------------------------------------------------------------------------
OUTPUT_DIR="${1:-/tmp}"
HOSTNAME_SAFE="$(hostname -s 2>/dev/null | tr -dc 'A-Za-z0-9._-' || echo unknown)"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BUNDLE_NAME="rhel8-audit-${HOSTNAME_SAFE}-${TIMESTAMP}"
STAGE_DIR="$(mktemp -d "/tmp/${BUNDLE_NAME}.XXXXXX")"
trap 'rm -rf "${STAGE_DIR}"' EXIT

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Warning: not running as root. Some files (shadow, audit rules, firewalld) will be incomplete." >&2
fi

mkdir -p "${STAGE_DIR}/etc" "${STAGE_DIR}/cmd" "${STAGE_DIR}/meta"

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
log() { printf '[*] %s\n' "$*"; }

# Copy a path into the staging dir, preserving relative location under ./etc.
# Silent on missing files (different RHEL minor versions have different files).
copy_etc() {
    local src="$1"
    if [ -e "$src" ]; then
        local dest="${STAGE_DIR}/etc${src#/etc}"
        mkdir -p "$(dirname "$dest")"
        cp -a "$src" "$dest" 2>/dev/null
    fi
}

# Run a command and capture stdout+stderr to ./cmd/<label>.txt.
capture_cmd() {
    local label="$1"; shift
    {
        echo "# Command: $*"
        echo "# Captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "# Host: $(hostname)"
        echo "---"
        "$@" 2>&1
        echo "---"
        echo "# Exit: $?"
    } > "${STAGE_DIR}/cmd/${label}.txt"
}

# ----------------------------------------------------------------------------
# Metadata about the collection itself
# ----------------------------------------------------------------------------
{
    echo "collector_version=1.0.0"
    echo "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "hostname=$(hostname)"
    echo "fqdn=$(hostname -f 2>/dev/null || hostname)"
    echo "collector_uid=$(id -u)"
    echo "collector_user=$(id -un)"
    echo "kernel=$(uname -r)"
    echo "arch=$(uname -m)"
    if [ -r /etc/os-release ]; then
        cat /etc/os-release
    fi
    if [ -r /etc/redhat-release ]; then
        echo "redhat_release=$(cat /etc/redhat-release)"
    fi
} > "${STAGE_DIR}/meta/collector.txt"

log "Bundle: ${BUNDLE_NAME}"
log "Staging: ${STAGE_DIR}"

# ----------------------------------------------------------------------------
# /etc files (configuration state)
# ----------------------------------------------------------------------------
log "Collecting /etc configuration files..."

# Authentication / accounts
copy_etc /etc/passwd
copy_etc /etc/shadow
copy_etc /etc/group
copy_etc /etc/gshadow
copy_etc /etc/login.defs
copy_etc /etc/securetty
copy_etc /etc/security
copy_etc /etc/pam.d

# SSH
copy_etc /etc/ssh/sshd_config
copy_etc /etc/ssh/sshd_config.d
copy_etc /etc/ssh/ssh_config
copy_etc /etc/ssh/ssh_config.d

# Sudo
copy_etc /etc/sudoers
copy_etc /etc/sudoers.d

# Audit / logging
copy_etc /etc/audit
copy_etc /etc/rsyslog.conf
copy_etc /etc/rsyslog.d
copy_etc /etc/systemd/journald.conf

# Network / firewall
copy_etc /etc/sysctl.conf
copy_etc /etc/sysctl.d
copy_etc /etc/firewalld
copy_etc /etc/sysconfig/iptables
copy_etc /etc/sysconfig/ip6tables
copy_etc /etc/nftables
copy_etc /etc/hosts.allow
copy_etc /etc/hosts.deny

# SELinux
copy_etc /etc/selinux/config

# Cron / scheduled tasks
copy_etc /etc/crontab
copy_etc /etc/cron.d
copy_etc /etc/cron.hourly
copy_etc /etc/cron.daily
copy_etc /etc/cron.weekly
copy_etc /etc/cron.monthly
copy_etc /etc/cron.allow
copy_etc /etc/cron.deny
copy_etc /etc/at.allow
copy_etc /etc/at.deny

# Mount / filesystem
copy_etc /etc/fstab

# Service / package management
copy_etc /etc/dnf/dnf.conf
copy_etc /etc/yum.repos.d
copy_etc /etc/yum/pluginconf.d
copy_etc /etc/aide.conf

# Banner / motd
copy_etc /etc/issue
copy_etc /etc/issue.net
copy_etc /etc/motd

# ----------------------------------------------------------------------------
# Command outputs (runtime state)
# ----------------------------------------------------------------------------
log "Collecting runtime command outputs..."

# Package inventory — primary input to the CVE module
capture_cmd rpm_qa rpm -qa --queryformat '%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{EPOCH}\n'

# systemd services
capture_cmd systemctl_unit_files  systemctl list-unit-files --no-pager --no-legend
capture_cmd systemctl_running     systemctl list-units --type=service --state=running --no-pager --no-legend
capture_cmd systemctl_failed      systemctl list-units --state=failed --no-pager --no-legend

# Audit / SELinux runtime
capture_cmd auditctl_rules        auditctl -l
capture_cmd auditctl_status       auditctl -s
capture_cmd sestatus              sestatus
capture_cmd getenforce            getenforce
capture_cmd semanage_login        semanage login -l
capture_cmd semanage_user         semanage user -l

# Kernel parameters
capture_cmd sysctl_a              sysctl -a

# Network / firewall runtime
capture_cmd firewall_cmd_list     firewall-cmd --list-all-zones
capture_cmd firewall_cmd_state    firewall-cmd --state
capture_cmd nft_list              nft list ruleset
capture_cmd iptables_save         iptables-save
capture_cmd ip6tables_save        ip6tables-save
capture_cmd ss_listen             ss -tulnp
capture_cmd ip_a                  ip -o addr show
capture_cmd ip_route              ip route show

# Filesystem snapshot
capture_cmd mount                 mount
capture_cmd findmnt               findmnt --raw
capture_cmd df_h                  df -hT

# Authentication runtime
capture_cmd lastlog_failed        faillock --user '*'
capture_cmd accounts_uid_zero     awk -F: '$3==0 {print $1":"$3":"$7}' /etc/passwd

# Cron runtime
capture_cmd crontab_root          crontab -l -u root

# Kernel & boot
capture_cmd uname_a               uname -a
capture_cmd boot_cmdline          cat /proc/cmdline
capture_cmd kernel_modules        lsmod

# AIDE / integrity
capture_cmd aide_status           aide --version

# Time sync
capture_cmd chronyc_sources       chronyc sources

# ----------------------------------------------------------------------------
# Bundle up
# ----------------------------------------------------------------------------
mkdir -p "$OUTPUT_DIR"
OUTPUT_PATH="${OUTPUT_DIR}/${BUNDLE_NAME}.tar.gz"
log "Creating archive: ${OUTPUT_PATH}"
( cd "$(dirname "${STAGE_DIR}")" && tar czf "${OUTPUT_PATH}" -C "${STAGE_DIR}" . )

SIZE="$(du -h "${OUTPUT_PATH}" 2>/dev/null | cut -f1)"
log "Done. Bundle size: ${SIZE}"
log "Transfer this file to the audit workstation and run:"
log "    python rhel8_scanner.py --bundle ${OUTPUT_PATH##*/} --output report.html"

echo "${OUTPUT_PATH}"
