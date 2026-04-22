#!/bin/bash
#
# harden.sh — Ubuntu 24.04 LTS CIS Level 1 Hardening Script
# Author: Illiasu (Nabbi)
# Date: April 2026
# Purpose: Automate production-grade server hardening from scratch
#
# Usage: sudo bash harden.sh
# Tested on: Ubuntu 24.04.4 LTS (AWS EC2)
#
# What this script does:
#   1. Baseline setup and system update
#   2. CIS Level 1 hardening
#   3. UFW firewall configuration
#   4. Fail2ban installation and configuration
#   5. Auditd installation and rules
#   6. Unattended upgrades configuration
#   7. Sudoers hardening
#
#################################################################

set -euo pipefail

#################################################################
# VARIABLES — change these before running
#################################################################

ADMIN_USER="nabbi"           # your named admin user
ADMIN_GROUP="admingroup"     # your admin group name
HOSTNAME="app-01"            # your server hostname
EMAIL="your@email.com"       # email for upgrade notifications

#################################################################
# COLOURS — for readable output
#################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # no colour

#################################################################
# HELPER FUNCTIONS
#################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Use: sudo bash harden.sh"
    fi
}

confirm() {
    read -r -p "${1} [y/N] " response
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

#################################################################
# PRE-FLIGHT CHECKS
#################################################################

preflight_checks() {
    log_info "Running pre-flight checks..."

    # Check Ubuntu version
    if ! grep -q "Ubuntu 24" /etc/os-release; then
        log_warning "This script is tested on Ubuntu 24.04. Proceed with caution on other versions."
    fi

    # Check admin user exists
    if ! id "$ADMIN_USER" &>/dev/null; then
        log_error "Admin user '$ADMIN_USER' does not exist. Create the user first then re-run."
    fi

    # Check internet connectivity
    if ! ping -c 1 8.8.8.8 &>/dev/null; then
        log_error "No internet connectivity. Cannot install packages."
    fi

    log_success "Pre-flight checks passed"
}

#################################################################
# STEP 1 — BASELINE SETUP
#################################################################

baseline_setup() {
    log_info "Step 1 — Baseline setup..."

    # Set hostname
    hostnamectl set-hostname "$HOSTNAME"
    log_success "Hostname set to $HOSTNAME"

    # Update and upgrade
    log_info "Updating package lists..."
    apt update -qq

    log_info "Upgrading packages — this may take a few minutes..."
    apt upgrade -y -qq

    log_success "System updated and patched"

    # Install required tools
    apt install -y -qq \
        ufw \
        fail2ban \
        auditd \
        audispd-plugins \
        unattended-upgrades \
        apt-listchanges \
        libpam-pwquality \
        tree

    log_success "Required packages installed"
}

#################################################################
# STEP 2 — CIS LEVEL 1 HARDENING
#################################################################

cis_hardening() {
    log_info "Step 2 — CIS Level 1 hardening..."

    # Lock root account
    passwd -l root
    log_success "Root account locked"

    # SSH hardening
    log_info "Hardening SSH configuration..."
    cat > /etc/ssh/sshd_config.d/hardening.conf << 'EOF'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
AllowTcpForwarding no
EOF
    systemctl restart sshd
    log_success "SSH hardened"

    # Restrict su to wheel group
    groupadd -f wheel
    usermod -aG wheel "$ADMIN_USER"
    if ! grep -q "pam_wheel.so use_uid" /etc/pam.d/su; then
        sed -i 's/^#auth\s*required\s*pam_wheel.so/auth required pam_wheel.so use_uid/' /etc/pam.d/su
        # If sed didn't find it, add it manually
        if ! grep -q "pam_wheel.so use_uid" /etc/pam.d/su; then
            echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
        fi
    fi
    log_success "su restricted to wheel group"

    # Password complexity policy
    cat > /etc/security/pwquality.conf << 'EOF'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
usercheck = 1
enforcing = 1
EOF
    log_success "Password complexity policy set"

    # Password aging
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
    log_success "Password aging policy set"

    # Apply aging to existing admin user
    chage -M 90 -m 7 -W 14 "$ADMIN_USER"
    log_success "Password aging applied to $ADMIN_USER"

    # Lock down /tmp
    if ! grep -q "tmpfs /tmp" /etc/fstab; then
        echo "tmpfs   /tmp   tmpfs   defaults,noexec,nosuid,nodev   0 0" >> /etc/fstab
        mount -o remount /tmp
        log_success "/tmp locked down with noexec,nosuid,nodev"
    else
        log_warning "/tmp already configured in fstab — skipping"
    fi

    # Disable unused filesystems
    cat > /etc/modprobe.d/cis-hardening.conf << 'EOF'
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF
    log_success "Unused filesystems disabled"

    # Sysctl hardening
    cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# Disable core dumps
fs.suid_dumpable = 0

# Enable ASLR
kernel.randomize_va_space = 2

# Disable IP forwarding
net.ipv4.ip_forward = 0

# Disable send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable accept redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Log martian packets
net.ipv4.conf.all.log_martians = 1

# Enable SYN cookies
net.ipv4.tcp_syncookies = 1

# Disable IPv6 redirects
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF
    sysctl --system -q
    log_success "Sysctl hardening applied"

    # Disable core dumps
    if ! grep -q "hard core 0" /etc/security/limits.conf; then
        echo "* hard core 0" >> /etc/security/limits.conf
    fi
    log_success "Core dumps disabled"
}

#################################################################
# STEP 3 — UFW FIREWALL
#################################################################

configure_ufw() {
    log_info "Step 3 — Configuring UFW firewall..."

    # Set defaults
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    # Allow SSH
    ufw allow 22/tcp

    # Enable
    ufw --force enable
    log_success "UFW enabled with default deny incoming, SSH allowed"
}

#################################################################
# STEP 4 — FAIL2BAN
#################################################################

configure_fail2ban() {
    log_info "Step 4 — Configuring Fail2ban..."

    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime  = 86400
findtime = 600
maxretry = 3
backend  = systemd

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = 3
bantime  = 86400
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban
    log_success "Fail2ban configured and running"
}

#################################################################
# STEP 5 — AUDITD
#################################################################

configure_auditd() {
    log_info "Step 5 — Configuring Auditd..."

    cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Delete all existing rules
-D

# Buffer size
-b 8192

# Failure mode — 1=log, 2=panic
-f 1

# Identity — watch user/group database files
-w /etc/passwd -p wa -k identity_change
-w /etc/shadow -p wa -k identity_change
-w /etc/group -p wa -k identity_change
-w /etc/gshadow -p wa -k identity_change

# Privilege escalation
-w /usr/bin/sudo -p x -k privilege_escalation
-w /bin/su -p x -k privilege_escalation

# Sudoers changes
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d/ -p wa -k sudoers_change

# SSH config changes
-w /etc/ssh/sshd_config -p wa -k sshd_config_change

# User management commands
-w /usr/sbin/useradd -p x -k user_mgmt
-w /usr/sbin/userdel -p x -k user_mgmt
-w /usr/sbin/usermod -p x -k user_mgmt
-w /usr/sbin/groupadd -p x -k user_mgmt
-w /usr/sbin/groupdel -p x -k user_mgmt

# Cron changes
-w /etc/cron.d/ -p wa -k cron_change
-w /etc/crontab -p wa -k cron_change
-w /var/spool/cron/ -p wa -k cron_change

# Login events
-w /var/log/faillog -p wa -k login_failure
-w /var/log/lastlog -p wa -k login_info
EOF

    augenrules --load
    systemctl enable auditd
    systemctl restart auditd
    log_success "Auditd configured with 19 rules"
}

#################################################################
# STEP 6 — UNATTENDED UPGRADES
#################################################################

configure_unattended_upgrades() {
    log_info "Step 6 — Configuring unattended upgrades..."

    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    # Configure upgrade settings
    sed -i 's|//.*"${distro_id}:${distro_codename}";|//      "${distro_id}:${distro_codename}";|' \
        /etc/apt/apt.conf.d/50unattended-upgrades

    # Set key options
    sed -i 's|//Unattended-Upgrade::Remove-Unused-Dependencies.*|Unattended-Upgrade::Remove-Unused-Dependencies "true";|' \
        /etc/apt/apt.conf.d/50unattended-upgrades

    sed -i 's|//Unattended-Upgrade::Automatic-Reboot .*|Unattended-Upgrade::Automatic-Reboot "false";|' \
        /etc/apt/apt.conf.d/50unattended-upgrades

    sed -i "s|//Unattended-Upgrade::Mail .*|Unattended-Upgrade::Mail \"${EMAIL}\";|" \
        /etc/apt/apt.conf.d/50unattended-upgrades

    systemctl enable unattended-upgrades
    systemctl restart unattended-upgrades
    log_success "Unattended upgrades configured"
}

#################################################################
# STEP 7 — SUDOERS HARDENING
#################################################################

configure_sudoers() {
    log_info "Step 7 — Hardening sudoers..."

    # Create admin group
    groupadd -f "$ADMIN_GROUP"
    usermod -aG "$ADMIN_GROUP" "$ADMIN_USER"

    # Create sudo I/O log directory
    mkdir -p /var/log/sudo-io
    chmod 700 /var/log/sudo-io

    # Write sudoers drop-in file
    cat > /etc/sudoers.d/hardening << EOF
# Admin group — full sudo access
%${ADMIN_GROUP}   ALL=(ALL:ALL) ALL

# Sudo hardening defaults
Defaults   logfile="/var/log/sudo.log"
Defaults   log_input, log_output
Defaults   iolog_dir="/var/log/sudo-io"
Defaults   requiretty
Defaults   passwd_timeout=1
Defaults   timestamp_timeout=5
Defaults   badpass_message="Invalid password"
EOF

    # Set correct permissions on sudoers drop-in
    chmod 440 /etc/sudoers.d/hardening

    # Validate sudoers syntax
    if visudo -c -f /etc/sudoers.d/hardening; then
        log_success "Sudoers hardened and validated"
    else
        log_error "Sudoers syntax error — check /etc/sudoers.d/hardening"
    fi
}

#################################################################
# VERIFICATION
#################################################################

verify_hardening() {
    log_info "Running verification checks..."
    echo ""

    # Root locked
    if passwd -S root | grep -q " L "; then
        log_success "Root account locked"
    else
        log_warning "Root account NOT locked"
    fi

    # SSH root login disabled
    if sshd -T | grep -q "permitrootlogin no"; then
        log_success "Root SSH login disabled"
    else
        log_warning "Root SSH login NOT disabled"
    fi

    # UFW active
    if ufw status | grep -q "Status: active"; then
        log_success "UFW firewall active"
    else
        log_warning "UFW firewall NOT active"
    fi

    # Fail2ban running
    if systemctl is-active --quiet fail2ban; then
        log_success "Fail2ban running"
    else
        log_warning "Fail2ban NOT running"
    fi

    # Auditd running
    if systemctl is-active --quiet auditd; then
        log_success "Auditd running"
    else
        log_warning "Auditd NOT running"
    fi

    # Audit rules loaded
    RULE_COUNT=$(auditctl -l | wc -l)
    if [[ $RULE_COUNT -ge 19 ]]; then
        log_success "Auditd rules loaded ($RULE_COUNT rules)"
    else
        log_warning "Auditd rules incomplete — only $RULE_COUNT rules loaded"
    fi

    # /tmp noexec
    if mount | grep "/tmp" | grep -q "noexec"; then
        log_success "/tmp mounted with noexec"
    else
        log_warning "/tmp noexec NOT set"
    fi

    # Sudo log exists
    if [[ -f /var/log/sudo.log ]]; then
        log_success "Sudo logging active"
    else
        log_warning "Sudo log not found — run a sudo command to initialise it"
    fi

    echo ""
    log_info "Check if reboot is required:"
    if [[ -f /var/run/reboot-required ]]; then
        log_warning "REBOOT REQUIRED — run: sudo reboot"
    else
        log_success "No reboot required"
    fi
}

#################################################################
# MAIN — runs all steps in order
#################################################################

main() {
    echo ""
    echo "=================================================="
    echo "   Ubuntu 24.04 Server Hardening Script"
    echo "   CIS Level 1 — by Illiasu (Nabbi)"
    echo "=================================================="
    echo ""

    check_root
    preflight_checks

    echo ""
    log_warning "This script will harden this server. Review variables at the top before proceeding."
    log_info "Admin user: $ADMIN_USER"
    log_info "Admin group: $ADMIN_GROUP"
    log_info "Hostname: $HOSTNAME"
    echo ""

    if ! confirm "Proceed with hardening?"; then
        log_info "Aborted."
        exit 0
    fi

    echo ""
    baseline_setup
    echo ""
    cis_hardening
    echo ""
    configure_ufw
    echo ""
    configure_fail2ban
    echo ""
    configure_auditd
    echo ""
    configure_unattended_upgrades
    echo ""
    configure_sudoers
    echo ""
    echo "=================================================="
    verify_hardening
    echo "=================================================="
    echo ""
    log_success "Hardening complete. Review any warnings above."
    echo ""
}

main "$@"