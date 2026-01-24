#!/bin/bash
#===============================================================================
# MWCCDC 2026 - Ubuntu Workstation (24.04) Hardening Script
# Target: Ubuntu Wks (Desktop 24.04.3)
# Default creds: sysadmin:changeme
# 
# NO FIREWALL/IPTABLES - as requested
# Run as root: sudo bash ubuntu_wks_harden.sh
#===============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
LOG_FILE="/var/log/hardening_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR="/root/backup_$(date +%Y%m%d_%H%M%S)"

log() {
    echo -e "${GREEN}[+]${NC} $1" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[-]${NC} $1" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[*]${NC} $1" | tee -a "$LOG_FILE"
}

#===============================================================================
# PRE-FLIGHT CHECKS
#===============================================================================
preflight() {
    info "Starting Ubuntu Workstation Hardening Script"
    info "Log file: $LOG_FILE"
    
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
    
    mkdir -p "$BACKUP_DIR"
    log "Backup directory created: $BACKUP_DIR"
    
    # Backup critical files
    log "Backing up critical configuration files..."
    cp /etc/passwd "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/shadow "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/group "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/sudoers "$BACKUP_DIR/" 2>/dev/null || true
    cp -r /etc/ssh "$BACKUP_DIR/" 2>/dev/null || true
    cp -r /etc/pam.d "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null || true
    crontab -l > "$BACKUP_DIR/root_crontab" 2>/dev/null || true
}

#===============================================================================
# USER ACCOUNT AUDIT AND HARDENING
#===============================================================================
harden_users() {
    log "========== USER ACCOUNT HARDENING =========="
    
    # List all users with login shells
    info "Users with login shells:"
    grep -E '/bin/(bash|sh|zsh|fish)' /etc/passwd | cut -d: -f1 | tee -a "$LOG_FILE"
    
    # List users with UID 0 (should only be root)
    info "Users with UID 0 (potential backdoor accounts):"
    awk -F: '($3 == 0) {print $1}' /etc/passwd | tee -a "$LOG_FILE"
    
    # Check for users with empty passwords
    info "Users with empty passwords:"
    awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null | tee -a "$LOG_FILE"
    
    # Lock suspicious accounts (adjust as needed for your environment)
    # Common backdoor account names
    SUSPICIOUS_USERS="msfadmin backdoor hacker test guest user1 admin administrator"
    for user in $SUSPICIOUS_USERS; do
        if id "$user" &>/dev/null; then
            warn "Found suspicious user: $user - Consider removing"
            # Uncomment to auto-lock: usermod -L "$user"
        fi
    done
    
    # Ensure password aging
    log "Setting password aging policies..."
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
    
    # Set minimum password length
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    12/' /etc/login.defs 2>/dev/null || \
        echo "PASS_MIN_LEN    12" >> /etc/login.defs
    
    # Lock the root account for direct login (use sudo instead)
    # passwd -l root  # Uncomment if you want to lock root
    
    # Disable guest account if it exists
    if [ -f /etc/lightdm/lightdm.conf ]; then
        log "Disabling guest account in lightdm..."
        echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
    fi
    
    # Remove unauthorized users from sudo/admin groups
    info "Users in sudo group:"
    getent group sudo | cut -d: -f4 | tee -a "$LOG_FILE"
    
    info "Users in admin group:"
    getent group admin 2>/dev/null | cut -d: -f4 | tee -a "$LOG_FILE"
}

#===============================================================================
# SSH HARDENING
#===============================================================================
harden_ssh() {
 if systemctl list-unit-files | grep -q '^ssh\.service'; then
        systemctl stop ssh.service 2>/dev/null || true
        systemctl disable ssh.service 2>/dev/null || true
    elif systemctl list-unit-files | grep -q '^sshd\.service'; then
        systemctl stop sshd.service 2>/dev/null || true
        systemctl disable sshd.service 2>/dev/null || true
    fi

    if dpkg -l | grep -q '^ii\s\+openssh-server'; then
        apt-get purge -y openssh-server || true
    fi
}

#===============================================================================
# SERVICE HARDENING
#===============================================================================
harden_services() {
    log "========== SERVICE HARDENING =========="
    
    # List all running services
    info "Currently running services:"
    systemctl list-units --type=service --state=running | tee -a "$LOG_FILE"
    
    # Dangerous services to disable
    DANGEROUS_SERVICES=(
        "telnet"
        "rsh"
        "rlogin"
        "rexec"
        "tftp"
        "vsftpd"
        "xinetd"
        "avahi-daemon"
        "cups-browsed"
        "rpcbind"
        "nfs-server"
        "snmpd"
        "named"
        "httpd"
        "nginx"
        "apache2"
        "smbd"
        "nmbd"
        "postgresql"
        "mysql"
        "mariadb"
        "mongod"
        "redis"
        "docker"
        "vncserver"
        "x11vnc"
        "tightvncserver"
        "ssh"
    )
    
    log "Checking for dangerous services..."
    for service in "${DANGEROUS_SERVICES[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            warn "Found running service: $service"
            # Uncomment to auto-disable:
            # systemctl stop "$service"
            # systemctl disable "$service"
        fi
    done
    
    # Check for services listening on ports
    info "Services listening on network ports:"
    ss -tulnp 2>/dev/null | tee -a "$LOG_FILE"
    
    # Alternative with netstat if ss not available
    # netstat -tulnp 2>/dev/null | tee -a "$LOG_FILE"
}

#===============================================================================
# CRON JOB AUDIT
#===============================================================================
audit_cron() {
    log "========== CRON JOB AUDIT =========="
    
    # Check system crontabs
    info "System crontab (/etc/crontab):"
    cat /etc/crontab 2>/dev/null | tee -a "$LOG_FILE"
    
    info "Cron directories:"
    for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        if [ -d "$crondir" ]; then
            info "Contents of $crondir:"
            ls -la "$crondir" 2>/dev/null | tee -a "$LOG_FILE"
        fi
    done
    
    # Check user crontabs
    info "User crontabs:"
    for user in $(cut -d: -f1 /etc/passwd); do
        crontab_content=$(crontab -u "$user" -l 2>/dev/null)
        if [ -n "$crontab_content" ]; then
            info "Crontab for $user:"
            echo "$crontab_content" | tee -a "$LOG_FILE"
        fi
    done
    
    # Check for suspicious cron entries
    warn "Checking for suspicious cron entries (reverse shells, etc.)..."
    grep -r "nc\|netcat\|bash -i\|/dev/tcp\|python.*socket\|perl.*socket\|ruby.*socket\|wget\|curl.*\|" \
        /etc/cron* /var/spool/cron 2>/dev/null | tee -a "$LOG_FILE"
}

#===============================================================================
# SUID/SGID BINARY AUDIT
#===============================================================================
audit_suid() {
    log "========== SUID/SGID BINARY AUDIT =========="
    
    info "Finding SUID binaries..."
    find / -perm -4000 -type f 2>/dev/null | tee -a "$LOG_FILE"
    
    info "Finding SGID binaries..."
    find / -perm -2000 -type f 2>/dev/null | tee -a "$LOG_FILE"
    
    # Common suspicious SUID binaries
    SUSPICIOUS_SUID=(
        "/usr/bin/nmap"
        "/usr/bin/vim"
        "/usr/bin/vi"
        "/usr/bin/nano"
        "/usr/bin/find"
        "/usr/bin/awk"
        "/usr/bin/perl"
        "/usr/bin/python"
        "/usr/bin/python3"
        "/usr/bin/ruby"
        "/usr/bin/gcc"
        "/usr/bin/less"
        "/usr/bin/more"
        "/usr/bin/man"
        "/usr/bin/wget"
        "/usr/bin/curl"
        "/usr/bin/nc"
        "/usr/bin/netcat"
        "/bin/nc"
        "/bin/netcat"
        "/usr/bin/socat"
        "/usr/bin/strace"
        "/usr/bin/ltrace"
        "/usr/bin/tcpdump"
        "/usr/bin/env"
    )
    
    warn "Checking for suspicious SUID binaries..."
    for binary in "${SUSPICIOUS_SUID[@]}"; do
        if [ -u "$binary" ] 2>/dev/null; then
            error "SUSPICIOUS SUID BINARY FOUND: $binary"
            # Remove SUID bit: chmod u-s "$binary"
        fi
    done
}

#===============================================================================
# WORLD-WRITABLE FILES AUDIT
#===============================================================================
audit_world_writable() {
    log "========== WORLD-WRITABLE FILES AUDIT =========="
    
    info "Finding world-writable files (excluding /proc, /sys, /dev)..."
    find / -xdev -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null | head -50 | tee -a "$LOG_FILE"
    
    info "Finding world-writable directories without sticky bit..."
    find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | tee -a "$LOG_FILE"
}

#===============================================================================
# PROCESS AUDIT (Look for suspicious processes)
#===============================================================================
audit_processes() {
    log "========== PROCESS AUDIT =========="
    
    info "All running processes:"
    ps auxf | tee -a "$LOG_FILE"
    
    # Check for suspicious processes
    warn "Checking for suspicious processes..."
    
    # Common reverse shell indicators
    SUSPICIOUS_PATTERNS=(
        "nc -e"
        "nc -l"
        "netcat"
        "ncat"
        "/dev/tcp"
        "bash -i"
        "python.*socket"
        "perl.*socket"
        "ruby.*socket"
        "socat"
        "msfconsole"
        "meterpreter"
        "beacon"
        "mimikatz"
        "cryptominer"
        "xmrig"
        "minerd"
    )
    
    for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
        if ps aux | grep -i "$pattern" | grep -v grep | tee -a "$LOG_FILE"; then
            error "Suspicious process found matching: $pattern"
        fi
    done
    
    # Check for hidden processes (comparing /proc to ps)
    info "Checking for hidden processes..."
    ps_procs=$(ps -e -o pid= | sort -n)
    proc_procs=$(ls /proc | grep -E '^[0-9]+$' | sort -n)
}

#===============================================================================
# NETWORK CONNECTION AUDIT
#===============================================================================
audit_network() {
    log "========== NETWORK CONNECTION AUDIT =========="
    
    info "Current network connections:"
    ss -tulnp 2>/dev/null | tee -a "$LOG_FILE"
    
    info "Established connections:"
    ss -tunp state established 2>/dev/null | tee -a "$LOG_FILE"
    
    info "Network interfaces:"
    ip addr show | tee -a "$LOG_FILE"
    
    info "Routing table:"
    ip route show | tee -a "$LOG_FILE"
    
    info "DNS configuration:"
    cat /etc/resolv.conf | tee -a "$LOG_FILE"
    
    info "Hosts file:"
    cat /etc/hosts | tee -a "$LOG_FILE"
    
    # Check for suspicious entries in hosts file
    warn "Checking hosts file for suspicious entries..."
    if grep -v "^#\|^$\|localhost\|127.0.0.1\|::1" /etc/hosts | grep -v "^$"; then
        warn "Found non-standard entries in /etc/hosts - REVIEW MANUALLY"
    fi
}

#===============================================================================
# KERNEL HARDENING (sysctl)
#===============================================================================
harden_kernel() {
    log "========== KERNEL HARDENING =========="
    
    log "Applying kernel hardening via sysctl..."
    
    cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# MWCCDC Kernel Hardening

# Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Enable SYN cookies
net.ipv4.tcp_syncookies = 1

# Enable reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Log martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Kernel hardening
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 1

# Disable core dumps
fs.suid_dumpable = 0

# Protect symlinks and hardlinks
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
EOF

    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-hardening.conf 2>/dev/null || warn "Some sysctl settings may not have applied"
}

#===============================================================================
# PAM HARDENING
#===============================================================================
harden_pam() {
    log "========== PAM HARDENING =========="
    
    # Add password complexity requirements
    if [ -f /etc/pam.d/common-password ]; then
        log "Configuring password complexity..."
        
        # Install libpam-pwquality if not present
        if ! dpkg -l libpam-pwquality &>/dev/null; then
            warn "libpam-pwquality not installed. Password complexity may be limited."
        fi
        
        # Configure pwquality
        if [ -f /etc/security/pwquality.conf ]; then
            cat > /etc/security/pwquality.conf << 'EOF'
# Password quality configuration
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
maxsequence = 3
reject_username
enforce_for_root
EOF
            log "Password quality settings configured"
        fi
    fi
    
    # Configure account lockout
    if [ -f /etc/pam.d/common-auth ]; then
        log "Configuring account lockout..."
        # Add faillock configuration if not present
        if ! grep -q "pam_faillock" /etc/pam.d/common-auth; then
            warn "Consider adding pam_faillock for account lockout after failed attempts"
        fi
    fi
}

#===============================================================================
# FILE PERMISSION HARDENING
#===============================================================================
harden_file_permissions() {
    log "========== FILE PERMISSION HARDENING =========="
    
    # Secure sensitive files
    log "Securing sensitive file permissions..."
    
    # /etc/passwd - world readable but not writable
    chmod 644 /etc/passwd
    chown root:root /etc/passwd
    
    # /etc/shadow - only root
    chmod 640 /etc/shadow
    chown root:shadow /etc/shadow
    
    # /etc/group
    chmod 644 /etc/group
    chown root:root /etc/group
    
    # /etc/gshadow
    chmod 640 /etc/gshadow 2>/dev/null
    chown root:shadow /etc/gshadow 2>/dev/null
    
    # /etc/sudoers
    chmod 440 /etc/sudoers
    chown root:root /etc/sudoers
    
    # SSH directory permissions
    if [ -d /etc/ssh ]; then
        chmod 755 /etc/ssh
        chmod 600 /etc/ssh/*_key 2>/dev/null
        chmod 644 /etc/ssh/*.pub 2>/dev/null
        chmod 644 /etc/ssh/sshd_config
    fi
    
    # Secure home directories
    log "Securing home directory permissions..."
    for home in /home/*; do
        if [ -d "$home" ]; then
            chmod 700 "$home"
            if [ -d "$home/.ssh" ]; then
                chmod 700 "$home/.ssh"
                chmod 600 "$home/.ssh/authorized_keys" 2>/dev/null
                chmod 600 "$home/.ssh/id_rsa" 2>/dev/null
                chmod 644 "$home/.ssh/id_rsa.pub" 2>/dev/null
            fi
        fi
    done
    
    # Secure /root
    chmod 700 /root
    if [ -d /root/.ssh ]; then
        chmod 700 /root/.ssh
        chmod 600 /root/.ssh/authorized_keys 2>/dev/null
    fi
}

#===============================================================================
# STARTUP SCRIPT AUDIT
#===============================================================================
audit_startup() {
    log "========== STARTUP SCRIPT AUDIT =========="
    
    info "Systemd enabled services:"
    systemctl list-unit-files --state=enabled | tee -a "$LOG_FILE"
    
    info "Init.d scripts:"
    ls -la /etc/init.d/ 2>/dev/null | tee -a "$LOG_FILE"
    
    info "RC local:"
    cat /etc/rc.local 2>/dev/null | tee -a "$LOG_FILE"
    
    info "User .bashrc files (checking for suspicious entries):"
    for home in /home/* /root; do
        if [ -f "$home/.bashrc" ]; then
            info "Checking $home/.bashrc"
            # Look for suspicious commands in .bashrc
            if grep -E "nc\s|netcat|/dev/tcp|bash\s+-i|python.*socket|wget|curl.*\||exec" "$home/.bashrc" 2>/dev/null; then
                error "SUSPICIOUS entry found in $home/.bashrc"
            fi
        fi
        if [ -f "$home/.profile" ]; then
            if grep -E "nc\s|netcat|/dev/tcp|bash\s+-i|python.*socket|wget|curl.*\||exec" "$home/.profile" 2>/dev/null; then
                error "SUSPICIOUS entry found in $home/.profile"
            fi
        fi
    done
    
    # Check /etc/profile and /etc/profile.d
    info "System profile scripts:"
    cat /etc/profile 2>/dev/null | tee -a "$LOG_FILE"
    ls -la /etc/profile.d/ 2>/dev/null | tee -a "$LOG_FILE"
}

#===============================================================================
# MALWARE/ROOTKIT CHECK
#===============================================================================
check_malware() {
    log "========== MALWARE/ROOTKIT CHECK =========="
    
    # Check for common backdoor locations
    BACKDOOR_LOCATIONS=(
        "/tmp"
        "/var/tmp"
        "/dev/shm"
        "/var/www"
        "/opt"
    )
    
    info "Checking common backdoor locations..."
    for loc in "${BACKDOOR_LOCATIONS[@]}"; do
        if [ -d "$loc" ]; then
            info "Contents of $loc:"
            ls -la "$loc" 2>/dev/null | head -20 | tee -a "$LOG_FILE"
            
            # Look for hidden files
            hidden=$(find "$loc" -name ".*" -type f 2>/dev/null)
            if [ -n "$hidden" ]; then
                warn "Hidden files found in $loc:"
                echo "$hidden" | tee -a "$LOG_FILE"
            fi
            
            # Look for executable files
            executables=$(find "$loc" -type f -executable 2>/dev/null)
            if [ -n "$executables" ]; then
                warn "Executable files in $loc:"
                echo "$executables" | tee -a "$LOG_FILE"
            fi
        fi
    done
    
    # Check for common webshells if web directory exists
    if [ -d "/var/www" ]; then
        warn "Checking for potential webshells..."
        grep -r "eval\|base64_decode\|exec\|system\|passthru\|shell_exec" /var/www 2>/dev/null | head -20 | tee -a "$LOG_FILE"
    fi
    
    # Check for suspicious files in /etc
    info "Checking for suspicious files in /etc..."
    find /etc -name "*.sh" -o -name "*.py" -o -name "*.pl" 2>/dev/null | tee -a "$LOG_FILE"
}

#===============================================================================
# LOGGING HARDENING
#===============================================================================
harden_logging() {
    log "========== LOGGING HARDENING =========="
    
    # Ensure auditd is installed and running
    if command -v auditd &>/dev/null; then
        log "Auditd is available"
        systemctl enable auditd 2>/dev/null
        systemctl start auditd 2>/dev/null
    else
        warn "auditd not installed - consider installing for better audit capabilities"
    fi
    
    # Ensure rsyslog is running
    if systemctl is-active --quiet rsyslog; then
        log "rsyslog is running"
    else
        warn "rsyslog is not running - starting..."
        systemctl start rsyslog 2>/dev/null
        systemctl enable rsyslog 2>/dev/null
    fi
    
    # Check log file permissions
    log "Securing log file permissions..."
    chmod -R g-wx,o-rwx /var/log/* 2>/dev/null
    
    # Ensure log rotation is configured
    if [ -f /etc/logrotate.conf ]; then
        log "Log rotation is configured"
    fi
}

#===============================================================================
# PACKAGE AUDIT
#===============================================================================
audit_packages() {
    log "========== PACKAGE AUDIT =========="
    
    # List installed packages
    info "Total installed packages: $(dpkg -l | grep -c '^ii')"
    
    # Check for suspicious packages
    SUSPICIOUS_PACKAGES=(
        "nmap"
        "netcat"
        "nc"
        "wireshark"
        "hydra"
        "john"
        "aircrack-ng"
        "metasploit"
        "nikto"
        "sqlmap"
        "burpsuite"
        "ettercap"
        "dsniff"
        "beef"
    )
    
    warn "Checking for potentially suspicious packages..."
    for pkg in "${SUSPICIOUS_PACKAGES[@]}"; do
        if dpkg -l "$pkg" &>/dev/null; then
            warn "Found package: $pkg - Review if needed"
        fi
    done
    
    # Check for packages that shouldn't be on a workstation
    info "Checking for server packages that may not be needed..."
    SERVER_PACKAGES=(
        "apache2"
        "nginx"
        "mysql-server"
        "postgresql"
        "samba"
        "bind9"
        "postfix"
        "dovecot"
    )
    
    for pkg in "${SERVER_PACKAGES[@]}"; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
            warn "Server package installed: $pkg - May not be needed on workstation"
        fi
    done
}

#===============================================================================
# GENERATE REPORT
#===============================================================================
generate_report() {
    log "========== GENERATING FINAL REPORT =========="
    
    REPORT_FILE="/root/hardening_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$REPORT_FILE" << EOF
================================================================================
MWCCDC 2026 - Ubuntu Workstation Hardening Report
Generated: $(date)
Hostname: $(hostname)
================================================================================

SYSTEM INFORMATION:
-------------------
OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
Kernel: $(uname -r)
Architecture: $(uname -m)
Uptime: $(uptime)

USERS WITH LOGIN SHELLS:
------------------------
$(grep -E '/bin/(bash|sh|zsh|fish)' /etc/passwd | cut -d: -f1)

USERS WITH UID 0:
-----------------
$(awk -F: '($3 == 0) {print $1}' /etc/passwd)

SUDO GROUP MEMBERS:
-------------------
$(getent group sudo | cut -d: -f4)

LISTENING PORTS:
----------------
$(ss -tulnp 2>/dev/null)

RUNNING SERVICES:
-----------------
$(systemctl list-units --type=service --state=running --no-pager | head -30)

SUID BINARIES:
--------------
$(find / -perm -4000 -type f 2>/dev/null)

RECENT LOGINS:
--------------
$(last -10)

FAILED LOGIN ATTEMPTS:
----------------------
$(lastb -10 2>/dev/null || echo "No failed logins recorded")

================================================================================
See full log at: $LOG_FILE
Backups stored at: $BACKUP_DIR
================================================================================
EOF

    log "Report generated: $REPORT_FILE"
}

#===============================================================================
# PASSWORD CHANGE HELPER
#===============================================================================
change_passwords_interactive() {
    log "========== PASSWORD CHANGE HELPER =========="
    
    info "Users that should have passwords changed:"
    echo "  - sysadmin (default: changeme)"
    echo ""
    info "To change passwords manually, use:"
    echo "  passwd <username>"
    echo ""
    info "To change the sysadmin password now, run:"
    echo "  passwd sysadmin"
    
    # Generate secure password suggestions
    if command -v openssl &>/dev/null; then
        info "Suggested strong passwords:"
        echo "  $(openssl rand -base64 12)"
        echo "  $(openssl rand -base64 12)"
        echo "  $(openssl rand -base64 12)"
    fi
}

#===============================================================================
# QUICK WINS
#===============================================================================
quick_wins() {
    log "========== APPLYING QUICK WINS =========="
    
    # Disable USB storage (uncomment if needed)
    # echo "blacklist usb-storage" > /etc/modprobe.d/disable-usb-storage.conf
    # log "USB storage disabled"
    
    # Set restrictive umask
    log "Setting restrictive umask..."
    echo "umask 027" >> /etc/profile
    
    # Disable Ctrl+Alt+Del reboot
    log "Disabling Ctrl+Alt+Del reboot..."
    systemctl mask ctrl-alt-del.target 2>/dev/null
    
    # Set secure permissions on /etc/cron* directories
    log "Securing cron directories..."
    chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null
    
    # Remove MOTD news
    if [ -f /etc/default/motd-news ]; then
        sed -i 's/ENABLED=1/ENABLED=0/' /etc/default/motd-news
    fi
    
    # Disable apport (crash reporting)
    if [ -f /etc/default/apport ]; then
        sed -i 's/enabled=1/enabled=0/' /etc/default/apport
        systemctl stop apport 2>/dev/null
        systemctl disable apport 2>/dev/null
        log "Apport disabled"
    fi
}

#===============================================================================
# MAIN
#===============================================================================
main() {
    echo "================================================================================"
    echo "  MWCCDC 2026 - Ubuntu Workstation Hardening Script"
    echo "  Target: Ubuntu 24.04 Desktop"
    echo "================================================================================"
    echo ""
    
    # Run all functions
    preflight
    harden_users
    harden_ssh
    harden_services
    audit_cron
    audit_suid
    audit_world_writable
    audit_processes
    audit_network
    harden_kernel
    harden_pam
    harden_file_permissions
    audit_startup
    check_malware
    harden_logging
    audit_packages
    quick_wins
    change_passwords_interactive
    generate_report
    
    echo ""
    echo "================================================================================"
    log "Hardening complete!"
    info "Review log file: $LOG_FILE"
    info "Review report: /root/hardening_report_*.txt"
    info "Backups stored in: $BACKUP_DIR"
    echo "================================================================================"
    echo ""
    warn "REMEMBER TO:"
    echo "  1. Change default passwords (sysadmin:changeme)"
    echo "  2. Review any suspicious findings in the log"
    echo "  3. Remove any unauthorized users"
    echo "  4. Review and clean up authorized_keys files"
    echo "  5. Disable any unnecessary services"
    echo "  6. Keep monitoring the NISE for injects!"
    echo ""
}

# Run main function
main "$@"
