#!/bin/bash

################################################################################
# CCDC Competition Hardening Script
# Designed for 2026 Midwest CCDC Qualifier
# 
# IMPORTANT COMPETITION RULES TO REMEMBER:
# - Do NOT scan other teams or Red Team (instant disqualification)
# - Do NOT modify public IP addresses or move services between IPs
# - Do NOT change system names or internal IPs unless directed by inject
# - Maintain ICMP on all devices (except Palo Alto core port)
# - Allow White/Black/Green Team access when requested
# - Score tracking available via NISE portal
# 
# System Information from Team Pack:
# - Ubuntu Ecom (24.04.3) - Web/Ecommerce server
# - Fedora Webmail (42) - Email server  
# - Splunk (Oracle Linux 9.2) - SIEM/Logging
# - Ubuntu Wks (24.04.3) - User workstation
# - Server 2019 AD/DNS - Domain controller
# - Server 2019 Web - IIS web server
# - Server 2022 FTP - File transfer server
# - Windows 11 Wks - User workstation
# - Palo Alto (11.0.2) - Firewall
# - Cisco FTD (7.2.9) - Firewall
# - VyOS Router (1.4.3) - Router
#
# Scored Services (from Team Pack):
# - HTTP/HTTPS (Web servers must serve correct content)
# - SMTP (Email sending/receiving)
# - POP3 (Email retrieval)
# - DNS (Must resolve lookups correctly)
################################################################################

# Check if running as root
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: Must be run as root"
  exit 1
fi

# Competition-specific variables
CCDC_DIR="/ccdc"
CCDC_ETC="$CCDC_DIR/etc"
SCRIPT_DIR="$CCDC_DIR/scripts"
BACKUP_DIR="$CCDC_DIR/backups"
LOGFILE="$CCDC_DIR/logs/ccdc-hardening.log"

# Color variables for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOGFILE"
}

log_info() {
    log "INFO" "$@"
}

log_warn() {
    echo -e "${YELLOW}$(log "WARN" "$@")${NC}"
}

log_error() {
    echo -e "${RED}$(log "ERROR" "$@")${NC}"
}

log_success() {
    echo -e "${GREEN}$(log "SUCCESS" "$@")${NC}"
}

# Initialize directory structure
initialize_directories() {
    log_info "Creating CCDC directory structure..."
    
    mkdir -p "$CCDC_DIR"/{logs,scripts,backups/{original,incremental},etc,tools}
    mkdir -p "$SCRIPT_DIR"/{linux,incident_response}
    
    # Set proper permissions
    chmod 700 "$CCDC_DIR"
    chmod 600 "$LOGFILE" 2>/dev/null || touch "$LOGFILE" && chmod 600 "$LOGFILE"
    
    log_success "Directory structure created"
}

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION_ID="$VERSION_ID"
        OS_NAME="$NAME"
    else
        log_error "Cannot detect OS - /etc/os-release not found"
        exit 1
    fi
    
    log_info "Detected OS: $OS_NAME ($OS_ID $OS_VERSION_ID)"
}

# CRITICAL: Check for malicious bash configurations
# Red Team often plants persistence mechanisms in shell configs
check_malicious_bash() {
    log_info "Checking for malicious bash configurations..."
    
    local suspicious_files=()
    local files_to_check=(
        /etc/bashrc
        /etc/profile
        /etc/profile.d/*
        /etc/bash.bashrc
        /etc/bash.bash_logout
        /etc/environment
        /root/.bashrc
        /root/.bash_profile
        /root/.bash_logout
        /root/.bash_login
        /root/.profile
        /home/*/.bashrc
        /home/*/.bash_profile
        /home/*/.bash_logout
        /home/*/.bash_login
        /home/*/.profile
    )
    
    for pattern in "${files_to_check[@]}"; do
        for file in $pattern; do
            if [ -f "$file" ]; then
                # Check for traps, PROMPT_COMMAND, watch commands
                if grep -qE "^[^#]*(trap|PROMPT_COMMAND|watch )" "$file"; then
                    log_warn "Suspicious content found in $file"
                    
                    # Extract and log the suspicious lines
                    grep -nE "^[^#]*(trap|PROMPT_COMMAND|watch )" "$file" >> "$CCDC_DIR/logs/suspicious_bash_$(date +%s).txt"
                    
                    # Back up the file
                    cp "$file" "$BACKUP_DIR/original/$(basename $file).$(stat -c %Y $file).bak"
                    
                    # Remove suspicious lines (commented out by default for safety)
                    # sed -i '/^[^#]*trap/d; /^[^#]*PROMPT_COMMAND/d; /^[^#]*watch /d' "$file"
                    
                    suspicious_files+=("$file")
                fi
            fi
        done
    done
    
    if [ ${#suspicious_files[@]} -gt 0 ]; then
        log_warn "Found ${#suspicious_files[@]} files with suspicious content. Review $CCDC_DIR/logs/suspicious_bash_*.txt"
        log_warn "Manual review recommended before removing suspicious lines"
    else
        log_success "No obvious malicious bash configurations detected"
    fi
    
    # Clear current environment
    export PROMPT_COMMAND=''
    trap - $(trap -p | awk '{print $NF}' | tr -d "'")
}

# Network configuration
configure_network() {
    log_info "Configuring network settings..."
    
    # CRITICAL: Do NOT change the IP addressing or break scored services
    # Only harden, don't restructure
    
    # Get main interface
    INTERFACE=$(ip route | grep default | awk '{print $5}')
    log_info "Primary interface: $INTERFACE"
    
    # Set DNS to reliable servers (competition allows this)
    cat > /etc/resolv.conf <<EOF
# CCDC Competition DNS
nameserver 1.1.1.1
nameserver 1.0.0.1
nameserver 8.8.8.8
EOF
    
    # Make resolv.conf immutable to prevent tampering
    chattr +i /etc/resolv.conf
    
    log_success "Network configuration completed"
}

# Kernel hardening via sysctl
harden_kernel() {
    log_info "Applying kernel hardening..."
    
    cat > /etc/sysctl.d/99-ccdc-hardening.conf <<EOF
# CCDC Kernel Hardening Configuration
# Applied: $(date)

# Network Security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_timestamps = 0

# IPv6 Security
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Kernel Security
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.randomize_va_space = 2
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
kernel.sysrq = 0

# Filesystem Security  
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
    
    sysctl -p /etc/sysctl.d/99-ccdc-hardening.conf > /dev/null 2>&1
    
    log_success "Kernel hardening applied"
}

# User account management - CRITICAL FOR CCDC
manage_users() {
    log_info "Managing user accounts..."
    
    # Get current user (preserve this account!)
    if [[ -n "$SUDO_USER" ]]; then
        CURRENT_USER="$SUDO_USER"
    else
        CURRENT_USER="$USER"
    fi
    
    log_info "Preserving current user: $CURRENT_USER"
    
    # List all users with login shells
    cat > "$SCRIPT_DIR/linux/user_audit.sh" <<'EOFSCRIPT'
#!/bin/bash
echo "=== User Account Audit ==="
echo "Date: $(date)"
echo ""
echo "Users with login shells:"
awk -F: '$7 !~ /(nologin|false)/ {print $1 ":" $3 ":" $7}' /etc/passwd
echo ""
echo "Recently logged in users:"
lastlog | head -20
echo ""
echo "Users with sudo privileges:"
grep -Po '^sudo.+:\K.*$' /etc/group
EOFSCRIPT
    chmod +x "$SCRIPT_DIR/linux/user_audit.sh"
    
    bash "$SCRIPT_DIR/linux/user_audit.sh" > "$CCDC_DIR/logs/user_audit_initial.txt"
    
    # Interactive user locking (recommended for competition start)
    cat > "$SCRIPT_DIR/linux/lock_users_interactive.sh" <<'EOFSCRIPT'
#!/bin/bash
if [[ $EUID -ne 0 ]]; then
    echo "Must be run as root"
    exit 1
fi

CURRENT_USER="${SUDO_USER:-$USER}"
echo "Current user (will NOT be locked): $CURRENT_USER"
echo ""
echo "=== Interactive User Locking ==="
echo "Review each user and decide whether to lock the account"
echo ""

while IFS=: read -r username uid shell; do
    # Skip root and current user
    if [ "$username" = "root" ] || [ "$username" = "$CURRENT_USER" ]; then
        continue
    fi
    
    # Skip system users (UID < 1000)
    if [ "$uid" -lt 1000 ]; then
        continue
    fi
    
    # Check if already locked
    if passwd -S "$username" | grep -q " L "; then
        echo "[ALREADY LOCKED] $username (UID: $uid, Shell: $shell)"
        continue
    fi
    
    echo -n "Lock user '$username' (UID: $uid, Shell: $shell)? [y/N]: "
    read -r response
    
    if [[ "$response" =~ ^[Yy]$ ]]; then
        usermod -s /sbin/nologin "$username"
        passwd -l "$username"
        echo "[LOCKED] $username"
    else
        echo "[SKIPPED] $username"
    fi
    echo ""
done < <(awk -F: '$7 !~ /(nologin|false)/ && $3 >= 1000 {print $1 ":" $3 ":" $7}' /etc/passwd)

echo ""
echo "User locking complete"
EOFSCRIPT
    chmod +x "$SCRIPT_DIR/linux/lock_users_interactive.sh"
    
    log_success "User management scripts created. Run lock_users_interactive.sh when ready."
}

# Password policy hardening
harden_passwords() {
    log_info "Hardening password policies..."
    
    # Configure PAM for strong passwords
    if [ -f /etc/pam.d/common-password ]; then
        # Debian/Ubuntu
        if ! grep -q "pam_pwquality" /etc/pam.d/common-password; then
            sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1' /etc/pam.d/common-password
        fi
    elif [ -f /etc/pam.d/system-auth ]; then
        # RHEL/CentOS/Fedora
        if ! grep -q "pam_pwquality" /etc/pam.d/system-auth; then
            sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1' /etc/pam.d/system-auth
        fi
    fi
    
    # Configure login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    14/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
    sed -i 's/^UMASK.*/UMASK           077/' /etc/login.defs
    
    # Add last login notification
    if [ -f /etc/pam.d/system-auth ] && ! grep -q "pam_lastlog.so" /etc/pam.d/system-auth; then
        echo "session required pam_lastlog.so showfailed" >> /etc/pam.d/system-auth
    fi
    
    log_success "Password policies hardened"
}

# Cron job security - CRITICAL: Red Team loves cron persistence
secure_cron() {
    log_info "Securing cron jobs..."
    
    # Create cron jail directory
    mkdir -p "$CCDC_ETC/cron.jail"
    
    # Backup and review all cron jobs
    local cron_locations=(
        "/etc/crontab"
        "/etc/cron.d"
        "/etc/cron.daily"
        "/etc/cron.hourly"
        "/etc/cron.weekly"
        "/etc/cron.monthly"
        "/var/spool/cron"
    )
    
    log_info "Backing up cron jobs for review..."
    for location in "${cron_locations[@]}"; do
        if [ -e "$location" ]; then
            cp -r "$location" "$CCDC_ETC/cron.jail/" 2>/dev/null
            log_info "Backed up: $location"
        fi
    done
    
    # List all cron jobs to a file for review
    cat > "$CCDC_DIR/logs/cron_audit.txt" <<EOF
=== CRON JOB AUDIT ===
Generated: $(date)

System Crontab:
$(cat /etc/crontab 2>/dev/null || echo "Not found")

Cron.d:
$(ls -la /etc/cron.d 2>/dev/null || echo "Not found")

User Crontabs:
$(for user in $(cut -f1 -d: /etc/passwd); do echo "=== $user ==="; crontab -u $user -l 2>/dev/null || echo "No crontab"; done)
EOF
    
    # Lock down cron access
    echo "root" > /etc/cron.allow
    rm -f /etc/cron.deny
    chmod 600 /etc/cron.allow
    
    # Lock down at access
    echo "root" > /etc/at.allow
    rm -f /etc/at.deny
    chmod 600 /etc/at.allow
    
    log_success "Cron jobs backed up to $CCDC_ETC/cron.jail"
    log_warn "IMPORTANT: Review $CCDC_DIR/logs/cron_audit.txt for suspicious jobs"
}

# Service management
manage_services() {
    log_info "Managing services..."
    
    # CRITICAL: Do NOT disable scored services!
    # HTTP, HTTPS, SMTP, POP3, DNS must remain functional
    
    # Create service audit
    systemctl list-units --type=service --state=running > "$CCDC_DIR/logs/services_running.txt"
    systemctl list-unit-files --type=service --state=enabled > "$CCDC_DIR/logs/services_enabled.txt"
    
    # Disable obviously dangerous services (if they exist and aren't needed)
    local dangerous_services=(
        "telnet"
        "rsh"
        "rlogin"
        "vsftpd"
        "tftp"
        "talk"
    )
    
    for service in "${dangerous_services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log_warn "Dangerous service detected: $service"
            # Don't auto-disable - let team decide
            # systemctl disable --now "$service"
        fi
    done
    
    # Enable useful services
    systemctl enable --now auditd 2>/dev/null
    systemctl enable --now rsyslog 2>/dev/null
    
    log_success "Service audit complete. Review logs in $CCDC_DIR/logs/"
}

# Backup functionality - CRITICAL FOR COMPETITION
create_backup_system() {
    log_info "Creating backup system..."
    
    cat > "$SCRIPT_DIR/linux/backup_critical.sh" <<'EOFBACKUP'
#!/bin/bash
# CCDC Critical System Backup

BACKUP_DIR="/ccdc/backups/incremental"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="backup_${TIMESTAMP}"

mkdir -p "$BACKUP_DIR/$BACKUP_NAME"

echo "=== CCDC Backup Started: $(date) ===" | tee "$BACKUP_DIR/$BACKUP_NAME/backup.log"

# Backup critical system files
echo "Backing up system configuration..." | tee -a "$BACKUP_DIR/$BACKUP_NAME/backup.log"
tar -czf "$BACKUP_DIR/$BACKUP_NAME/etc.tar.gz" /etc/ 2>/dev/null

# Backup web content (if applicable)
if [ -d /var/www/html ]; then
    echo "Backing up web content..." | tee -a "$BACKUP_DIR/$BACKUP_NAME/backup.log"
    tar -czf "$BACKUP_DIR/$BACKUP_NAME/www.tar.gz" /var/www/html/ 2>/dev/null
fi

# Backup databases (MySQL/MariaDB)
if command -v mysqldump &> /dev/null; then
    echo "Backing up databases..." | tee -a "$BACKUP_DIR/$BACKUP_NAME/backup.log"
    # Note: Will need authentication
    # mysqldump --all-databases > "$BACKUP_DIR/$BACKUP_NAME/databases.sql" 2>/dev/null
fi

# Backup user home directories
echo "Backing up home directories..." | tee -a "$BACKUP_DIR/$BACKUP_NAME/backup.log"
tar -czf "$BACKUP_DIR/$BACKUP_NAME/home.tar.gz" /home/ 2>/dev/null

# Backup cron jobs
echo "Backing up cron jobs..." | tee -a "$BACKUP_DIR/$BACKUP_NAME/backup.log"
tar -czf "$BACKUP_DIR/$BACKUP_NAME/cron.tar.gz" /etc/cron* /var/spool/cron 2>/dev/null

echo "=== Backup Complete: $(date) ===" | tee -a "$BACKUP_DIR/$BACKUP_NAME/backup.log"
echo "Backup location: $BACKUP_DIR/$BACKUP_NAME"

# Keep only last 10 backups
cd "$BACKUP_DIR"
ls -t | tail -n +11 | xargs -r rm -rf
EOFBACKUP
    
    chmod +x "$SCRIPT_DIR/linux/backup_critical.sh"
    
    # Create initial backup
    log_info "Creating initial system backup..."
    bash "$SCRIPT_DIR/linux/backup_critical.sh"
    
    log_success "Backup system created. Run $SCRIPT_DIR/linux/backup_critical.sh as needed"
}

# Incident response preparation
setup_incident_response() {
    log_info "Setting up incident response tools..."
    
    # Create incident report template
    cat > "$SCRIPT_DIR/incident_response/IR_TEMPLATE.txt" <<'EOFIR'
================================================================================
INCIDENT REPORT - 2026 MWCCDC Qualifier
================================================================================

Report ID: IR-[YYYYMMDD]-[###]
Date/Time Detected: 
Reported By: 
Severity: [ ] Critical  [ ] High  [ ] Medium  [ ] Low

================================================================================
1. INCIDENT SUMMARY
================================================================================
Brief description of the incident:




================================================================================
2. DETECTION DETAILS
================================================================================
How was the incident detected?


Source IP Address(es):


Destination IP Address(es):


Affected System(s):


Timeline of Activity:
- 
- 
- 

================================================================================
3. IMPACT ASSESSMENT
================================================================================
What was affected?


Services impacted:


Data accessed/modified:


================================================================================
4. EVIDENCE COLLECTED
================================================================================
Log files examined:


Commands executed during investigation:


Suspicious files found:


Network traffic captured:


================================================================================
5. ROOT CAUSE ANALYSIS
================================================================================
How did the attacker gain access?


Vulnerabilities exploited:


================================================================================
6. REMEDIATION ACTIONS TAKEN
================================================================================
Immediate actions:
- 
- 

Passwords changed:
- 

Services restarted:
- 

Firewall rules added:
- 

================================================================================
7. LESSONS LEARNED
================================================================================
What could have prevented this?


Recommended improvements:


================================================================================
8. ADDITIONAL NOTES
================================================================================


================================================================================
Report Completed By: ______________________ Date: ______________
================================================================================
EOFIR
    
    # Create quick investigation script
    cat > "$SCRIPT_DIR/incident_response/quick_investigate.sh" <<'EOFINV'
#!/bin/bash
# Quick investigation script for CCDC

OUTPUT_DIR="/ccdc/logs/investigations/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"

echo "=== Quick Investigation Report ===" | tee "$OUTPUT_DIR/report.txt"
echo "Generated: $(date)" | tee -a "$OUTPUT_DIR/report.txt"
echo "" | tee -a "$OUTPUT_DIR/report.txt"

echo "=== Active Network Connections ===" | tee -a "$OUTPUT_DIR/report.txt"
netstat -tunap 2>/dev/null | grep ESTABLISHED | tee -a "$OUTPUT_DIR/connections.txt"
echo "" | tee -a "$OUTPUT_DIR/report.txt"

echo "=== Recently Modified Files (last 60 min) ===" | tee -a "$OUTPUT_DIR/report.txt"
find /etc /home /var/www -type f -mmin -60 2>/dev/null | tee -a "$OUTPUT_DIR/recent_files.txt"
echo "" | tee -a "$OUTPUT_DIR/report.txt"

echo "=== Currently Logged In Users ===" | tee -a "$OUTPUT_DIR/report.txt"
w | tee -a "$OUTPUT_DIR/users.txt"
echo "" | tee -a "$OUTPUT_DIR/report.txt"

echo "=== Recent Auth Logs ===" | tee -a "$OUTPUT_DIR/report.txt"
tail -100 /var/log/auth.log /var/log/secure 2>/dev/null | tee -a "$OUTPUT_DIR/auth.txt"
echo "" | tee -a "$OUTPUT_DIR/report.txt"

echo "=== Suspicious Processes ===" | tee -a "$OUTPUT_DIR/report.txt"
ps aux | grep -E '(nc|ncat|netcat|/dev/tcp|bash -i|sh -i|perl|python|ruby) ' | grep -v grep | tee -a "$OUTPUT_DIR/processes.txt"
echo "" | tee -a "$OUTPUT_DIR/report.txt"

echo "=== Report saved to: $OUTPUT_DIR ===" | tee -a "$OUTPUT_DIR/report.txt"
EOFINV
    
    chmod +x "$SCRIPT_DIR/incident_response/quick_investigate.sh"
    
    log_success "Incident response tools created"
}

# Network monitoring setup
setup_monitoring() {
    log_info "Setting up network monitoring..."
    
    # Create connection monitoring script
    cat > "$SCRIPT_DIR/linux/monitor_connections.sh" <<'EOFMON'
#!/bin/bash
# Monitor network connections for suspicious activity

LOG_FILE="/ccdc/logs/network_monitor.log"
ALERT_FILE="/ccdc/logs/network_alerts.log"

while true; do
    TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
    
    # Log all ESTABLISHED connections
    netstat -tunap 2>/dev/null | grep ESTABLISHED >> "$LOG_FILE"
    
    # Check for suspicious ports
    SUSPICIOUS=$(netstat -tunap 2>/dev/null | grep ESTABLISHED | grep -E ':(4444|31337|1337|6666|6667)')
    
    if [ ! -z "$SUSPICIOUS" ]; then
        echo "[$TIMESTAMP] ALERT: Suspicious connection detected!" >> "$ALERT_FILE"
        echo "$SUSPICIOUS" >> "$ALERT_FILE"
        
        # Optional: Send notification (implement based on team communication method)
        # echo "ALERT: Suspicious connection" | wall
    fi
    
    sleep 30
done
EOFMON
    
    chmod +x "$SCRIPT_DIR/linux/monitor_connections.sh"
    
    # Note: Team should run this in background or tmux session
    # nohup /ccdc/scripts/linux/monitor_connections.sh &
    
    log_success "Monitoring scripts created. Start manually when ready."
}

# SELinux configuration (for RHEL-based systems)
configure_selinux() {
    if [ -f /etc/selinux/config ]; then
        log_info "Configuring SELinux..."
        
        # Set to enforcing
        if ! grep -q "^SELINUX=enforcing" /etc/selinux/config; then
            sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
            log_warn "SELinux set to enforcing - reboot required for full effect"
        fi
        
        # Set proper contexts for web content
        if [ -d /var/www/html ]; then
            chcon -R -t httpd_sys_content_t /var/www/html 2>/dev/null
            log_info "Set SELinux contexts for web content"
        fi
        
        log_success "SELinux configured"
    fi
}

# File integrity monitoring prep
setup_file_integrity() {
    log_info "Preparing file integrity monitoring..."
    
    # Create baseline of critical files
    cat > "$SCRIPT_DIR/linux/create_file_baseline.sh" <<'EOFBASE'
#!/bin/bash
# Create baseline of critical system files

BASELINE_DIR="/ccdc/baselines/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BASELINE_DIR"

echo "Creating file integrity baseline..."

# Hash critical directories
find /etc -type f -exec md5sum {} \; > "$BASELINE_DIR/etc_hashes.txt" 2>/dev/null
find /bin -type f -exec md5sum {} \; > "$BASELINE_DIR/bin_hashes.txt" 2>/dev/null
find /sbin -type f -exec md5sum {} \; > "$BASELINE_DIR/sbin_hashes.txt" 2>/dev/null
find /usr/bin -type f -exec md5sum {} \; > "$BASELINE_DIR/usr_bin_hashes.txt" 2>/dev/null
find /usr/sbin -type f -exec md5sum {} \; > "$BASELINE_DIR/usr_sbin_hashes.txt" 2>/dev/null

if [ -d /var/www/html ]; then
    find /var/www/html -type f -exec md5sum {} \; > "$BASELINE_DIR/web_hashes.txt" 2>/dev/null
fi

echo "Baseline created at: $BASELINE_DIR"
ln -sf "$BASELINE_DIR" /ccdc/baselines/latest
EOFBASE
    
    chmod +x "$SCRIPT_DIR/linux/create_file_baseline.sh"
    
    # Create check script
    cat > "$SCRIPT_DIR/linux/check_file_integrity.sh" <<'EOFCHECK'
#!/bin/bash
# Check files against baseline

BASELINE="/ccdc/baselines/latest"
REPORT_FILE="/ccdc/logs/integrity_check_$(date +%Y%m%d_%H%M%S).txt"

if [ ! -d "$BASELINE" ]; then
    echo "ERROR: No baseline found. Run create_file_baseline.sh first."
    exit 1
fi

echo "=== File Integrity Check ===" | tee "$REPORT_FILE"
echo "Date: $(date)" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

for hashfile in "$BASELINE"/*_hashes.txt; do
    echo "Checking $(basename $hashfile)..." | tee -a "$REPORT_FILE"
    md5sum -c "$hashfile" 2>/dev/null | grep -v "OK$" | tee -a "$REPORT_FILE"
done

echo "" | tee -a "$REPORT_FILE"
echo "Report saved to: $REPORT_FILE" | tee -a "$REPORT_FILE"
EOFCHECK
    
    chmod +x "$SCRIPT_DIR/linux/check_file_integrity.sh"
    
    # Create initial baseline
    bash "$SCRIPT_DIR/linux/create_file_baseline.sh"
    
    log_success "File integrity monitoring prepared"
}

# SSH hardening
harden_ssh() {
    if [ -f /etc/ssh/sshd_config ]; then
        log_info "Hardening SSH configuration..."
        
        # Backup original config
        cp /etc/ssh/sshd_config "$BACKUP_DIR/original/sshd_config.$(date +%s)"
        
        # Apply hardening
        sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
        sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
        sed -i 's/#PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
        sed -i 's/#MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
        sed -i 's/#ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
        sed -i 's/#ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
        sed -i 's/#LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config
        
        # Disable X11 forwarding
        sed -i 's/#X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
        
        # Add banner
        echo "UNAUTHORIZED ACCESS PROHIBITED" > /etc/issue.net
        sed -i 's/#Banner.*/Banner \/etc\/issue.net/' /etc/ssh/sshd_config
        
        # Test configuration
        if sshd -t; then
            systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
            log_success "SSH hardened and restarted"
        else
            log_error "SSH configuration test failed - not restarting"
            cp "$BACKUP_DIR/original/sshd_config."* /etc/ssh/sshd_config
        fi
    fi
}

# Create quick reference guide
create_quick_reference() {
    cat > "$CCDC_DIR/QUICK_REFERENCE.txt" <<'EOFREF'
================================================================================
                    CCDC COMPETITION QUICK REFERENCE
================================================================================

CRITICAL REMINDERS:
-------------------
1. Do NOT scan other teams or Red Team (INSTANT DISQUALIFICATION)
2. Do NOT change public IP addresses of services
3. Do NOT change system names or internal IPs (unless inject directs)
4. Maintain ICMP on all devices (except Palo Alto core port)
5. Allow White/Black/Green Team access when requested
6. Services must remain functional for scoring

SCORED SERVICES:
----------------
- HTTP/HTTPS: Must serve correct web content
- SMTP: Email sending and receiving
- POP3: Email retrieval  
- DNS: Must resolve lookups correctly

Check service status: Log into NISE portal (ccdcadmin1.morainevalley.edu)

IMPORTANT DIRECTORIES:
----------------------
/ccdc                   - Main directory
/ccdc/logs              - All logs and audits
/ccdc/scripts/linux     - Hardening and management scripts
/ccdc/scripts/incident_response - IR tools
/ccdc/backups           - System backups

KEY SCRIPTS:
------------
Backup System:
  /ccdc/scripts/linux/backup_critical.sh

User Management:
  /ccdc/scripts/linux/lock_users_interactive.sh
  /ccdc/scripts/linux/user_audit.sh

Security Auditing:
  /ccdc/logs/cron_audit.txt            - Review all cron jobs
  /ccdc/logs/suspicious_bash_*.txt     - Suspicious shell configs
  /ccdc/logs/user_audit_initial.txt    - Initial user inventory

Incident Response:
  /ccdc/scripts/incident_response/quick_investigate.sh
  /ccdc/scripts/incident_response/IR_TEMPLATE.txt

File Integrity:
  /ccdc/scripts/linux/create_file_baseline.sh
  /ccdc/scripts/linux/check_file_integrity.sh

Monitoring:
  /ccdc/scripts/linux/monitor_connections.sh

LOG FILES TO MONITOR:
---------------------
/ccdc/logs/ccdc-hardening.log    - This hardening script log
/ccdc/logs/network_monitor.log   - Connection monitoring
/ccdc/logs/network_alerts.log    - Suspicious connection alerts
/var/log/auth.log                - Authentication attempts (Ubuntu/Debian)
/var/log/secure                  - Authentication attempts (RHEL/CentOS)
/var/log/syslog                  - System messages

COMMON COMMANDS:
----------------
Check running services:
  systemctl list-units --type=service --state=running

Check network connections:
  netstat -tunap | grep ESTABLISHED
  ss -tunap

Check recent file modifications:
  find /etc /var/www -type f -mmin -60

Check logged in users:
  w
  last | head -20

Check cron jobs:
  crontab -l
  ls -la /etc/cron*

Review suspicious processes:
  ps aux | grep -E '(nc|ncat|bash -i|perl|python)'

INCIDENT RESPONSE PROCESS:
--------------------------
1. Detect anomaly (monitoring, alerts, service checks)
2. Run: /ccdc/scripts/incident_response/quick_investigate.sh
3. Document using IR_TEMPLATE.txt
4. Take remediation action (close backdoors, change passwords, etc.)
5. Submit incident report via NISE portal
6. Create backup: /ccdc/scripts/linux/backup_critical.sh

RED TEAM COMMON TACTICS:
------------------------
- Backdoor accounts (check /etc/passwd)
- Cron job persistence (check all cron locations)
- Bash profile persistence (PROMPT_COMMAND, traps)
- Reverse shells (check connections on ports 4444, 31337, etc.)
- Web shells (check web directories for suspicious .php files)
- SSH key persistence (check ~/.ssh/authorized_keys)
- Service hijacking (check service configs)

Submit IR reports for EXPLOITATION events, not misconfigurations.

PASSWORDS:
----------
Track all password changes in a secure document
Admin passwords can be changed without notification
User passwords may need to be tracked for scoring

================================================================================
                        GOOD LUCK!
================================================================================
EOFREF
    
    log_success "Quick reference guide created: $CCDC_DIR/QUICK_REFERENCE.txt"
}

# Main execution function
main() {
    clear
    echo "================================================================================"
    echo "           CCDC Competition System Hardening Script"
    echo "           2026 Midwest CCDC Qualifier"
    echo "================================================================================"
    echo ""
    
    log_info "Starting CCDC hardening process..."
    log_info "This script will prepare your system for competition"
    log_info "Review all output carefully and make decisions based on your environment"
    echo ""
    
    # Confirmation
    echo -n "This script will modify system configuration. Continue? [y/N]: "
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo "Aborted by user"
        exit 0
    fi
    
    echo ""
    log_info "=== Phase 1: System Initialization ==="
    initialize_directories
    detect_os
    
    echo ""
    log_info "=== Phase 2: Threat Detection ==="
    check_malicious_bash
    
    echo ""
    log_info "=== Phase 3: System Hardening ==="
    configure_network
    harden_kernel
    harden_passwords
    harden_ssh
    configure_selinux
    
    echo ""
    log_info "=== Phase 4: User and Service Management ==="
    manage_users
    secure_cron
    manage_services
    
    echo ""
    log_info "=== Phase 5: Backup and Monitoring ==="
    create_backup_system
    setup_monitoring
    setup_file_integrity
    
    echo ""
    log_info "=== Phase 6: Incident Response Preparation ==="
    setup_incident_response
    
    echo ""
    log_info "=== Phase 7: Documentation ==="
    create_quick_reference
    
    echo ""
    echo "================================================================================"
    log_success "CCDC Hardening Complete!"
    echo "================================================================================"
    echo ""
    echo "IMPORTANT NEXT STEPS:"
    echo "1. Review: $CCDC_DIR/QUICK_REFERENCE.txt"
    echo "2. Review: $CCDC_DIR/logs/cron_audit.txt for suspicious cron jobs"
    echo "3. Review: $CCDC_DIR/logs/suspicious_bash_*.txt for backdoors"
    echo "4. Run: $SCRIPT_DIR/linux/lock_users_interactive.sh to lock unnecessary users"
    echo "5. Review: $CCDC_DIR/logs/services_running.txt for unnecessary services"
    echo "6. Start: $SCRIPT_DIR/linux/monitor_connections.sh for network monitoring"
    echo ""
    echo "CRITICAL REMINDERS:"
    echo "- Do NOT scan other teams (instant disqualification)"
    echo "- Do NOT modify public IPs or move services"
    echo "- Maintain scored services: HTTP/HTTPS, SMTP, POP3, DNS"
    echo "- Monitor NISE portal for injects and announcements"
    echo ""
    echo "Log file: $LOGFILE"
    echo "================================================================================"
}

# Run main function
main

exit 0
