#!/bin/bash
###############################################################################
# 08-logging-setup.sh - Logging and Monitoring Setup
# Target: Ubuntu 24 E-Commerce Server
# Purpose: Enable comprehensive logging for incident detection/response
###############################################################################

set -euo pipefail

LOGDIR="/root/ccdc-logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p "$LOGDIR"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOGDIR/logging_setup_$TIMESTAMP.log"
}

log "Starting logging configuration..."

echo ""
echo "============================================"
echo "LOGGING AND MONITORING SETUP"
echo "============================================"

# 1. Ensure rsyslog is running
echo ""
echo "--- System Logging (rsyslog) ---"
if systemctl is-active --quiet rsyslog; then
    log "rsyslog is running"
else
    log "Starting rsyslog..."
    systemctl enable rsyslog 2>/dev/null || true
    systemctl start rsyslog 2>/dev/null || true
fi

# 2. Enable auditd if available
echo ""
echo "--- Audit Daemon ---"
if command -v auditd &> /dev/null; then
    if ! systemctl is-active --quiet auditd; then
        log "Starting auditd..."
        systemctl enable auditd 2>/dev/null || true
        systemctl start auditd 2>/dev/null || true
    fi
    log "auditd is available"

    read -p "Add audit rules for suspicious activity? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Adding audit rules..."

        # Watch critical files
        auditctl -w /etc/passwd -p wa -k passwd_changes 2>/dev/null || true
        auditctl -w /etc/shadow -p wa -k shadow_changes 2>/dev/null || true
        auditctl -w /etc/sudoers -p wa -k sudoers_changes 2>/dev/null || true
        auditctl -w /etc/ssh/sshd_config -p wa -k sshd_changes 2>/dev/null || true

        # Watch for privilege escalation
        auditctl -w /usr/bin/sudo -p x -k sudo_usage 2>/dev/null || true
        auditctl -w /usr/bin/su -p x -k su_usage 2>/dev/null || true

        # Watch cron
        auditctl -w /etc/crontab -p wa -k cron_changes 2>/dev/null || true
        auditctl -w /etc/cron.d -p wa -k cron_changes 2>/dev/null || true

        log "Audit rules added"
        echo "View audit logs: ausearch -k passwd_changes"
    fi
else
    log "auditd not installed. Installing..."
    apt-get install -y auditd audispd-plugins 2>/dev/null || true
fi

# 3. Configure fail2ban
echo ""
echo "--- Fail2ban (Brute Force Protection) ---"
if command -v fail2ban-client &> /dev/null; then
    log "fail2ban is installed"
else
    read -p "Install fail2ban? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        apt-get update && apt-get install -y fail2ban
        log "fail2ban installed"
    fi
fi

if command -v fail2ban-client &> /dev/null; then
    read -p "Configure fail2ban for SSH and web? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/*error.log
maxretry = 5

[apache-badbots]
enabled = true
port = http,https
filter = apache-badbots
logpath = /var/log/apache2/*access.log
maxretry = 2
EOF
        systemctl enable fail2ban 2>/dev/null || true
        systemctl restart fail2ban 2>/dev/null || true
        log "fail2ban configured and started"
    fi
fi

# 4. Create log monitoring script
echo ""
echo "--- Creating Log Monitor Script ---"
cat > "$LOGDIR/monitor.sh" << 'MONITOR_EOF'
#!/bin/bash
# Quick log monitoring for CCDC
# Usage: ./monitor.sh [auth|web|mysql|all]

RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

case "${1:-all}" in
    auth)
        echo "=== Authentication Logs ==="
        tail -f /var/log/auth.log 2>/dev/null | while read line; do
            if echo "$line" | grep -q "Failed"; then
                echo -e "${RED}$line${NC}"
            elif echo "$line" | grep -q "Accepted"; then
                echo -e "${YELLOW}$line${NC}"
            else
                echo "$line"
            fi
        done
        ;;
    web)
        echo "=== Web Server Logs ==="
        tail -f /var/log/apache2/access.log /var/log/apache2/error.log /var/log/nginx/access.log /var/log/nginx/error.log 2>/dev/null
        ;;
    mysql)
        echo "=== MySQL Logs ==="
        tail -f /var/log/mysql/error.log /var/log/mysql/general.log 2>/dev/null
        ;;
    all)
        echo "=== All Critical Logs ==="
        tail -f /var/log/auth.log /var/log/syslog /var/log/apache2/error.log 2>/dev/null
        ;;
    *)
        echo "Usage: $0 [auth|web|mysql|all]"
        ;;
esac
MONITOR_EOF
chmod +x "$LOGDIR/monitor.sh"
log "Monitor script created: $LOGDIR/monitor.sh"

# 5. Create suspicious activity detector
echo ""
echo "--- Creating Threat Detection Script ---"
cat > "$LOGDIR/detect.sh" << 'DETECT_EOF'
#!/bin/bash
# Quick threat detection for CCDC
# Run periodically or after suspected incident

echo "============================================"
echo "CCDC THREAT DETECTION REPORT"
echo "Time: $(date)"
echo "============================================"

echo ""
echo "=== FAILED SSH LOGINS (last 100) ==="
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20 || echo "None found"

echo ""
echo "=== SUCCESSFUL SSH LOGINS ==="
grep "Accepted" /var/log/auth.log 2>/dev/null | tail -10 || echo "None found"

echo ""
echo "=== SUDO USAGE ==="
grep "sudo:" /var/log/auth.log 2>/dev/null | tail -10 || echo "None found"

echo ""
echo "=== CURRENT LOGGED IN USERS ==="
who 2>/dev/null || true

echo ""
echo "=== RECENT USER ADDITIONS ==="
grep "useradd\|adduser" /var/log/auth.log 2>/dev/null | tail -5 || echo "None found"

echo ""
echo "=== SUSPICIOUS WEB REQUESTS ==="
grep -E "(\.\.\/|<script|SELECT.*FROM|UNION.*SELECT|cmd=|exec\(|system\()" /var/log/apache2/access.log 2>/dev/null | tail -10 || echo "None found"
grep -E "(\.\.\/|<script|SELECT.*FROM|UNION.*SELECT|cmd=|exec\(|system\()" /var/log/nginx/access.log 2>/dev/null | tail -10 || true

echo ""
echo "=== 404 ERRORS (potential scanning) ==="
grep " 404 " /var/log/apache2/access.log 2>/dev/null | tail -10 || echo "None found"

echo ""
echo "=== RECENTLY MODIFIED FILES IN /etc ==="
find /etc -mmin -30 -type f 2>/dev/null | head -20 || echo "None found"

echo ""
echo "=== NEW SUID FILES ==="
find / -perm -4000 -mmin -60 -type f 2>/dev/null || echo "None found"

echo ""
echo "=== LISTENING PORTS ==="
ss -tlnp 2>/dev/null | grep LISTEN || netstat -tlnp 2>/dev/null | grep LISTEN || true

echo ""
echo "=== OUTBOUND CONNECTIONS ==="
ss -tnp 2>/dev/null | grep ESTAB | grep -v "127.0.0.1" || netstat -tnp 2>/dev/null | grep ESTABLISHED | grep -v "127.0.0.1" || true

echo ""
echo "=== SUSPICIOUS PROCESSES ==="
ps aux | grep -E "(nc |ncat|netcat|/tmp/|perl -e|python -c|bash -i)" | grep -v grep || echo "None found"

echo ""
echo "=== CRON JOBS (non-system) ==="
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -l -u "$user" 2>/dev/null && echo "^^^ $user ^^^"
done

echo ""
echo "============================================"
echo "Detection complete. Review above for anomalies."
echo "============================================"
DETECT_EOF
chmod +x "$LOGDIR/detect.sh"
log "Threat detection script created: $LOGDIR/detect.sh"

# 6. Web access log analysis
echo ""
echo "--- Creating Web Log Analyzer ---"
cat > "$LOGDIR/web-analyze.sh" << 'WEBLOG_EOF'
#!/bin/bash
# Web log analysis for CCDC

ACCESS_LOG="${1:-/var/log/apache2/access.log}"

if [ ! -f "$ACCESS_LOG" ]; then
    echo "Usage: $0 [access.log path]"
    exit 1
fi

echo "============================================"
echo "WEB ACCESS LOG ANALYSIS"
echo "Log: $ACCESS_LOG"
echo "============================================"

echo ""
echo "=== TOP 10 IPs BY REQUESTS ==="
awk '{print $1}' "$ACCESS_LOG" | sort | uniq -c | sort -rn | head -10

echo ""
echo "=== TOP 10 REQUESTED URLS ==="
awk '{print $7}' "$ACCESS_LOG" | sort | uniq -c | sort -rn | head -10

echo ""
echo "=== HTTP STATUS CODE DISTRIBUTION ==="
awk '{print $9}' "$ACCESS_LOG" | sort | uniq -c | sort -rn

echo ""
echo "=== TOP 10 USER AGENTS ==="
awk -F'"' '{print $6}' "$ACCESS_LOG" | sort | uniq -c | sort -rn | head -10

echo ""
echo "=== POTENTIAL ATTACK PATTERNS ==="
echo "SQL Injection attempts:"
grep -iE "(union|select|from|where|drop|insert|update|delete|--|;)" "$ACCESS_LOG" | wc -l
echo "Path traversal attempts:"
grep -E "(\.\.\/|\.\.\\\\)" "$ACCESS_LOG" | wc -l
echo "XSS attempts:"
grep -iE "(<script|javascript:|onerror=|onload=)" "$ACCESS_LOG" | wc -l
echo "Command injection attempts:"
grep -iE "(;|&&|\|\||cmd=|exec|system|passthru)" "$ACCESS_LOG" | wc -l

echo ""
echo "=== REQUESTS TO ADMIN AREAS ==="
grep -iE "(admin|administrator|wp-admin|phpmyadmin)" "$ACCESS_LOG" | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
WEBLOG_EOF
chmod +x "$LOGDIR/web-analyze.sh"
log "Web analyzer script created: $LOGDIR/web-analyze.sh"

# 7. Display log locations
echo ""
echo "============================================"
echo "KEY LOG LOCATIONS"
echo "============================================"
echo ""
echo "System logs:"
echo "  /var/log/syslog          - General system log"
echo "  /var/log/auth.log        - Authentication log"
echo "  /var/log/kern.log        - Kernel log"
echo ""
echo "Web server logs:"
echo "  /var/log/apache2/        - Apache logs"
echo "  /var/log/nginx/          - Nginx logs"
echo ""
echo "Database logs:"
echo "  /var/log/mysql/          - MySQL logs"
echo ""
echo "Security logs:"
echo "  /var/log/fail2ban.log    - Fail2ban log"
echo "  /var/log/audit/          - Audit logs"
echo ""

echo "============================================"
echo "MONITORING SCRIPTS CREATED"
echo "============================================"
echo ""
echo "  $LOGDIR/monitor.sh       - Real-time log monitoring"
echo "    Usage: ./monitor.sh [auth|web|mysql|all]"
echo ""
echo "  $LOGDIR/detect.sh        - Quick threat detection"
echo "    Usage: ./detect.sh"
echo ""
echo "  $LOGDIR/web-analyze.sh   - Web log analysis"
echo "    Usage: ./web-analyze.sh [access.log]"
echo ""

log "Logging setup complete"
