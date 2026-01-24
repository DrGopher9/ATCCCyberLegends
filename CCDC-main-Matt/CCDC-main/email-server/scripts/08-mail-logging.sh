#!/bin/bash
###############################################################################
# 08-mail-logging.sh - Mail Server Logging and Monitoring
# Target: Linux Mail Server (Postfix + Dovecot)
# Purpose: Enable comprehensive logging and create monitoring tools
###############################################################################

set -euo pipefail

LOGDIR="/root/ccdc-logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p "$LOGDIR"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOGDIR/mail_logging_setup_$TIMESTAMP.log"
}

log "Starting mail logging configuration..."

echo ""
echo "============================================"
echo "MAIL SERVER LOGGING SETUP"
echo "============================================"

# 1. Ensure rsyslog is running
echo ""
echo "=== System Logging (rsyslog) ==="
if systemctl is-active --quiet rsyslog 2>/dev/null; then
    log "rsyslog is running"
else
    log "Starting rsyslog..."
    systemctl enable rsyslog 2>/dev/null || true
    systemctl start rsyslog 2>/dev/null || true
fi

# 2. Configure mail logging
echo ""
echo "=== Mail Log Configuration ==="

# Check current mail log location
MAIL_LOG="/var/log/mail.log"
if [ ! -f "$MAIL_LOG" ]; then
    MAIL_LOG="/var/log/maillog"
fi

if [ -f "$MAIL_LOG" ]; then
    log "Mail log found at: $MAIL_LOG"
else
    log "Mail log not found, checking journald..."
    MAIL_LOG="journald"
fi

# 3. Enable auditd
echo ""
echo "=== Audit Daemon ==="
if command -v auditd &> /dev/null; then
    if ! systemctl is-active --quiet auditd 2>/dev/null; then
        log "Starting auditd..."
        systemctl enable auditd 2>/dev/null || true
        systemctl start auditd 2>/dev/null || true
    fi
    log "auditd is available"

    read -p "Add audit rules for mail configuration changes? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Adding audit rules..."
        # Watch Postfix config
        auditctl -w /etc/postfix/main.cf -p wa -k postfix_config 2>/dev/null || true
        auditctl -w /etc/postfix/master.cf -p wa -k postfix_config 2>/dev/null || true
        # Watch Dovecot config
        auditctl -w /etc/dovecot/dovecot.conf -p wa -k dovecot_config 2>/dev/null || true
        auditctl -w /etc/dovecot/conf.d -p wa -k dovecot_config 2>/dev/null || true
        # Watch aliases
        auditctl -w /etc/aliases -p wa -k mail_aliases 2>/dev/null || true
        # Watch system files
        auditctl -w /etc/passwd -p wa -k passwd_changes 2>/dev/null || true
        auditctl -w /etc/shadow -p wa -k shadow_changes 2>/dev/null || true
        log "Audit rules added"
    fi
else
    log "auditd not installed"
    read -p "Install auditd? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        apt-get install -y auditd audispd-plugins 2>/dev/null || yum install -y audit 2>/dev/null || dnf install -y audit 2>/dev/null
    fi
fi

# 4. Configure fail2ban
echo ""
echo "=== Fail2ban (Brute Force Protection) ==="
if command -v fail2ban-client &> /dev/null; then
    log "fail2ban is installed"
else
    read -p "Install fail2ban? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        apt-get update && apt-get install -y fail2ban 2>/dev/null || \
        yum install -y epel-release && yum install -y fail2ban 2>/dev/null || \
        dnf install -y fail2ban 2>/dev/null
        log "fail2ban installed"
    fi
fi

if command -v fail2ban-client &> /dev/null; then
    read -p "Configure fail2ban for mail services? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 600
findtime = 600
maxretry = 5
backend = auto

[sshd]
enabled = true
port = ssh
maxretry = 3

[postfix]
enabled = true
port = smtp,465,submission
filter = postfix
logpath = /var/log/mail.log
maxretry = 5

[postfix-sasl]
enabled = true
port = smtp,465,submission,imap,imaps
filter = postfix-sasl
logpath = /var/log/mail.log
maxretry = 3

[dovecot]
enabled = true
port = imap,imaps,pop3,pop3s
filter = dovecot
logpath = /var/log/mail.log
maxretry = 3
EOF
        # Adjust log path if using maillog
        if [ -f "/var/log/maillog" ]; then
            sed -i 's|/var/log/mail.log|/var/log/maillog|g' /etc/fail2ban/jail.local
        fi

        systemctl enable fail2ban 2>/dev/null || true
        systemctl restart fail2ban 2>/dev/null || true
        log "fail2ban configured for mail services"
        fail2ban-client status 2>/dev/null || true
    fi
fi

# 5. Create mail monitoring script
echo ""
echo "=== Creating Mail Monitor Script ==="
cat > "$LOGDIR/mail-monitor.sh" << 'MONITOR_EOF'
#!/bin/bash
# Real-time mail log monitoring for CCDC
# Usage: ./mail-monitor.sh [auth|queue|all|attacks]

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

MAIL_LOG="/var/log/mail.log"
[ -f "/var/log/maillog" ] && MAIL_LOG="/var/log/maillog"

case "${1:-all}" in
    auth)
        echo "=== Mail Authentication Logs ==="
        tail -f "$MAIL_LOG" 2>/dev/null | while read line; do
            if echo "$line" | grep -qiE "(auth.*fail|login.*fail|authentication failed)"; then
                echo -e "${RED}$line${NC}"
            elif echo "$line" | grep -qiE "(logged in|auth.*ok|sasl.*login)"; then
                echo -e "${GREEN}$line${NC}"
            else
                echo "$line"
            fi
        done || journalctl -u postfix -u dovecot -f
        ;;
    queue)
        echo "=== Mail Queue Monitor ==="
        watch -n 5 'echo "=== Queue Status ===" && mailq | tail -20 && echo "" && echo "=== Queue Count ===" && mailq | grep -c "^[A-F0-9]" 2>/dev/null || echo "0"'
        ;;
    attacks)
        echo "=== Potential Attack Detection ==="
        tail -f "$MAIL_LOG" 2>/dev/null | while read line; do
            if echo "$line" | grep -qiE "(reject|blocked|denied|warning|error|too many|rate limit)"; then
                echo -e "${RED}[ALERT] $line${NC}"
            fi
        done || journalctl -u postfix -u dovecot -f | grep -iE "(reject|blocked|denied)"
        ;;
    all|*)
        echo "=== All Mail Logs ==="
        tail -f "$MAIL_LOG" /var/log/dovecot.log 2>/dev/null || journalctl -u postfix -u dovecot -f
        ;;
esac
MONITOR_EOF
chmod +x "$LOGDIR/mail-monitor.sh"
log "Mail monitor script created: $LOGDIR/mail-monitor.sh"

# 6. Create mail threat detection script
echo ""
echo "=== Creating Mail Threat Detection Script ==="
cat > "$LOGDIR/mail-detect.sh" << 'DETECT_EOF'
#!/bin/bash
# Mail server threat detection for CCDC

MAIL_LOG="/var/log/mail.log"
[ -f "/var/log/maillog" ] && MAIL_LOG="/var/log/maillog"

echo "============================================"
echo "MAIL SERVER THREAT DETECTION REPORT"
echo "Time: $(date)"
echo "============================================"

echo ""
echo "=== POSTFIX STATUS ==="
systemctl status postfix --no-pager 2>/dev/null | head -5 || echo "Cannot check postfix status"

echo ""
echo "=== DOVECOT STATUS ==="
systemctl status dovecot --no-pager 2>/dev/null | head -5 || echo "Cannot check dovecot status"

echo ""
echo "=== MAIL QUEUE ==="
echo "Queue size: $(mailq 2>/dev/null | grep -c "^[A-F0-9]" || echo "unknown") messages"
mailq 2>/dev/null | tail -10 || echo "Cannot check queue"

echo ""
echo "=== FAILED AUTHENTICATION (last 24h) ==="
grep -iE "(auth.*fail|login.*fail|authentication failed)" "$MAIL_LOG" 2>/dev/null | tail -20 || echo "No recent failures in log"

echo ""
echo "=== TOP ATTACKING IPs (auth failures) ==="
grep -iE "(auth.*fail|login.*fail|authentication failed)" "$MAIL_LOG" 2>/dev/null | \
    grep -oE "\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b" | \
    sort | uniq -c | sort -rn | head -10 || echo "None found"

echo ""
echo "=== REJECTED CONNECTIONS ==="
grep -i "reject" "$MAIL_LOG" 2>/dev/null | tail -10 || echo "No rejections in log"

echo ""
echo "=== RELAY ATTEMPTS ==="
grep -iE "(relay access denied|relay not permitted)" "$MAIL_LOG" 2>/dev/null | tail -10 || echo "No relay attempts"

echo ""
echo "=== SUSPICIOUS SENDERS ==="
grep -iE "(reject.*from|blocked.*sender)" "$MAIL_LOG" 2>/dev/null | tail -10 || echo "None found"

echo ""
echo "=== OPEN RELAY CHECK ==="
MYNETWORKS=$(postconf -h mynetworks 2>/dev/null || echo "unknown")
echo "mynetworks: $MYNETWORKS"
if echo "$MYNETWORKS" | grep -qE "0\.0\.0\.0/0"; then
    echo "[CRITICAL] Possible open relay configuration!"
fi

echo ""
echo "=== RECENT CONFIG CHANGES ==="
find /etc/postfix /etc/dovecot -mmin -60 -type f 2>/dev/null || echo "No recent changes"

echo ""
echo "=== FAIL2BAN STATUS ==="
if command -v fail2ban-client &> /dev/null; then
    fail2ban-client status 2>/dev/null || echo "fail2ban not running"
    echo ""
    echo "Banned IPs (postfix-sasl):"
    fail2ban-client status postfix-sasl 2>/dev/null | grep "Banned IP" || echo "None"
    echo "Banned IPs (dovecot):"
    fail2ban-client status dovecot 2>/dev/null | grep "Banned IP" || echo "None"
else
    echo "fail2ban not installed"
fi

echo ""
echo "=== CURRENT CONNECTIONS ==="
ss -tnp 2>/dev/null | grep -E ":(25|110|143|465|587|993|995)\s" | head -20 || echo "Cannot check connections"

echo ""
echo "============================================"
echo "Detection complete. Review above for anomalies."
echo "============================================"
DETECT_EOF
chmod +x "$LOGDIR/mail-detect.sh"
log "Threat detection script created: $LOGDIR/mail-detect.sh"

# 7. Create mail statistics script
echo ""
echo "=== Creating Mail Statistics Script ==="
cat > "$LOGDIR/mail-stats.sh" << 'STATS_EOF'
#!/bin/bash
# Mail server statistics for CCDC

MAIL_LOG="/var/log/mail.log"
[ -f "/var/log/maillog" ] && MAIL_LOG="/var/log/maillog"

echo "============================================"
echo "MAIL SERVER STATISTICS"
echo "Time: $(date)"
echo "Log: $MAIL_LOG"
echo "============================================"

echo ""
echo "=== MESSAGE COUNTS (today) ==="
TODAY=$(date +%b\ %d)
echo "Sent: $(grep "$TODAY" "$MAIL_LOG" 2>/dev/null | grep -c "status=sent" || echo "0")"
echo "Bounced: $(grep "$TODAY" "$MAIL_LOG" 2>/dev/null | grep -c "status=bounced" || echo "0")"
echo "Deferred: $(grep "$TODAY" "$MAIL_LOG" 2>/dev/null | grep -c "status=deferred" || echo "0")"
echo "Rejected: $(grep "$TODAY" "$MAIL_LOG" 2>/dev/null | grep -c "NOQUEUE.*reject" || echo "0")"

echo ""
echo "=== TOP SENDERS (today) ==="
grep "$TODAY" "$MAIL_LOG" 2>/dev/null | grep "from=" | grep -oP "from=<[^>]+>" | sort | uniq -c | sort -rn | head -10 || echo "Cannot parse senders"

echo ""
echo "=== TOP RECIPIENTS (today) ==="
grep "$TODAY" "$MAIL_LOG" 2>/dev/null | grep "to=" | grep -oP "to=<[^>]+>" | sort | uniq -c | sort -rn | head -10 || echo "Cannot parse recipients"

echo ""
echo "=== DOVECOT LOGINS (today) ==="
grep "$TODAY" /var/log/dovecot.log 2>/dev/null | grep -c "Login:" || \
grep "$TODAY" "$MAIL_LOG" 2>/dev/null | grep -c "dovecot.*Login" || echo "0"

echo ""
echo "=== HOURLY MESSAGE DISTRIBUTION ==="
for hour in $(seq -w 0 23); do
    COUNT=$(grep "$TODAY" "$MAIL_LOG" 2>/dev/null | grep -c "^.*$TODAY $hour:" || echo "0")
    printf "Hour %s: %5d messages\n" "$hour" "$COUNT"
done 2>/dev/null | grep -v ": *0 messages" || echo "Cannot calculate distribution"
STATS_EOF
chmod +x "$LOGDIR/mail-stats.sh"
log "Statistics script created: $LOGDIR/mail-stats.sh"

# 8. Display log locations
echo ""
echo "============================================"
echo "KEY MAIL LOG LOCATIONS"
echo "============================================"
echo ""
echo "Mail logs:"
echo "  /var/log/mail.log       - Debian/Ubuntu mail log"
echo "  /var/log/maillog        - RHEL/CentOS mail log"
echo "  /var/log/dovecot.log    - Dovecot log"
echo ""
echo "System logs:"
echo "  /var/log/auth.log       - Authentication (Debian)"
echo "  /var/log/secure         - Authentication (RHEL)"
echo ""
echo "Security logs:"
echo "  /var/log/fail2ban.log   - Fail2ban log"
echo "  /var/log/audit/         - Audit logs"
echo ""

echo "============================================"
echo "MONITORING SCRIPTS CREATED"
echo "============================================"
echo ""
echo "  $LOGDIR/mail-monitor.sh  - Real-time log monitoring"
echo "    Usage: ./mail-monitor.sh [auth|queue|attacks|all]"
echo ""
echo "  $LOGDIR/mail-detect.sh   - Threat detection"
echo "    Usage: ./mail-detect.sh"
echo ""
echo "  $LOGDIR/mail-stats.sh    - Mail statistics"
echo "    Usage: ./mail-stats.sh"
echo ""

log "Mail logging setup complete"
