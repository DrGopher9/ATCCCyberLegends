#!/bin/bash
#===============================================================================
# CCDC Fedora Webmail/Apps - Logging Configuration Script
# Target: Fedora Server
# Run as: root
#===============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

LOGDIR="/opt/ccdc-logs"
mkdir -p "$LOGDIR"

echo -e "${CYAN}========================================"
echo "  CCDC Fedora Logging Configuration"
echo -e "========================================${NC}"
echo ""

#===============================================================================
echo -e "${YELLOW}[*] Configuring auditd...${NC}"
echo ""

# Install auditd if needed
if ! command -v auditctl &>/dev/null; then
    dnf install -y audit
fi

# Enable and start auditd
systemctl enable auditd
systemctl start auditd

# Add audit rules
cat > /etc/audit/rules.d/ccdc.rules << 'EOF'
# CCDC Audit Rules

# Monitor authentication files
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d -p wa -k sudoers_changes

# Monitor SSH
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /root/.ssh -p wa -k root_ssh

# Monitor cron
-w /etc/crontab -p wa -k cron_changes
-w /etc/cron.d -p wa -k cron_changes
-w /var/spool/cron -p wa -k cron_changes

# Monitor web config
-w /etc/httpd -p wa -k httpd_config
-w /var/www/html -p wa -k webroot_changes

# Monitor privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# Monitor network configuration
-w /etc/hosts -p wa -k hosts_changes
-w /etc/sysconfig/network-scripts -p wa -k network_changes

# Monitor firewall
-w /etc/firewalld -p wa -k firewall_changes
EOF

augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/ccdc.rules
echo -e "${GREEN}    [+] Audit rules installed${NC}"

#===============================================================================
echo ""
echo -e "${YELLOW}[*] Configuring fail2ban...${NC}"
echo ""

# Install fail2ban
if ! command -v fail2ban-client &>/dev/null; then
    dnf install -y fail2ban
fi

# Create fail2ban config
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
banaction = firewallcmd-rich-rules

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/secure
maxretry = 3

[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/httpd/*error_log
maxretry = 5

[apache-badbots]
enabled = true
port = http,https
filter = apache-badbots
logpath = /var/log/httpd/*access_log
maxretry = 2

[roundcube-auth]
enabled = true
port = http,https
filter = roundcube-auth
logpath = /var/www/html/roundcube/logs/errors.log
            /var/www/roundcube/logs/errors.log
            /usr/share/roundcubemail/logs/errors.log
maxretry = 5
EOF

# Create roundcube filter
cat > /etc/fail2ban/filter.d/roundcube-auth.conf << 'EOF'
[Definition]
failregex = IMAP Error.*Login failed for .* from <HOST>
            .*FAILED login for .* from <HOST>
ignoreregex =
EOF

systemctl enable fail2ban
systemctl restart fail2ban
echo -e "${GREEN}    [+] fail2ban configured and started${NC}"

#===============================================================================
echo ""
echo -e "${YELLOW}[*] Configuring Apache logging...${NC}"
echo ""

if [ -d /etc/httpd ]; then
    # Ensure access and error logs are enabled with useful format
    cat > /etc/httpd/conf.d/logging.conf << 'EOF'
# Enhanced logging
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %T" combined_time
CustomLog "logs/access_log" combined_time

# Log SSL info
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{SSL_PROTOCOL}x\" \"%{SSL_CIPHER}x\"" ssl_combined

# Separate security log
CustomLog "logs/security_log" combined env=security
EOF
    echo -e "${GREEN}    [+] Apache logging enhanced${NC}"
fi

#===============================================================================
echo ""
echo -e "${YELLOW}[*] Creating monitoring scripts...${NC}"
echo ""

# Failed login monitor
cat > "$LOGDIR/monitor-failed-logins.sh" << 'SCRIPT'
#!/bin/bash
echo "========================================"
echo "  Failed Login Monitor - $(date)"
echo "========================================"
echo ""

echo "=== SSH Failed Logins (last hour) ==="
grep "Failed password" /var/log/secure 2>/dev/null | \
    awk -v d="$(date -d '1 hour ago' '+%b %d %H')" '$0 >= d' | tail -20
echo ""

echo "=== Failed Login Summary by IP ==="
grep "Failed password" /var/log/secure 2>/dev/null | \
    grep -oP "from \K[\d.]+" | sort | uniq -c | sort -rn | head -10
echo ""

echo "=== Apache Auth Failures ==="
grep -i "authentication failure\|authorization failed" /var/log/httpd/*error_log 2>/dev/null | tail -10
echo ""

echo "=== Fail2ban Status ==="
fail2ban-client status 2>/dev/null
echo ""
SCRIPT
chmod +x "$LOGDIR/monitor-failed-logins.sh"
echo -e "${GREEN}    [+] monitor-failed-logins.sh${NC}"

# Web activity monitor
cat > "$LOGDIR/monitor-web-activity.sh" << 'SCRIPT'
#!/bin/bash
echo "========================================"
echo "  Web Activity Monitor - $(date)"
echo "========================================"
echo ""

echo "=== Top IPs (last hour) ==="
awk -v d="$(date -d '1 hour ago' '+%d/%b/%Y:%H')" '$4 ~ d' /var/log/httpd/access_log 2>/dev/null | \
    awk '{print $1}' | sort | uniq -c | sort -rn | head -10
echo ""

echo "=== 404 Errors ==="
grep '" 404 ' /var/log/httpd/access_log 2>/dev/null | tail -10
echo ""

echo "=== Suspicious Requests ==="
grep -iE "(\.\.\/|%2e%2e|etc/passwd|proc/self|\<script\>|union.*select)" /var/log/httpd/access_log 2>/dev/null | tail -10
echo ""

echo "=== POST Requests ==="
grep "POST" /var/log/httpd/access_log 2>/dev/null | tail -20
echo ""
SCRIPT
chmod +x "$LOGDIR/monitor-web-activity.sh"
echo -e "${GREEN}    [+] monitor-web-activity.sh${NC}"

# System health check
cat > "$LOGDIR/quick-health-check.sh" << 'SCRIPT'
#!/bin/bash
echo "========================================"
echo "  Quick Health Check - $(date)"
echo "========================================"
echo ""

echo "=== Service Status ==="
for svc in httpd mariadb postfix dovecot sshd firewalld fail2ban; do
    status=$(systemctl is-active $svc 2>/dev/null || echo "not installed")
    printf "  %-12s : %s\n" "$svc" "$status"
done
echo ""

echo "=== Disk Usage ==="
df -h / /var 2>/dev/null
echo ""

echo "=== Memory ==="
free -h
echo ""

echo "=== Logged In Users ==="
who
echo ""

echo "=== Recent Authentication ==="
grep "Accepted\|session opened" /var/log/secure 2>/dev/null | tail -5
echo ""

echo "=== Apache Status ==="
curl -s http://localhost/server-status 2>/dev/null | head -20 || echo "  server-status not enabled"
echo ""
SCRIPT
chmod +x "$LOGDIR/quick-health-check.sh"
echo -e "${GREEN}    [+] quick-health-check.sh${NC}"

#===============================================================================
echo ""
echo -e "${GREEN}========================================"
echo "  Logging Configuration Complete"
echo -e "========================================${NC}"
echo ""
echo "Monitoring Scripts:"
echo "  $LOGDIR/monitor-failed-logins.sh"
echo "  $LOGDIR/monitor-web-activity.sh"
echo "  $LOGDIR/quick-health-check.sh"
echo ""
echo -e "${YELLOW}Key Log Files:${NC}"
echo "  /var/log/secure          - SSH/auth"
echo "  /var/log/httpd/          - Apache logs"
echo "  /var/log/audit/audit.log - Audit events"
echo "  /var/log/fail2ban.log    - Banned IPs"
echo ""
