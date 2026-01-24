#!/bin/bash
#===============================================================================
# CCDC Splunk SIEM - Logging and Monitoring Script
# Target: Splunk Enterprise on Linux
# Run as: root
#===============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

LOGDIR="/opt/splunk-ccdc-logs"
mkdir -p "$LOGDIR"

echo -e "${CYAN}========================================"
echo "  CCDC Splunk Logging & Monitoring"
echo -e "========================================${NC}"
echo ""

# Detect Splunk installation
SPLUNK_HOME=""
for path in /opt/splunk /opt/splunkforwarder /usr/local/splunk; do
    if [ -d "$path" ]; then
        SPLUNK_HOME="$path"
        break
    fi
done

if [ -z "$SPLUNK_HOME" ]; then
    echo -e "${RED}[!] Splunk installation not found${NC}"
    read -p "Enter Splunk installation path: " SPLUNK_HOME
fi

SPLUNK_CMD="$SPLUNK_HOME/bin/splunk"

#===============================================================================
# ENABLE SPLUNK INTERNAL LOGGING
#===============================================================================

echo -e "${YELLOW}[*] Configuring Splunk Internal Logging...${NC}"
echo ""

# Enable audit logging
mkdir -p "$SPLUNK_HOME/etc/system/local"

cat >> "$SPLUNK_HOME/etc/system/local/audit.conf" << 'EOF'

[events]
# Log all user activity
search = enabled
acceleration = enabled
admin = enabled
settings = enabled

# Log authentication events
auth = enabled

# Log scheduled search events
scheduler = enabled
EOF

echo -e "${GREEN}    [+] Audit logging enabled${NC}"

# Configure splunkd logging level
cat >> "$SPLUNK_HOME/etc/system/local/log.conf" << 'EOF'

[splunkd]
# Keep logs for 30 days
maxBackupIndex = 30

# Rotate at 25MB
maxFileSize = 25000000
EOF

echo -e "${GREEN}    [+] Log rotation configured${NC}"

#===============================================================================
# ENABLE SYSTEM LOGGING (AUDITD)
#===============================================================================

echo ""
echo -e "${YELLOW}[*] Configuring System Audit Logging...${NC}"
echo ""

if command -v auditctl &>/dev/null; then
    # Install audit rules for Splunk
    cat > /etc/audit/rules.d/splunk.rules << EOF
# CCDC Splunk Audit Rules

# Monitor Splunk config changes
-w $SPLUNK_HOME/etc -p wa -k splunk_config

# Monitor Splunk binary execution
-w $SPLUNK_HOME/bin -p x -k splunk_exec

# Monitor authentication files
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes

# Monitor sudo usage
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d -p wa -k sudoers_changes

# Monitor SSH
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /root/.ssh -p wa -k root_ssh

# Monitor cron
-w /etc/crontab -p wa -k cron_changes
-w /etc/cron.d -p wa -k cron_changes
-w /var/spool/cron -p wa -k cron_changes

# Monitor privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
EOF

    # Load rules
    augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/splunk.rules

    echo -e "${GREEN}    [+] Audit rules installed${NC}"
else
    echo -e "${YELLOW}    [!] auditd not installed - consider installing for enhanced logging${NC}"
fi

#===============================================================================
# CONFIGURE SPLUNK TO INDEX ITS OWN LOGS
#===============================================================================

echo ""
echo -e "${YELLOW}[*] Configuring Splunk Self-Monitoring...${NC}"
echo ""

# Create input for Splunk's own logs
cat >> "$SPLUNK_HOME/etc/system/local/inputs.conf" << EOF

# Splunk internal logs
[monitor://$SPLUNK_HOME/var/log/splunk/splunkd.log]
index = _internal
sourcetype = splunkd

[monitor://$SPLUNK_HOME/var/log/splunk/audit.log]
index = _audit
sourcetype = audittrail

[monitor://$SPLUNK_HOME/var/log/splunk/metrics.log]
index = _internal
sourcetype = splunkd

# Splunk access logs
[monitor://$SPLUNK_HOME/var/log/splunk/splunkd_access.log]
index = _internal
sourcetype = splunkd_access

# Scheduler logs
[monitor://$SPLUNK_HOME/var/log/splunk/scheduler.log]
index = _internal
sourcetype = scheduler
EOF

echo -e "${GREEN}    [+] Splunk self-monitoring configured${NC}"

#===============================================================================
# CONFIGURE LINUX LOG COLLECTION
#===============================================================================

echo ""
echo -e "${YELLOW}[*] Configuring Linux Log Collection...${NC}"
echo ""

read -p "Index local system logs? (y/N): " index_syslog
if [ "$index_syslog" = "y" ]; then
    cat >> "$SPLUNK_HOME/etc/system/local/inputs.conf" << 'EOF'

# System logs
[monitor:///var/log/messages]
index = main
sourcetype = syslog
disabled = false

[monitor:///var/log/secure]
index = main
sourcetype = linux_secure
disabled = false

[monitor:///var/log/auth.log]
index = main
sourcetype = linux_secure
disabled = false

[monitor:///var/log/audit/audit.log]
index = main
sourcetype = linux_audit
disabled = false
EOF

    echo -e "${GREEN}    [+] Linux log collection configured${NC}"
fi

#===============================================================================
# CREATE MONITORING ALERTS
#===============================================================================

echo ""
echo -e "${YELLOW}[*] Creating Monitoring Alerts...${NC}"
echo ""

mkdir -p "$SPLUNK_HOME/etc/apps/ccdc_alerts/local/data/ui/views"
mkdir -p "$SPLUNK_HOME/etc/apps/ccdc_alerts/default"

# Create app.conf
cat > "$SPLUNK_HOME/etc/apps/ccdc_alerts/default/app.conf" << 'EOF'
[install]
state = enabled

[ui]
is_visible = true
label = CCDC Alerts

[launcher]
author = CCDC Blue Team
description = CCDC Security Monitoring Alerts
version = 1.0.0
EOF

# Create saved searches (alerts)
cat > "$SPLUNK_HOME/etc/apps/ccdc_alerts/local/savedsearches.conf" << 'EOF'
# Failed Logins Alert
[CCDC - Multiple Failed Logins]
search = index=_audit action=login_failed | stats count by user, src | where count > 5
cron_schedule = */5 * * * *
enableSched = 1
dispatch.earliest_time = -5m
dispatch.latest_time = now
alert_threshold = 1
alert.severity = 4
alert.track = 1
description = Alert when user has more than 5 failed logins in 5 minutes

# Admin Activity Alert
[CCDC - Admin Activity]
search = index=_audit action=* user=admin OR info=granted | table _time, user, action, info
cron_schedule = */10 * * * *
enableSched = 1
dispatch.earliest_time = -10m
dispatch.latest_time = now
alert.severity = 3
alert.track = 1
description = Track all admin user activity

# New User Created Alert
[CCDC - New User Created]
search = index=_audit action=edit_user info=granted | table _time, user, object, info
cron_schedule = */5 * * * *
enableSched = 1
dispatch.earliest_time = -5m
dispatch.latest_time = now
alert_threshold = 1
alert.severity = 5
alert.track = 1
description = Alert when new Splunk user is created

# Role Change Alert
[CCDC - Role Modified]
search = index=_audit action=edit_roles OR action=edit_user roles=* | table _time, user, action, roles
cron_schedule = */5 * * * *
enableSched = 1
dispatch.earliest_time = -5m
dispatch.latest_time = now
alert_threshold = 1
alert.severity = 5
alert.track = 1
description = Alert when user roles are modified

# Configuration Change Alert
[CCDC - Config Change]
search = index=_audit action=edit_* NOT action=edit_search | table _time, user, action, object
cron_schedule = */15 * * * *
enableSched = 1
dispatch.earliest_time = -15m
dispatch.latest_time = now
alert.severity = 3
alert.track = 1
description = Track configuration changes

# Forwarder Down Alert
[CCDC - Forwarder Missing]
search = | metadata type=hosts index=* | eval age=now()-lastTime | where age > 900 | table host, lastTime, age
cron_schedule = */15 * * * *
enableSched = 1
dispatch.earliest_time = -24h
dispatch.latest_time = now
alert_threshold = 1
alert.severity = 4
alert.track = 1
description = Alert when forwarder stops sending data for 15 minutes

# Suspicious Search Alert
[CCDC - Suspicious Search]
search = index=_audit action=search search="*password*" OR search="*credential*" OR search="*secret*" | table _time, user, search
cron_schedule = */10 * * * *
enableSched = 1
dispatch.earliest_time = -10m
dispatch.latest_time = now
alert.severity = 4
alert.track = 1
description = Alert on searches for sensitive terms
EOF

echo -e "${GREEN}    [+] CCDC alerts app created${NC}"

#===============================================================================
# CREATE MONITORING SCRIPTS
#===============================================================================

echo ""
echo -e "${YELLOW}[*] Creating Monitoring Scripts...${NC}"
echo ""

# Quick health check
cat > "$LOGDIR/splunk-health-check.sh" << 'HEALTHSCRIPT'
#!/bin/bash
# Splunk Quick Health Check

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
SPLUNK_CMD="$SPLUNK_HOME/bin/splunk"

echo "========================================"
echo "  Splunk Health Check - $(date)"
echo "========================================"
echo ""

# Service status
echo "=== Service Status ==="
$SPLUNK_CMD status
echo ""

# License usage
echo "=== License Usage ==="
$SPLUNK_CMD list licenser-pools 2>/dev/null | head -20
echo ""

# Recent errors
echo "=== Recent Errors (last hour) ==="
grep -i "error\|fail\|critical" "$SPLUNK_HOME/var/log/splunk/splunkd.log" 2>/dev/null | tail -10
echo ""

# Disk usage
echo "=== Disk Usage ==="
df -h "$SPLUNK_HOME"
echo ""

# Index sizes
echo "=== Index Sizes ==="
$SPLUNK_CMD list index 2>/dev/null | head -20
echo ""

# Active users
echo "=== Recent Logins (audit log) ==="
grep "action=login" "$SPLUNK_HOME/var/log/splunk/audit.log" 2>/dev/null | tail -10
echo ""

# Network connections
echo "=== Active Connections ==="
ss -tnp 2>/dev/null | grep -E "(splunk|:8000|:8089|:9997)" | head -20
echo ""
HEALTHSCRIPT

chmod +x "$LOGDIR/splunk-health-check.sh"
echo -e "${GREEN}    [+] splunk-health-check.sh${NC}"

# Failed login monitor
cat > "$LOGDIR/monitor-splunk-logins.sh" << 'LOGINSCRIPT'
#!/bin/bash
# Monitor Splunk Failed Logins

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
AUDIT_LOG="$SPLUNK_HOME/var/log/splunk/audit.log"

echo "========================================"
echo "  Splunk Login Monitor - $(date)"
echo "========================================"
echo ""

# Failed logins
echo "=== Failed Logins (last hour) ==="
grep "login_failed" "$AUDIT_LOG" 2>/dev/null | \
    awk -v cutoff=$(date -d '1 hour ago' +%s) '
    {
        if ($0 ~ /timestamp/) {
            print $0
        }
    }' | tail -20
echo ""

# Successful logins
echo "=== Successful Logins (last hour) ==="
grep "action=login info=granted" "$AUDIT_LOG" 2>/dev/null | tail -20
echo ""

# Login summary by user
echo "=== Login Summary ==="
grep "action=login" "$AUDIT_LOG" 2>/dev/null | \
    grep -oP "user=\K[^ ]*" | sort | uniq -c | sort -rn | head -10
echo ""
LOGINSCRIPT

chmod +x "$LOGDIR/monitor-splunk-logins.sh"
echo -e "${GREEN}    [+] monitor-splunk-logins.sh${NC}"

# Configuration change monitor
cat > "$LOGDIR/monitor-config-changes.sh" << 'CONFIGSCRIPT'
#!/bin/bash
# Monitor Splunk Configuration Changes

SPLUNK_HOME="${SPLUNK_HOME:-/opt/splunk}"
AUDIT_LOG="$SPLUNK_HOME/var/log/splunk/audit.log"

echo "========================================"
echo "  Splunk Config Change Monitor"
echo "========================================"
echo ""

# Recent config changes
echo "=== Configuration Changes (last 24 hours) ==="
grep -E "action=edit_|action=create_|action=delete_" "$AUDIT_LOG" 2>/dev/null | \
    tail -50
echo ""

# File changes
echo "=== Recently Modified Config Files ==="
find "$SPLUNK_HOME/etc/system/local" -type f -mmin -1440 -ls 2>/dev/null
echo ""

find "$SPLUNK_HOME/etc/apps" -name "*.conf" -type f -mmin -1440 -ls 2>/dev/null | head -20
echo ""
CONFIGSCRIPT

chmod +x "$LOGDIR/monitor-config-changes.sh"
echo -e "${GREEN}    [+] monitor-config-changes.sh${NC}"

#===============================================================================
# ENABLE FAIL2BAN FOR SPLUNK WEB
#===============================================================================

echo ""
echo -e "${YELLOW}[*] Configuring fail2ban for Splunk...${NC}"
echo ""

if command -v fail2ban-client &>/dev/null; then
    read -p "Configure fail2ban for Splunk Web? (y/N): " config_f2b
    if [ "$config_f2b" = "y" ]; then
        # Create Splunk filter
        cat > /etc/fail2ban/filter.d/splunk.conf << 'EOF'
[Definition]
failregex = ^.*action=login_failed.*src=<HOST>.*$
            ^.*Failed login attempt.*remote_ip=<HOST>.*$
ignoreregex =
EOF

        # Create Splunk jail
        cat >> /etc/fail2ban/jail.local << EOF

[splunk]
enabled = true
port = 8000,8089
filter = splunk
logpath = $SPLUNK_HOME/var/log/splunk/audit.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

        systemctl restart fail2ban 2>/dev/null || service fail2ban restart 2>/dev/null
        echo -e "${GREEN}    [+] fail2ban configured for Splunk${NC}"
    fi
else
    echo "    fail2ban not installed - consider installing for brute-force protection"
fi

#===============================================================================
# RESTART SPLUNK TO APPLY CHANGES
#===============================================================================

echo ""
read -p "Restart Splunk to apply logging changes? (y/N): " restart_splunk
if [ "$restart_splunk" = "y" ]; then
    $SPLUNK_CMD restart 2>/dev/null
    echo -e "${GREEN}    [+] Splunk restarted${NC}"
fi

#===============================================================================
echo ""
echo -e "${GREEN}========================================"
echo "  Logging Configuration Complete"
echo -e "========================================${NC}"
echo ""
echo "Monitoring Scripts Created:"
echo "  $LOGDIR/splunk-health-check.sh"
echo "  $LOGDIR/monitor-splunk-logins.sh"
echo "  $LOGDIR/monitor-config-changes.sh"
echo ""
echo "CCDC Alerts App: $SPLUNK_HOME/etc/apps/ccdc_alerts/"
echo ""
echo -e "${CYAN}USAGE:${NC}"
echo "  $LOGDIR/splunk-health-check.sh      # Quick health check"
echo "  $LOGDIR/monitor-splunk-logins.sh    # Check login activity"
echo ""
echo -e "${YELLOW}SPLUNK SEARCHES FOR MONITORING:${NC}"
echo "  index=_audit | stats count by action, user"
echo "  index=_audit action=login_failed | stats count by user, src"
echo "  index=_internal sourcetype=splunkd log_level=ERROR"
echo ""
