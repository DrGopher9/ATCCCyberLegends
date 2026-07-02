#!/bin/bash
#===============================================================================
# CCDC Splunk SIEM - Reconnaissance Script
# Target: Splunk Enterprise on Linux
# Run as: root or splunk user
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
RECON_FILE="$LOGDIR/splunk_recon_$(date +%Y%m%d_%H%M%S).txt"

echo -e "${CYAN}========================================"
echo "  CCDC Splunk SIEM Reconnaissance"
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
    echo -e "${RED}[!] Splunk installation not found in standard locations${NC}"
    read -p "Enter Splunk installation path: " SPLUNK_HOME
fi

SPLUNK_CMD="$SPLUNK_HOME/bin/splunk"

echo "Splunk Home: $SPLUNK_HOME"
echo ""

{
    echo "CCDC Splunk Reconnaissance - $(date)"
    echo "=============================================="
    echo ""

    #---------------------------------------------------------------------------
    echo "=== SYSTEM INFORMATION ==="
    echo ""
    echo "Hostname: $(hostname)"
    echo "IP Addresses:"
    ip -4 addr show | grep inet | awk '{print "  " $2}'
    echo ""
    echo "OS Information:"
    cat /etc/os-release 2>/dev/null | head -5
    echo ""
    echo "Kernel: $(uname -r)"
    echo "Uptime: $(uptime)"
    echo ""

    #---------------------------------------------------------------------------
    echo "=== SPLUNK VERSION & STATUS ==="
    echo ""
    if [ -x "$SPLUNK_CMD" ]; then
        echo "Splunk Version:"
        $SPLUNK_CMD version 2>/dev/null || echo "  Could not get version"
        echo ""
        echo "Splunk Status:"
        $SPLUNK_CMD status 2>/dev/null || echo "  Could not get status"
        echo ""
    fi

    #---------------------------------------------------------------------------
    echo "=== SPLUNK CONFIGURATION ==="
    echo ""
    echo "server.conf (key settings):"
    if [ -f "$SPLUNK_HOME/etc/system/local/server.conf" ]; then
        cat "$SPLUNK_HOME/etc/system/local/server.conf" 2>/dev/null
    else
        echo "  No local server.conf found"
    fi
    echo ""

    echo "web.conf (key settings):"
    if [ -f "$SPLUNK_HOME/etc/system/local/web.conf" ]; then
        cat "$SPLUNK_HOME/etc/system/local/web.conf" 2>/dev/null
    else
        echo "  No local web.conf found"
    fi
    echo ""

    echo "inputs.conf (data inputs):"
    find "$SPLUNK_HOME/etc" -name "inputs.conf" -exec echo "--- {} ---" \; -exec cat {} \; 2>/dev/null
    echo ""

    #---------------------------------------------------------------------------
    echo "=== SPLUNK USERS & AUTHENTICATION ==="
    echo ""
    echo "Local Users (passwd file):"
    if [ -f "$SPLUNK_HOME/etc/passwd" ]; then
        cat "$SPLUNK_HOME/etc/passwd" 2>/dev/null
    else
        echo "  No passwd file found"
    fi
    echo ""

    echo "Authentication Configuration:"
    if [ -f "$SPLUNK_HOME/etc/system/local/authentication.conf" ]; then
        cat "$SPLUNK_HOME/etc/system/local/authentication.conf" 2>/dev/null
    else
        echo "  No local authentication.conf found"
    fi
    echo ""

    echo "authorize.conf (roles):"
    find "$SPLUNK_HOME/etc" -name "authorize.conf" -exec echo "--- {} ---" \; -exec cat {} \; 2>/dev/null | head -100
    echo ""

    #---------------------------------------------------------------------------
    echo "=== SPLUNK APPS ==="
    echo ""
    echo "Installed Apps:"
    ls -la "$SPLUNK_HOME/etc/apps/" 2>/dev/null
    echo ""

    echo "Enabled Apps:"
    for app in "$SPLUNK_HOME/etc/apps/"*/; do
        appname=$(basename "$app")
        if [ -f "$app/local/app.conf" ]; then
            disabled=$(grep -i "state.*disabled" "$app/local/app.conf" 2>/dev/null)
            if [ -z "$disabled" ]; then
                echo "  [ENABLED] $appname"
            else
                echo "  [DISABLED] $appname"
            fi
        else
            echo "  [DEFAULT] $appname"
        fi
    done
    echo ""

    #---------------------------------------------------------------------------
    echo "=== SPLUNK INDEXES ==="
    echo ""
    echo "Index Configuration:"
    find "$SPLUNK_HOME/etc" -name "indexes.conf" -exec echo "--- {} ---" \; -exec cat {} \; 2>/dev/null | head -100
    echo ""

    echo "Index Sizes:"
    if [ -x "$SPLUNK_CMD" ]; then
        $SPLUNK_CMD list index 2>/dev/null || echo "  Could not list indexes"
    fi
    echo ""

    #---------------------------------------------------------------------------
    echo "=== SPLUNK FORWARDERS & RECEIVERS ==="
    echo ""
    echo "outputs.conf (forwarding):"
    find "$SPLUNK_HOME/etc" -name "outputs.conf" -exec echo "--- {} ---" \; -exec cat {} \; 2>/dev/null
    echo ""

    echo "Receiving Configuration:"
    if [ -f "$SPLUNK_HOME/etc/system/local/inputs.conf" ]; then
        grep -A5 "\[splunktcp\]" "$SPLUNK_HOME/etc/system/local/inputs.conf" 2>/dev/null
        grep -A5 "\[tcp\]" "$SPLUNK_HOME/etc/system/local/inputs.conf" 2>/dev/null
        grep -A5 "\[udp\]" "$SPLUNK_HOME/etc/system/local/inputs.conf" 2>/dev/null
    fi
    echo ""

    #---------------------------------------------------------------------------
    echo "=== SPLUNK DEPLOYMENT SERVER ==="
    echo ""
    echo "deploymentclient.conf:"
    find "$SPLUNK_HOME/etc" -name "deploymentclient.conf" -exec echo "--- {} ---" \; -exec cat {} \; 2>/dev/null
    echo ""

    echo "serverclass.conf (if deployment server):"
    if [ -f "$SPLUNK_HOME/etc/system/local/serverclass.conf" ]; then
        cat "$SPLUNK_HOME/etc/system/local/serverclass.conf" 2>/dev/null
    fi
    echo ""

    #---------------------------------------------------------------------------
    echo "=== NETWORK LISTENERS ==="
    echo ""
    echo "Splunk Listening Ports:"
    ss -tlnp 2>/dev/null | grep -E "(splunk|8000|8089|9997|8088|514)" || \
    netstat -tlnp 2>/dev/null | grep -E "(splunk|8000|8089|9997|8088|514)"
    echo ""

    echo "All Listening Ports:"
    ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
    echo ""

    #---------------------------------------------------------------------------
    echo "=== SSL/TLS CONFIGURATION ==="
    echo ""
    echo "SSL Settings in server.conf:"
    grep -i ssl "$SPLUNK_HOME/etc/system/local/server.conf" 2>/dev/null || echo "  No local SSL settings"
    echo ""

    echo "SSL Settings in web.conf:"
    grep -i ssl "$SPLUNK_HOME/etc/system/local/web.conf" 2>/dev/null || echo "  No local SSL settings"
    echo ""

    echo "Certificate Files:"
    find "$SPLUNK_HOME/etc/auth" -type f -name "*.pem" -o -name "*.crt" -o -name "*.key" 2>/dev/null
    echo ""

    #---------------------------------------------------------------------------
    echo "=== SYSTEM USERS ==="
    echo ""
    echo "Users with shells:"
    grep -v "nologin\|false" /etc/passwd | grep -v "^#"
    echo ""

    echo "Splunk service user:"
    ps aux | grep splunk | grep -v grep | head -5
    echo ""

    echo "Sudoers for splunk:"
    grep -r splunk /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo "  No splunk sudo entries"
    echo ""

    #---------------------------------------------------------------------------
    echo "=== SSH CONFIGURATION ==="
    echo ""
    echo "SSH Config:"
    grep -E "^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|Port)" /etc/ssh/sshd_config 2>/dev/null
    echo ""

    echo "Authorized Keys (root):"
    cat /root/.ssh/authorized_keys 2>/dev/null || echo "  No root authorized_keys"
    echo ""

    #---------------------------------------------------------------------------
    echo "=== FIREWALL STATUS ==="
    echo ""
    if command -v ufw &>/dev/null; then
        echo "UFW Status:"
        ufw status verbose 2>/dev/null
    elif command -v firewall-cmd &>/dev/null; then
        echo "Firewalld Status:"
        firewall-cmd --state 2>/dev/null
        firewall-cmd --list-all 2>/dev/null
    else
        echo "iptables Rules:"
        iptables -L -n 2>/dev/null | head -50
    fi
    echo ""

    #---------------------------------------------------------------------------
    echo "=== SCHEDULED TASKS ==="
    echo ""
    echo "Crontab (root):"
    crontab -l 2>/dev/null || echo "  No root crontab"
    echo ""

    echo "Crontab (splunk user):"
    crontab -u splunk -l 2>/dev/null || echo "  No splunk user crontab"
    echo ""

    echo "System Cron Jobs:"
    ls -la /etc/cron.d/ 2>/dev/null
    echo ""

    #---------------------------------------------------------------------------
    echo "=== RUNNING PROCESSES ==="
    echo ""
    echo "Splunk Processes:"
    ps aux | grep -i splunk | grep -v grep
    echo ""

    echo "Suspicious Processes:"
    ps aux | grep -iE "(nc|ncat|netcat|python.*-c|perl.*-e|ruby.*-e|bash.*-i)" | grep -v grep
    echo ""

    #---------------------------------------------------------------------------
    echo "=== SPLUNK LICENSE ==="
    echo ""
    if [ -x "$SPLUNK_CMD" ]; then
        $SPLUNK_CMD list licenser-pools 2>/dev/null || echo "  Could not get license info"
    fi
    echo ""

    #---------------------------------------------------------------------------
    echo "=== RECENT SPLUNK LOGS ==="
    echo ""
    echo "Last 20 lines of splunkd.log:"
    tail -20 "$SPLUNK_HOME/var/log/splunk/splunkd.log" 2>/dev/null
    echo ""

    echo "Recent Audit Logs:"
    tail -20 "$SPLUNK_HOME/var/log/splunk/audit.log" 2>/dev/null
    echo ""

} | tee "$RECON_FILE"

echo ""
echo -e "${GREEN}========================================"
echo "  Reconnaissance Complete"
echo -e "========================================${NC}"
echo ""
echo -e "${YELLOW}Output saved to: $RECON_FILE${NC}"
echo ""
echo -e "${CYAN}Key Items to Review:${NC}"
echo "  - Splunk users and roles"
echo "  - Enabled apps (potential backdoors)"
echo "  - Data inputs (what's being collected)"
echo "  - Forwarding configuration"
echo "  - SSL/TLS settings"
echo "  - Network listeners"
echo ""
