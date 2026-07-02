#!/bin/bash
#===============================================================================
# CCDC Splunk SIEM - Incident Response Script
# Target: Splunk Enterprise on Linux
# Run as: root
#===============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

LOGDIR="/opt/splunk-ccdc-logs"
mkdir -p "$LOGDIR"

# Detect Splunk installation
SPLUNK_HOME=""
for path in /opt/splunk /opt/splunkforwarder /usr/local/splunk; do
    if [ -d "$path" ]; then
        SPLUNK_HOME="$path"
        break
    fi
done

SPLUNK_HOME=${SPLUNK_HOME:-/opt/splunk}
SPLUNK_CMD="$SPLUNK_HOME/bin/splunk"

show_menu() {
    echo ""
    echo -e "${RED}========================================"
    echo "  CCDC Splunk Incident Response"
    echo -e "========================================${NC}"
    echo ""
    echo "  1) Disable Splunk User Account"
    echo "  2) Reset Splunk User Password"
    echo "  3) Disable Linux User Account"
    echo "  4) Block IP in Firewall"
    echo "  5) Kill Suspicious Process"
    echo "  6) Check Active Sessions"
    echo "  7) Check for Suspicious Apps"
    echo "  8) Disable Splunk App"
    echo "  9) Check Persistence Mechanisms"
    echo " 10) Export Audit Logs"
    echo " 11) Quick System Capture"
    echo " 12) Emergency: Disable Splunk Web"
    echo " 13) Emergency: Stop All Forwarder Input"
    echo "  0) Exit"
    echo ""
}

#===============================================================================
disable_splunk_user() {
    echo ""
    echo "Current Splunk users:"
    cat "$SPLUNK_HOME/etc/passwd" 2>/dev/null
    echo ""

    read -p "Enter Splunk username to disable: " username
    if [ -n "$username" ]; then
        # Remove from passwd file (effectively disables)
        if grep -q "^$username:" "$SPLUNK_HOME/etc/passwd" 2>/dev/null; then
            # Backup first
            cp "$SPLUNK_HOME/etc/passwd" "$LOGDIR/passwd.bak.$(date +%Y%m%d_%H%M%S)"

            # Comment out user
            sed -i "s/^$username:/#DISABLED#$username:/" "$SPLUNK_HOME/etc/passwd"

            echo -e "${GREEN}[+] Disabled Splunk user: $username${NC}"
            echo "[$(date)] Disabled Splunk user: $username" >> "$LOGDIR/incident_actions.log"
        else
            echo -e "${RED}User not found${NC}"
        fi
    fi
}

#===============================================================================
reset_splunk_password() {
    echo ""
    read -p "Enter Splunk username: " username
    if [ -n "$username" ]; then
        NEW_PASS=$(< /dev/urandom tr -dc 'A-Za-z0-9!@#$%' | head -c 16)

        read -sp "Enter current admin password for authentication: " admin_pass
        echo ""

        if $SPLUNK_CMD edit user "$username" -password "$NEW_PASS" -auth "admin:$admin_pass" 2>/dev/null; then
            echo -e "${GREEN}[+] Password reset for: $username${NC}"
            echo -e "${YELLOW}    New password: $NEW_PASS${NC}"
            echo "[$(date)] Reset password for Splunk user: $username" >> "$LOGDIR/incident_actions.log"
        else
            echo -e "${RED}[-] Failed to reset password${NC}"
        fi
    fi
}

#===============================================================================
disable_linux_user() {
    echo ""
    echo "Users with login shells:"
    grep -v "nologin\|false" /etc/passwd | cut -d: -f1
    echo ""

    read -p "Enter Linux username to disable: " username
    if [ -n "$username" ]; then
        # Lock account
        usermod -L "$username" 2>/dev/null && echo -e "${GREEN}[+] Account locked${NC}"

        # Set shell to nologin
        usermod -s /sbin/nologin "$username" 2>/dev/null && echo -e "${GREEN}[+] Shell set to nologin${NC}"

        # Expire password
        passwd -e "$username" 2>/dev/null

        echo "[$(date)] Disabled Linux user: $username" >> "$LOGDIR/incident_actions.log"
    fi
}

#===============================================================================
block_ip() {
    echo ""
    read -p "Enter IP address to block: " ip
    if [ -n "$ip" ]; then
        # Detect firewall type
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
            ufw deny from "$ip"
            ufw deny to "$ip"
            echo -e "${GREEN}[+] Blocked $ip (UFW)${NC}"
        elif command -v firewall-cmd &>/dev/null; then
            firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$ip' reject"
            firewall-cmd --reload
            echo -e "${GREEN}[+] Blocked $ip (firewalld)${NC}"
        else
            iptables -I INPUT -s "$ip" -j DROP
            iptables -I OUTPUT -d "$ip" -j DROP
            echo -e "${GREEN}[+] Blocked $ip (iptables)${NC}"
        fi

        echo "$ip" >> "$LOGDIR/blocked_ips.txt"
        echo "[$(date)] Blocked IP: $ip" >> "$LOGDIR/incident_actions.log"
    fi
}

#===============================================================================
kill_process() {
    echo ""
    echo "Current processes:"
    ps aux --sort=-%cpu | head -20
    echo ""

    echo "Splunk processes:"
    ps aux | grep -i splunk | grep -v grep
    echo ""

    read -p "Enter PID to kill: " pid
    if [ -n "$pid" ] && [ "$pid" -gt 0 ]; then
        # Get process info before killing
        ps -p "$pid" -o pid,user,comm,args >> "$LOGDIR/killed_processes.log" 2>/dev/null

        kill -9 "$pid" 2>/dev/null
        echo -e "${GREEN}[+] Killed process: $pid${NC}"
        echo "[$(date)] Killed PID: $pid" >> "$LOGDIR/incident_actions.log"
    fi
}

#===============================================================================
check_sessions() {
    echo ""
    echo -e "${CYAN}=== Splunk Active Sessions ===${NC}"

    # Check web sessions via REST API
    echo "REST API sessions:"
    read -sp "Enter admin password: " admin_pass
    echo ""

    curl -sk -u "admin:$admin_pass" https://localhost:8089/services/authentication/httpauth-tokens 2>/dev/null | \
        grep -oP "name=\"[^\"]*\"" | head -20

    echo ""
    echo -e "${CYAN}=== Linux User Sessions ===${NC}"
    who
    echo ""

    echo -e "${CYAN}=== SSH Connections ===${NC}"
    ss -tnp | grep ":22"
    echo ""

    echo -e "${CYAN}=== Network Connections to Splunk ===${NC}"
    ss -tnp | grep -E ":8000|:8089|:9997"
    echo ""
}

#===============================================================================
check_suspicious_apps() {
    echo ""
    echo -e "${CYAN}=== Checking Splunk Apps ===${NC}"
    echo ""

    echo "Installed apps:"
    ls -la "$SPLUNK_HOME/etc/apps/"
    echo ""

    # Check for suspicious patterns
    echo "Apps with bin/ directories (executable scripts):"
    for app in "$SPLUNK_HOME/etc/apps/"*/; do
        if [ -d "${app}bin" ]; then
            appname=$(basename "$app")
            echo -e "${YELLOW}[!] $appname has bin/ directory:${NC}"
            ls -la "${app}bin/"
        fi
    done
    echo ""

    echo "Apps with scripted inputs:"
    find "$SPLUNK_HOME/etc/apps" -name "inputs.conf" -exec grep -l "script://" {} \; 2>/dev/null
    echo ""

    echo "Recently modified apps (last 24 hours):"
    find "$SPLUNK_HOME/etc/apps" -type f -mtime -1 -ls 2>/dev/null | head -20
    echo ""
}

#===============================================================================
disable_app() {
    echo ""
    echo "Installed apps:"
    ls -1 "$SPLUNK_HOME/etc/apps/"
    echo ""

    read -p "Enter app name to disable: " appname
    if [ -n "$appname" ] && [ -d "$SPLUNK_HOME/etc/apps/$appname" ]; then
        mkdir -p "$SPLUNK_HOME/etc/apps/$appname/local"
        echo -e "[install]\nstate = disabled" > "$SPLUNK_HOME/etc/apps/$appname/local/app.conf"

        echo -e "${GREEN}[+] Disabled app: $appname${NC}"
        echo -e "${YELLOW}[!] Restart Splunk to apply: $SPLUNK_CMD restart${NC}"
        echo "[$(date)] Disabled Splunk app: $appname" >> "$LOGDIR/incident_actions.log"
    else
        echo -e "${RED}App not found${NC}"
    fi
}

#===============================================================================
check_persistence() {
    echo ""
    echo -e "${CYAN}=== Checking Persistence Mechanisms ===${NC}"
    echo ""

    echo "=== Cron Jobs ==="
    echo "Root crontab:"
    crontab -l 2>/dev/null || echo "  No root crontab"
    echo ""

    echo "Splunk user crontab:"
    crontab -u splunk -l 2>/dev/null || echo "  No splunk crontab"
    echo ""

    echo "System cron:"
    ls -la /etc/cron.d/ 2>/dev/null
    echo ""

    echo "=== Systemd Services ==="
    systemctl list-unit-files --type=service | grep -i splunk
    echo ""

    echo "=== Startup Scripts ==="
    ls -la /etc/init.d/ 2>/dev/null | grep -i splunk
    echo ""

    echo "=== Splunk Scheduled Searches ==="
    find "$SPLUNK_HOME/etc" -name "savedsearches.conf" -exec grep -l "enableSched.*1" {} \; 2>/dev/null
    echo ""

    echo "=== Suspicious Scripts in Splunk ==="
    find "$SPLUNK_HOME/etc/apps" -name "*.sh" -o -name "*.py" -o -name "*.pl" 2>/dev/null | head -20
    echo ""

    echo "=== SSH Authorized Keys ==="
    for home in /home/* /root; do
        if [ -f "$home/.ssh/authorized_keys" ]; then
            echo "$home/.ssh/authorized_keys:"
            cat "$home/.ssh/authorized_keys"
        fi
    done
    echo ""
}

#===============================================================================
export_audit_logs() {
    echo ""
    EXPORT_DIR="$LOGDIR/audit_export_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$EXPORT_DIR"

    echo "[*] Exporting audit logs to $EXPORT_DIR..."

    # Splunk audit log
    cp "$SPLUNK_HOME/var/log/splunk/audit.log" "$EXPORT_DIR/" 2>/dev/null
    echo "    [+] Splunk audit.log"

    # Splunk access log
    cp "$SPLUNK_HOME/var/log/splunk/splunkd_access.log" "$EXPORT_DIR/" 2>/dev/null
    echo "    [+] Splunk access log"

    # Recent splunkd logs
    tail -10000 "$SPLUNK_HOME/var/log/splunk/splunkd.log" > "$EXPORT_DIR/splunkd_recent.log" 2>/dev/null
    echo "    [+] Recent splunkd.log"

    # System logs
    cp /var/log/auth.log "$EXPORT_DIR/" 2>/dev/null || cp /var/log/secure "$EXPORT_DIR/" 2>/dev/null
    echo "    [+] System auth log"

    # Audit log
    cp /var/log/audit/audit.log "$EXPORT_DIR/" 2>/dev/null
    echo "    [+] Audit log"

    echo ""
    echo -e "${GREEN}[+] Logs exported to: $EXPORT_DIR${NC}"

    # Create tar
    tar -czf "$EXPORT_DIR.tar.gz" -C "$LOGDIR" "$(basename $EXPORT_DIR)"
    echo -e "${GREEN}[+] Archive: $EXPORT_DIR.tar.gz${NC}"
}

#===============================================================================
quick_capture() {
    echo ""
    CAPTURE_DIR="$LOGDIR/capture_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$CAPTURE_DIR"

    echo "[*] Capturing system state..."

    # Processes
    ps auxf > "$CAPTURE_DIR/processes.txt"
    echo "    [+] Processes"

    # Network connections
    ss -tnpa > "$CAPTURE_DIR/connections.txt"
    echo "    [+] Network connections"

    # Listening ports
    ss -tlnp > "$CAPTURE_DIR/listening.txt"
    echo "    [+] Listening ports"

    # Users
    cat /etc/passwd > "$CAPTURE_DIR/passwd.txt"
    who > "$CAPTURE_DIR/who.txt"
    last -50 > "$CAPTURE_DIR/last.txt"
    echo "    [+] User info"

    # Splunk status
    $SPLUNK_CMD status > "$CAPTURE_DIR/splunk_status.txt" 2>&1
    echo "    [+] Splunk status"

    # Splunk users
    cp "$SPLUNK_HOME/etc/passwd" "$CAPTURE_DIR/splunk_passwd.txt" 2>/dev/null
    echo "    [+] Splunk users"

    # Network routes
    ip route > "$CAPTURE_DIR/routes.txt"
    echo "    [+] Network routes"

    # Firewall rules
    iptables -L -n > "$CAPTURE_DIR/iptables.txt" 2>/dev/null
    echo "    [+] Firewall rules"

    echo ""
    echo -e "${GREEN}[+] Capture complete: $CAPTURE_DIR${NC}"
}

#===============================================================================
emergency_disable_web() {
    echo ""
    echo -e "${RED}[!] EMERGENCY: Disabling Splunk Web Interface${NC}"

    read -p "This will disable web access. Continue? (y/N): " confirm
    if [ "$confirm" = "y" ]; then
        # Backup current config
        cp "$SPLUNK_HOME/etc/system/local/web.conf" "$LOGDIR/web.conf.bak.$(date +%Y%m%d_%H%M%S)" 2>/dev/null

        # Disable web server
        mkdir -p "$SPLUNK_HOME/etc/system/local"
        cat > "$SPLUNK_HOME/etc/system/local/web.conf" << 'EOF'
[settings]
startwebserver = false
EOF

        $SPLUNK_CMD restart 2>/dev/null

        echo -e "${GREEN}[+] Splunk Web disabled${NC}"
        echo "[$(date)] EMERGENCY: Disabled Splunk Web" >> "$LOGDIR/incident_actions.log"
    fi
}

#===============================================================================
emergency_stop_inputs() {
    echo ""
    echo -e "${RED}[!] EMERGENCY: Stopping Forwarder Inputs${NC}"
    echo "This will stop accepting data from forwarders"

    read -p "Continue? (y/N): " confirm
    if [ "$confirm" = "y" ]; then
        # Disable the receiving port
        mkdir -p "$SPLUNK_HOME/etc/system/local"

        # Backup
        cp "$SPLUNK_HOME/etc/system/local/inputs.conf" "$LOGDIR/inputs.conf.bak.$(date +%Y%m%d_%H%M%S)" 2>/dev/null

        # Disable splunktcp
        cat >> "$SPLUNK_HOME/etc/system/local/inputs.conf" << 'EOF'

[splunktcp://9997]
disabled = true

[splunktcp-ssl://9997]
disabled = true
EOF

        $SPLUNK_CMD restart 2>/dev/null

        echo -e "${GREEN}[+] Forwarder receiving disabled${NC}"
        echo "[$(date)] EMERGENCY: Disabled forwarder inputs" >> "$LOGDIR/incident_actions.log"
    fi
}

#===============================================================================
# Main loop
#===============================================================================

while true; do
    show_menu
    read -p "Select action: " choice

    case $choice in
        1) disable_splunk_user ;;
        2) reset_splunk_password ;;
        3) disable_linux_user ;;
        4) block_ip ;;
        5) kill_process ;;
        6) check_sessions ;;
        7) check_suspicious_apps ;;
        8) disable_app ;;
        9) check_persistence ;;
        10) export_audit_logs ;;
        11) quick_capture ;;
        12) emergency_disable_web ;;
        13) emergency_stop_inputs ;;
        0) exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac

    echo ""
    read -p "Press Enter to continue..."
done
