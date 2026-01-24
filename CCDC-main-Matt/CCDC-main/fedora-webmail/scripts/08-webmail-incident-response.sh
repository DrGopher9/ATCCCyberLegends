#!/bin/bash
#===============================================================================
# CCDC Fedora Webmail/Apps - Incident Response Script
# Target: Fedora Server
# Run as: root
#===============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

LOGDIR="/opt/ccdc-logs"
mkdir -p "$LOGDIR"

show_menu() {
    echo ""
    echo -e "${RED}========================================"
    echo "  CCDC Fedora Incident Response"
    echo -e "========================================${NC}"
    echo ""
    echo "  1) Lock User Account"
    echo "  2) Reset User Password"
    echo "  3) Block IP Address"
    echo "  4) Kill Suspicious Process"
    echo "  5) Check for Web Shells"
    echo "  6) Check Active Connections"
    echo "  7) Check Persistence Mechanisms"
    echo "  8) Export Logs"
    echo "  9) Quick System Capture"
    echo " 10) Disable Web Application"
    echo " 11) Check Failed Logins"
    echo "  0) Exit"
    echo ""
}

#===============================================================================
lock_user() {
    echo ""
    echo "Users with login shells:"
    grep -v "nologin\|false" /etc/passwd | cut -d: -f1
    echo ""
    read -p "Enter username to lock: " username
    if [ -n "$username" ]; then
        usermod -L "$username" 2>/dev/null && echo -e "${GREEN}[+] Account locked${NC}"
        usermod -s /sbin/nologin "$username" 2>/dev/null && echo -e "${GREEN}[+] Shell disabled${NC}"
        passwd -e "$username" 2>/dev/null
        echo "[$(date)] Locked user: $username" >> "$LOGDIR/incident_actions.log"
    fi
}

#===============================================================================
reset_password() {
    echo ""
    read -p "Enter username: " username
    if [ -n "$username" ]; then
        NEW_PASS=$(< /dev/urandom tr -dc 'A-Za-z0-9!@#$%' | head -c 16)
        echo "$NEW_PASS" | passwd --stdin "$username" 2>/dev/null || \
        echo "$username:$NEW_PASS" | chpasswd

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+] Password reset for: $username${NC}"
            echo -e "${YELLOW}    New password: $NEW_PASS${NC}"
            echo "[$(date)] Reset password: $username" >> "$LOGDIR/incident_actions.log"
        fi
    fi
}

#===============================================================================
block_ip() {
    echo ""
    read -p "Enter IP address to block: " ip
    if [ -n "$ip" ]; then
        firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$ip' reject"
        firewall-cmd --reload
        echo -e "${GREEN}[+] Blocked: $ip${NC}"
        echo "$ip" >> "$LOGDIR/blocked_ips.txt"
        echo "[$(date)] Blocked IP: $ip" >> "$LOGDIR/incident_actions.log"
    fi
}

#===============================================================================
kill_process() {
    echo ""
    echo "Suspicious processes:"
    ps aux | grep -iE "(nc|ncat|netcat|python.*-c|perl.*-e|bash.*-i|/tmp/)" | grep -v grep
    echo ""
    echo "All processes by CPU:"
    ps aux --sort=-%cpu | head -15
    echo ""
    read -p "Enter PID to kill: " pid
    if [ -n "$pid" ]; then
        ps -p "$pid" -o pid,user,comm,args >> "$LOGDIR/killed_processes.log" 2>/dev/null
        kill -9 "$pid" 2>/dev/null
        echo -e "${GREEN}[+] Killed process: $pid${NC}"
        echo "[$(date)] Killed PID: $pid" >> "$LOGDIR/incident_actions.log"
    fi
}

#===============================================================================
check_webshells() {
    echo ""
    echo -e "${YELLOW}[*] Scanning for web shells...${NC}"

    WEBROOT="/var/www/html"

    echo ""
    echo "=== Files with dangerous PHP functions ==="
    grep -rn "eval\|base64_decode\|shell_exec\|system\|passthru\|exec(" "$WEBROOT" 2>/dev/null | \
        grep -v "Binary" | head -20
    echo ""

    echo "=== Files modified in last 24 hours ==="
    find "$WEBROOT" -name "*.php" -mtime -1 2>/dev/null | head -20
    echo ""

    echo "=== PHP files in suspicious locations ==="
    find "$WEBROOT" -path "*upload*" -name "*.php" 2>/dev/null
    find "$WEBROOT" -path "*tmp*" -name "*.php" 2>/dev/null
    find "$WEBROOT" -path "*cache*" -name "*.php" 2>/dev/null
    echo ""

    echo "=== Files with suspicious names ==="
    find "$WEBROOT" -name "*.php" | grep -iE "(shell|cmd|backdoor|c99|r57|wso|b374k)" 2>/dev/null
    echo ""

    read -p "Enter file path to examine (or skip): " filepath
    if [ -n "$filepath" ] && [ -f "$filepath" ]; then
        echo ""
        echo "=== File contents ==="
        head -50 "$filepath"
        echo ""
        read -p "Delete this file? (y/N): " delete_file
        if [ "$delete_file" = "y" ]; then
            cp "$filepath" "$LOGDIR/webshell_$(date +%Y%m%d_%H%M%S)_$(basename $filepath)"
            rm "$filepath"
            echo -e "${GREEN}[+] File deleted (backup saved to $LOGDIR)${NC}"
        fi
    fi
}

#===============================================================================
check_connections() {
    echo ""
    echo -e "${CYAN}=== Active Network Connections ===${NC}"
    echo ""

    echo "Established connections:"
    ss -tnp state established 2>/dev/null | head -20
    echo ""

    echo "Listening ports:"
    ss -tlnp | head -20
    echo ""

    echo "Connections to/from external IPs:"
    ss -tnp | grep -v "127.0.0.1\|::1" | head -20
    echo ""
}

#===============================================================================
check_persistence() {
    echo ""
    echo -e "${CYAN}=== Checking Persistence Mechanisms ===${NC}"
    echo ""

    echo "=== Cron Jobs ==="
    for user in $(cut -d: -f1 /etc/passwd); do
        crontab -l -u "$user" 2>/dev/null | grep -v "^#" | grep -v "^$" | while read -r line; do
            echo "  $user: $line"
        done
    done
    echo ""
    ls -la /etc/cron.d/ 2>/dev/null
    echo ""

    echo "=== Systemd Services (non-vendor) ==="
    ls -la /etc/systemd/system/*.service 2>/dev/null
    echo ""

    echo "=== SSH Authorized Keys ==="
    for home in /home/* /root; do
        if [ -f "$home/.ssh/authorized_keys" ]; then
            user=$(basename "$home")
            count=$(wc -l < "$home/.ssh/authorized_keys")
            echo "  $user: $count keys"
        fi
    done
    echo ""

    echo "=== Recently Modified Startup Files ==="
    find /etc/rc.d /etc/init.d -mtime -7 2>/dev/null
    echo ""

    echo "=== Sudoers Entries ==="
    grep -v "^#" /etc/sudoers 2>/dev/null | grep -v "^$"
    ls -la /etc/sudoers.d/ 2>/dev/null
    echo ""
}

#===============================================================================
export_logs() {
    echo ""
    EXPORT_DIR="$LOGDIR/export_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$EXPORT_DIR"

    echo "[*] Exporting logs to $EXPORT_DIR..."

    cp /var/log/secure "$EXPORT_DIR/" 2>/dev/null && echo "    [+] secure log"
    cp /var/log/messages "$EXPORT_DIR/" 2>/dev/null && echo "    [+] messages log"
    cp -r /var/log/httpd "$EXPORT_DIR/" 2>/dev/null && echo "    [+] httpd logs"
    cp /var/log/audit/audit.log "$EXPORT_DIR/" 2>/dev/null && echo "    [+] audit log"
    cp /var/log/fail2ban.log "$EXPORT_DIR/" 2>/dev/null && echo "    [+] fail2ban log"

    tar -czf "$EXPORT_DIR.tar.gz" -C "$LOGDIR" "$(basename $EXPORT_DIR)"
    echo ""
    echo -e "${GREEN}[+] Logs exported to: $EXPORT_DIR.tar.gz${NC}"
}

#===============================================================================
quick_capture() {
    echo ""
    CAPTURE_DIR="$LOGDIR/capture_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$CAPTURE_DIR"

    echo "[*] Capturing system state..."

    ps auxf > "$CAPTURE_DIR/processes.txt" && echo "    [+] Processes"
    ss -tnpa > "$CAPTURE_DIR/connections.txt" && echo "    [+] Connections"
    ss -tlnp > "$CAPTURE_DIR/listening.txt" && echo "    [+] Listening ports"
    netstat -rn > "$CAPTURE_DIR/routes.txt" 2>/dev/null && echo "    [+] Routes"
    cat /etc/passwd > "$CAPTURE_DIR/passwd.txt" && echo "    [+] Users"
    who > "$CAPTURE_DIR/who.txt" && echo "    [+] Logged in"
    last -50 > "$CAPTURE_DIR/last.txt" && echo "    [+] Login history"
    crontab -l > "$CAPTURE_DIR/root_cron.txt" 2>/dev/null && echo "    [+] Root crontab"
    firewall-cmd --list-all > "$CAPTURE_DIR/firewall.txt" 2>/dev/null && echo "    [+] Firewall"
    find /var/www -name "*.php" -mtime -1 > "$CAPTURE_DIR/recent_php.txt" 2>/dev/null && echo "    [+] Recent PHP files"

    echo ""
    echo -e "${GREEN}[+] Capture complete: $CAPTURE_DIR${NC}"
}

#===============================================================================
disable_webapp() {
    echo ""
    echo "Web applications in /var/www/html:"
    ls -la /var/www/html/
    echo ""
    read -p "Enter app directory to disable (e.g., roundcube): " appdir
    if [ -n "$appdir" ] && [ -d "/var/www/html/$appdir" ]; then
        mv "/var/www/html/$appdir" "/var/www/html/${appdir}.disabled"
        echo -e "${GREEN}[+] Disabled: $appdir${NC}"
        echo "[$(date)] Disabled webapp: $appdir" >> "$LOGDIR/incident_actions.log"
    fi
}

#===============================================================================
check_failed_logins() {
    echo ""
    echo -e "${CYAN}=== Failed Logins ===${NC}"
    echo ""

    echo "SSH Failed Logins (last 50):"
    grep "Failed password" /var/log/secure 2>/dev/null | tail -50
    echo ""

    echo "Summary by IP:"
    grep "Failed password" /var/log/secure 2>/dev/null | \
        grep -oP "from \K[\d.]+" | sort | uniq -c | sort -rn | head -10
    echo ""

    echo "Summary by User:"
    grep "Failed password" /var/log/secure 2>/dev/null | \
        grep -oP "for (invalid user )?\K\w+" | sort | uniq -c | sort -rn | head -10
    echo ""

    echo "Fail2ban banned IPs:"
    fail2ban-client status sshd 2>/dev/null | grep "Banned IP"
    echo ""
}

#===============================================================================
# Main loop
while true; do
    show_menu
    read -p "Select action: " choice

    case $choice in
        1) lock_user ;;
        2) reset_password ;;
        3) block_ip ;;
        4) kill_process ;;
        5) check_webshells ;;
        6) check_connections ;;
        7) check_persistence ;;
        8) export_logs ;;
        9) quick_capture ;;
        10) disable_webapp ;;
        11) check_failed_logins ;;
        0) exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac

    echo ""
    read -p "Press Enter to continue..."
done
