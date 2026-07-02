#!/bin/bash
###############################################################################
# 09-incident-response.sh - Quick Incident Response Actions
# Target: Ubuntu 24 E-Commerce Server
# Purpose: Rapid response to suspected compromise
###############################################################################

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

LOGDIR="/root/ccdc-logs"
IR_LOG="$LOGDIR/incident_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$LOGDIR"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$IR_LOG"
}

banner() {
    echo ""
    echo -e "${RED}============================================${NC}"
    echo -e "${RED}  $1${NC}"
    echo -e "${RED}============================================${NC}"
    echo ""
}

banner "INCIDENT RESPONSE - QUICK ACTIONS"

echo "This script provides rapid response options."
echo "Log file: $IR_LOG"
echo ""
echo "Select action:"
echo ""
echo "  1) Kill suspicious process"
echo "  2) Block IP address"
echo "  3) Lock user account"
echo "  4) Kill all sessions for user"
echo "  5) Check for backdoors"
echo "  6) Emergency password reset"
echo "  7) Capture system state"
echo "  8) Check for webshells"
echo "  9) Restore from backup"
echo "  0) Exit"
echo ""

while true; do
    read -p "Select action [0-9]: " -r ACTION

    case $ACTION in
        1)
            banner "KILL SUSPICIOUS PROCESS"
            echo "Current processes:"
            ps aux --sort=-%cpu | head -20
            echo ""
            read -p "Enter PID to kill: " -r PID
            if [ -n "$PID" ]; then
                ps -p "$PID" -o pid,user,comm 2>/dev/null && {
                    read -p "Kill this process? (y/N): " -r CONFIRM
                    if [[ $CONFIRM =~ ^[Yy]$ ]]; then
                        kill -9 "$PID" && log "Killed PID $PID" || log "Failed to kill PID $PID"
                    fi
                } || echo "PID not found"
            fi
            ;;

        2)
            banner "BLOCK IP ADDRESS"
            echo "Recent connections:"
            ss -tn 2>/dev/null | grep ESTAB | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10
            echo ""
            echo "Recent failed logins:"
            grep "Failed password" /var/log/auth.log 2>/dev/null | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -10
            echo ""
            read -p "Enter IP to block: " -r IP
            if [ -n "$IP" ]; then
                ufw deny from "$IP" to any comment "IR-blocked $(date +%Y%m%d_%H%M%S)"
                log "Blocked IP: $IP"
                echo -e "${GREEN}Blocked: $IP${NC}"
            fi
            ;;

        3)
            banner "LOCK USER ACCOUNT"
            echo "Users with login shells:"
            grep -E '/bin/(bash|sh|zsh)$' /etc/passwd | cut -d: -f1
            echo ""
            read -p "Enter username to lock: " -r USER
            if [ -n "$USER" ]; then
                usermod -L "$USER" && log "Locked user: $USER" && echo -e "${GREEN}Locked: $USER${NC}"
                usermod -s /sbin/nologin "$USER" 2>/dev/null && log "Disabled shell for: $USER"
            fi
            ;;

        4)
            banner "KILL USER SESSIONS"
            echo "Currently logged in:"
            who
            echo ""
            read -p "Enter username to kill sessions: " -r USER
            if [ -n "$USER" ]; then
                pkill -KILL -u "$USER" 2>/dev/null && log "Killed all sessions for: $USER" && echo -e "${GREEN}Sessions terminated for: $USER${NC}"
            fi
            ;;

        5)
            banner "CHECK FOR BACKDOORS"
            log "Running backdoor checks..."
            echo ""

            echo "=== Checking for reverse shells ==="
            ps aux | grep -E "(nc |ncat|netcat|bash -i|/dev/tcp|python.*socket)" | grep -v grep || echo "None found"

            echo ""
            echo "=== Checking for suspicious cron jobs ==="
            for user in $(cut -f1 -d: /etc/passwd); do
                CRON=$(crontab -l -u "$user" 2>/dev/null | grep -v "^#" | grep -v "^$")
                if [ -n "$CRON" ]; then
                    echo "User: $user"
                    echo "$CRON"
                    echo ""
                fi
            done

            echo "=== Checking /etc/cron.d ==="
            ls -la /etc/cron.d/

            echo ""
            echo "=== Checking for unusual SUID binaries ==="
            find /tmp /var/tmp /dev/shm -perm -4000 -type f 2>/dev/null || echo "None in tmp directories"

            echo ""
            echo "=== Checking for SSH backdoor keys ==="
            for dir in /root /home/*; do
                if [ -f "$dir/.ssh/authorized_keys" ]; then
                    COUNT=$(wc -l < "$dir/.ssh/authorized_keys")
                    echo "$dir/.ssh/authorized_keys: $COUNT keys"
                fi
            done

            echo ""
            echo "=== Checking /etc/passwd for new users ==="
            awk -F: '$3 >= 1000 {print $1, $3, $7}' /etc/passwd

            echo ""
            echo "=== Checking for modified system binaries ==="
            SUSPECT_BINS="/bin/sh /bin/bash /usr/bin/sudo /usr/bin/su /usr/bin/passwd"
            for bin in $SUSPECT_BINS; do
                if [ -f "$bin" ]; then
                    MTIME=$(stat -c %y "$bin" 2>/dev/null)
                    echo "$bin: $MTIME"
                fi
            done

            log "Backdoor check complete"
            ;;

        6)
            banner "EMERGENCY PASSWORD RESET"
            echo "Users with login shells:"
            grep -E '/bin/(bash|sh|zsh)$' /etc/passwd | cut -d: -f1
            echo ""
            read -p "Enter username: " -r USER
            if [ -n "$USER" ]; then
                NEW_PASS=$(openssl rand -base64 12 | tr -dc 'A-Za-z0-9' | head -c 16)
                echo "$USER:$NEW_PASS" | chpasswd && {
                    log "Password reset for: $USER"
                    echo -e "${GREEN}New password for $USER: $NEW_PASS${NC}"
                    echo "SAVE THIS PASSWORD!"
                }
            fi
            ;;

        7)
            banner "CAPTURE SYSTEM STATE"
            CAPTURE_DIR="$LOGDIR/capture_$(date +%Y%m%d_%H%M%S)"
            mkdir -p "$CAPTURE_DIR"
            log "Capturing system state to $CAPTURE_DIR"

            echo "Capturing processes..."
            ps auxf > "$CAPTURE_DIR/processes.txt" 2>/dev/null

            echo "Capturing network connections..."
            ss -tulnp > "$CAPTURE_DIR/listening.txt" 2>/dev/null
            ss -tnp > "$CAPTURE_DIR/connections.txt" 2>/dev/null

            echo "Capturing users..."
            who > "$CAPTURE_DIR/logged_in.txt" 2>/dev/null
            last -50 > "$CAPTURE_DIR/last_logins.txt" 2>/dev/null

            echo "Capturing cron..."
            cp -r /etc/cron.d "$CAPTURE_DIR/" 2>/dev/null || true
            crontab -l > "$CAPTURE_DIR/root_crontab.txt" 2>/dev/null || true

            echo "Capturing recent file changes..."
            find /etc -mmin -60 -type f > "$CAPTURE_DIR/etc_changes.txt" 2>/dev/null
            find /var/www -mmin -60 -type f > "$CAPTURE_DIR/www_changes.txt" 2>/dev/null

            echo "Capturing auth log tail..."
            tail -500 /var/log/auth.log > "$CAPTURE_DIR/auth_tail.txt" 2>/dev/null

            log "State captured to: $CAPTURE_DIR"
            echo -e "${GREEN}Capture complete: $CAPTURE_DIR${NC}"
            ;;

        8)
            banner "CHECK FOR WEBSHELLS"
            log "Scanning for webshells..."
            echo ""

            WEB_ROOT="/var/www"
            read -p "Web root [$WEB_ROOT]: " -r INPUT
            WEB_ROOT="${INPUT:-$WEB_ROOT}"

            echo "Scanning $WEB_ROOT for suspicious files..."
            echo ""

            echo "=== PHP files with dangerous functions ==="
            grep -rlE "(eval\s*\(|base64_decode|system\s*\(|exec\s*\(|passthru|shell_exec|assert\s*\(|\\\$_GET\[|curl_exec)" "$WEB_ROOT" --include="*.php" 2>/dev/null | head -20 || echo "None found"

            echo ""
            echo "=== Recently modified PHP files (last hour) ==="
            find "$WEB_ROOT" -name "*.php" -mmin -60 -type f 2>/dev/null | head -20 || echo "None found"

            echo ""
            echo "=== Files with suspicious names ==="
            find "$WEB_ROOT" -type f \( -name "*.php.txt" -o -name "*.phtml" -o -name "*shell*" -o -name "*c99*" -o -name "*r57*" -o -name "*b374k*" \) 2>/dev/null | head -20 || echo "None found"

            echo ""
            echo "=== PHP files in upload directories ==="
            find "$WEB_ROOT" -path "*/upload*" -name "*.php" 2>/dev/null | head -20 || echo "None found"
            find "$WEB_ROOT" -path "*/tmp*" -name "*.php" 2>/dev/null | head -20 || echo "None found"

            log "Webshell scan complete"
            ;;

        9)
            banner "RESTORE FROM BACKUP"
            echo "Available backups:"
            ls -la /root/ccdc-backups/ 2>/dev/null || echo "No backups found"
            echo ""
            echo "Restore options:"
            echo "  1) Restore SSH config"
            echo "  2) Restore user accounts"
            echo "  3) Restore web files"
            echo "  4) Restore MySQL config"
            echo "  0) Cancel"
            echo ""
            read -p "Select restore option: " -r RESTORE_OPT

            case $RESTORE_OPT in
                1)
                    read -p "Enter backup timestamp (e.g., 20240115_143022): " -r TS
                    if [ -d "/root/ccdc-backups/$TS/configs/ssh" ]; then
                        cp -a "/root/ccdc-backups/$TS/configs/ssh/"* /etc/ssh/
                        systemctl restart sshd
                        log "Restored SSH config from $TS"
                    else
                        echo "Backup not found"
                    fi
                    ;;
                2)
                    echo "WARNING: This will overwrite current user accounts!"
                    read -p "Enter backup timestamp: " -r TS
                    if [ -f "/root/ccdc-backups/$TS/users/passwd" ]; then
                        read -p "Confirm restore? (y/N): " -r CONFIRM
                        if [[ $CONFIRM =~ ^[Yy]$ ]]; then
                            cp "/root/ccdc-backups/$TS/users/passwd" /etc/passwd
                            cp "/root/ccdc-backups/$TS/users/shadow" /etc/shadow
                            log "Restored user accounts from $TS"
                        fi
                    fi
                    ;;
                *)
                    echo "Cancelled"
                    ;;
            esac
            ;;

        0)
            echo "Exiting incident response."
            log "IR session ended"
            exit 0
            ;;

        *)
            echo "Invalid option"
            ;;
    esac

    echo ""
    read -p "Press Enter to continue..."
done
