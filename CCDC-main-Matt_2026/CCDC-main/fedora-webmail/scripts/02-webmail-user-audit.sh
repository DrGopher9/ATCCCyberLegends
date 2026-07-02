#!/bin/bash
#===============================================================================
# CCDC Fedora Webmail/Apps - User Audit Script
# Target: Fedora Server with Webmail and Web Apps
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
echo "  CCDC Fedora Webmail User Audit"
echo -e "========================================${NC}"
echo ""

#===============================================================================
echo -e "${YELLOW}[*] System User Audit${NC}"
echo ""

echo -e "${CYAN}=== Users with Login Shells ===${NC}"
grep -v "nologin\|false" /etc/passwd | while IFS=':' read -r user x uid gid desc home shell; do
    if [ "$uid" -ge 1000 ] || [ "$uid" -eq 0 ]; then
        echo -e "  ${YELLOW}$user${NC} (UID: $uid) - $shell - $home"
    fi
done
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== Root Account Status ===${NC}"
passwd -S root 2>/dev/null || echo "Could not check root status"
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== Sudo Access ===${NC}"
echo "Users/groups with sudo privileges:"
grep -v "^#" /etc/sudoers 2>/dev/null | grep -E "ALL.*ALL" | head -15
echo ""

echo "Sudoers.d files:"
for f in /etc/sudoers.d/*; do
    if [ -f "$f" ]; then
        echo "  $f:"
        grep -v "^#" "$f" 2>/dev/null | grep -v "^$" | sed 's/^/    /'
    fi
done
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== SSH Authorized Keys ===${NC}"
for home in /home/* /root; do
    if [ -d "$home" ]; then
        user=$(basename "$home")
        if [ -f "$home/.ssh/authorized_keys" ]; then
            key_count=$(wc -l < "$home/.ssh/authorized_keys" 2>/dev/null || echo "0")
            if [ "$key_count" -gt 0 ]; then
                echo -e "  ${YELLOW}$user${NC}: $key_count key(s)"
                while read -r key; do
                    key_comment=$(echo "$key" | awk '{print $NF}')
                    echo "    - $key_comment"
                done < "$home/.ssh/authorized_keys"
            fi
        fi
    fi
done
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== Recently Modified User Files ===${NC}"
echo "Files modified in /etc in last 24 hours:"
find /etc -name "passwd" -o -name "shadow" -o -name "group" -o -name "sudoers" -mtime -1 2>/dev/null
echo ""

#===============================================================================
echo -e "${YELLOW}[*] Web Application User Audit${NC}"
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== Apache/Nginx Service User ===${NC}"
if id apache &>/dev/null; then
    echo "Apache user: apache"
    id apache
elif id nginx &>/dev/null; then
    echo "Nginx user: nginx"
    id nginx
elif id www-data &>/dev/null; then
    echo "Web user: www-data"
    id www-data
fi
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== Roundcube Users ===${NC}"
# Check Roundcube database for users
for path in /var/www/html/roundcube /var/www/roundcube /usr/share/roundcubemail; do
    if [ -f "$path/config/config.inc.php" ]; then
        echo "Roundcube config found at: $path"

        # Extract DB connection info
        db_dsn=$(grep "db_dsnw" "$path/config/config.inc.php" 2>/dev/null | head -1)
        echo "Database config: $db_dsn"

        # If SQLite
        if echo "$db_dsn" | grep -qi sqlite; then
            db_file=$(echo "$db_dsn" | grep -oP "sqlite:///\K[^'\"]+")
            if [ -f "$db_file" ]; then
                echo "SQLite users:"
                sqlite3 "$db_file" "SELECT username FROM users;" 2>/dev/null | head -20
            fi
        fi
    fi
done
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== MySQL/MariaDB Users ===${NC}"
if systemctl is-active mariadb &>/dev/null || systemctl is-active mysql &>/dev/null; then
    echo "Database users (requires password):"
    read -sp "Enter MySQL root password (or skip): " mysql_pass
    echo ""
    if [ -n "$mysql_pass" ]; then
        mysql -u root -p"$mysql_pass" -e "SELECT User, Host FROM mysql.user;" 2>/dev/null
    fi
fi
echo ""

#===============================================================================
echo -e "${YELLOW}[*] Suspicious Activity Check${NC}"
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== Web Shell Detection ===${NC}"
echo "Checking for potential web shells..."

# Common web shell patterns
WEBROOT="/var/www/html"
if [ -d "$WEBROOT" ]; then
    echo "Files with suspicious functions:"
    grep -rl "eval\|base64_decode\|shell_exec\|system\|passthru\|exec(" "$WEBROOT" 2>/dev/null | head -20
    echo ""

    echo "Recently modified PHP files (last 24h):"
    find "$WEBROOT" -name "*.php" -mtime -1 2>/dev/null | head -20
    echo ""

    echo "PHP files in upload directories:"
    find "$WEBROOT" -path "*upload*" -name "*.php" 2>/dev/null
    find "$WEBROOT" -path "*tmp*" -name "*.php" 2>/dev/null
fi
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== Suspicious Cron Jobs ===${NC}"
echo "Checking all user crontabs..."
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -l -u "$user" 2>/dev/null | grep -v "^#" | grep -v "^$" | while read -r line; do
        echo "  $user: $line"
    done
done
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== Failed Login Attempts ===${NC}"
echo "Recent failed logins:"
grep "Failed password" /var/log/secure 2>/dev/null | tail -15
echo ""

echo "Failed login summary by IP:"
grep "Failed password" /var/log/secure 2>/dev/null | \
    grep -oP "from \K[\d.]+" | sort | uniq -c | sort -rn | head -10
echo ""

#===============================================================================
echo -e "${YELLOW}[*] User Management Actions${NC}"
echo ""

echo "Options:"
echo "  1) Lock a user account"
echo "  2) Remove SSH authorized key"
echo "  3) Remove user from sudoers"
echo "  4) Check for web shells (detailed)"
echo "  5) Exit"
echo ""

read -p "Select action (1-5): " action

case $action in
    1)
        echo ""
        read -p "Enter username to lock: " lock_user
        if [ -n "$lock_user" ]; then
            usermod -L "$lock_user" 2>/dev/null && echo -e "${GREEN}[+] Locked: $lock_user${NC}"
            usermod -s /sbin/nologin "$lock_user" 2>/dev/null && echo -e "${GREEN}[+] Shell disabled: $lock_user${NC}"
            echo "[$(date)] Locked user: $lock_user" >> "$LOGDIR/user_changes.log"
        fi
        ;;
    2)
        echo ""
        read -p "Enter username: " ssh_user
        if [ "$ssh_user" = "root" ]; then
            keyfile="/root/.ssh/authorized_keys"
        else
            keyfile="/home/$ssh_user/.ssh/authorized_keys"
        fi
        if [ -f "$keyfile" ]; then
            echo "Current keys:"
            cat -n "$keyfile"
            read -p "Remove line (number or 'all'): " remove_line
            if [ "$remove_line" = "all" ]; then
                > "$keyfile"
                echo -e "${GREEN}[+] All keys removed${NC}"
            elif [ -n "$remove_line" ]; then
                sed -i "${remove_line}d" "$keyfile"
                echo -e "${GREEN}[+] Key removed${NC}"
            fi
            echo "[$(date)] Modified SSH keys for: $ssh_user" >> "$LOGDIR/user_changes.log"
        fi
        ;;
    3)
        echo ""
        read -p "Enter username to remove from sudo: " sudo_user
        if [ -n "$sudo_user" ]; then
            # Remove from wheel group
            gpasswd -d "$sudo_user" wheel 2>/dev/null && echo -e "${GREEN}[+] Removed from wheel group${NC}"
            # Check sudoers.d
            grep -l "$sudo_user" /etc/sudoers.d/* 2>/dev/null | while read -r f; do
                echo "Found in: $f"
            done
            echo "[$(date)] Removed sudo for: $sudo_user" >> "$LOGDIR/user_changes.log"
        fi
        ;;
    4)
        echo ""
        echo "Detailed web shell scan..."
        WEBROOT="/var/www/html"
        echo "Checking $WEBROOT for suspicious patterns..."

        # Extended detection
        grep -rn "eval\s*(" "$WEBROOT" 2>/dev/null | head -10
        grep -rn "base64_decode\s*(" "$WEBROOT" 2>/dev/null | head -10
        grep -rn "shell_exec\s*(" "$WEBROOT" 2>/dev/null | head -10
        grep -rn "\\$_GET\s*\\[.*\\]\s*(" "$WEBROOT" 2>/dev/null | head -10
        grep -rn "\\$_POST\s*\\[.*\\]\s*(" "$WEBROOT" 2>/dev/null | head -10
        grep -rn "assert\s*(" "$WEBROOT" 2>/dev/null | head -10

        echo ""
        echo "Files with suspicious permissions:"
        find "$WEBROOT" -type f -perm /111 -name "*.php" 2>/dev/null
        ;;
    5)
        echo "Exiting..."
        ;;
    *)
        echo "No action taken"
        ;;
esac

echo ""
echo -e "${GREEN}========================================"
echo "  User Audit Complete"
echo -e "========================================${NC}"
echo ""
