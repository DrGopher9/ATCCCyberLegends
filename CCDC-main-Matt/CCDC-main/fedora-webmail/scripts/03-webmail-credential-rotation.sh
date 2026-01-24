#!/bin/bash
#===============================================================================
# CCDC Fedora Webmail/Apps - Credential Rotation Script
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
CRED_FILE="$LOGDIR/CREDENTIALS_$(date +%Y%m%d_%H%M%S).txt"

touch "$CRED_FILE"
chmod 600 "$CRED_FILE"

echo -e "${CYAN}========================================"
echo "  CCDC Fedora Credential Rotation"
echo -e "========================================${NC}"
echo ""

# Password generator
generate_password() {
    < /dev/urandom tr -dc 'A-Za-z0-9!@#$%^&*' | head -c 20
    echo ""
}

# Start credentials file
cat >> "$CRED_FILE" << EOF
================================================================================
CCDC FEDORA WEBMAIL CREDENTIALS - $(date)
================================================================================
Hostname: $(hostname)
================================================================================

EOF

echo -e "${RED}[!] IMPORTANT: Back up configurations before rotating credentials!${NC}"
echo ""

#===============================================================================
echo -e "${YELLOW}=== Linux Root Password ===${NC}"
echo ""

read -p "Change root password? (y/N): " change_root
if [ "$change_root" = "y" ]; then
    NEW_ROOT_PASS=$(generate_password)

    echo "$NEW_ROOT_PASS" | passwd --stdin root 2>/dev/null || \
    echo "root:$NEW_ROOT_PASS" | chpasswd

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[+] Root password changed${NC}"
        cat >> "$CRED_FILE" << EOF
LINUX ROOT
----------
Username: root
Password: $NEW_ROOT_PASS

EOF
    else
        echo -e "${RED}[-] Failed to change root password${NC}"
    fi
fi

#===============================================================================
echo ""
echo -e "${YELLOW}=== Linux User Passwords ===${NC}"
echo ""

echo "Users with login shells:"
grep -v "nologin\|false" /etc/passwd | awk -F: '$3 >= 1000 {print "  " $1}'
echo ""

read -p "Change password for a user? (enter username or skip): " linux_user
while [ -n "$linux_user" ]; do
    if id "$linux_user" &>/dev/null; then
        NEW_USER_PASS=$(generate_password)

        echo "$NEW_USER_PASS" | passwd --stdin "$linux_user" 2>/dev/null || \
        echo "$linux_user:$NEW_USER_PASS" | chpasswd

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+] Password changed for: $linux_user${NC}"
            cat >> "$CRED_FILE" << EOF
LINUX USER: $linux_user
-----------------------
Username: $linux_user
Password: $NEW_USER_PASS

EOF
        fi
    else
        echo -e "${RED}User not found${NC}"
    fi

    read -p "Change password for another user? (enter username or skip): " linux_user
done

#===============================================================================
echo ""
echo -e "${YELLOW}=== MySQL/MariaDB Credentials ===${NC}"
echo ""

if systemctl is-active mariadb &>/dev/null || systemctl is-active mysql &>/dev/null; then
    read -p "Change MySQL root password? (y/N): " change_mysql
    if [ "$change_mysql" = "y" ]; then
        read -sp "Enter CURRENT MySQL root password: " current_mysql
        echo ""

        NEW_MYSQL_PASS=$(generate_password)

        # Change MySQL root password
        mysql -u root -p"$current_mysql" -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$NEW_MYSQL_PASS';" 2>/dev/null || \
        mysql -u root -p"$current_mysql" -e "SET PASSWORD FOR 'root'@'localhost' = PASSWORD('$NEW_MYSQL_PASS');" 2>/dev/null

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+] MySQL root password changed${NC}"
            cat >> "$CRED_FILE" << EOF
MYSQL ROOT
----------
Username: root
Password: $NEW_MYSQL_PASS

EOF
            # Update current password for subsequent operations
            current_mysql="$NEW_MYSQL_PASS"
        else
            echo -e "${RED}[-] Failed to change MySQL root password${NC}"
        fi
    fi

    # Other MySQL users
    echo ""
    echo "Other MySQL users:"
    mysql -u root -p"$current_mysql" -e "SELECT User, Host FROM mysql.user WHERE User != 'root';" 2>/dev/null

    read -p "Change password for MySQL user? (enter username or skip): " mysql_user
    while [ -n "$mysql_user" ]; do
        NEW_MYSQL_USER_PASS=$(generate_password)

        mysql -u root -p"$current_mysql" -e "ALTER USER '$mysql_user'@'localhost' IDENTIFIED BY '$NEW_MYSQL_USER_PASS';" 2>/dev/null || \
        mysql -u root -p"$current_mysql" -e "SET PASSWORD FOR '$mysql_user'@'localhost' = PASSWORD('$NEW_MYSQL_USER_PASS');" 2>/dev/null

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+] Password changed for MySQL user: $mysql_user${NC}"
            cat >> "$CRED_FILE" << EOF
MYSQL USER: $mysql_user
-----------------------
Username: $mysql_user
Password: $NEW_MYSQL_USER_PASS

EOF
        else
            echo -e "${RED}[-] Failed to change password${NC}"
        fi

        read -p "Change password for another MySQL user? (enter username or skip): " mysql_user
    done
fi

#===============================================================================
echo ""
echo -e "${YELLOW}=== Roundcube Database Password ===${NC}"
echo ""

# Find Roundcube config
for path in /var/www/html/roundcube /var/www/roundcube /usr/share/roundcubemail /var/www/html/roundcubemail; do
    if [ -f "$path/config/config.inc.php" ]; then
        echo "Roundcube config found: $path/config/config.inc.php"

        # Show current DB config
        grep "db_dsnw" "$path/config/config.inc.php" 2>/dev/null

        echo ""
        echo -e "${YELLOW}[!] If using MySQL, update Roundcube config after changing DB password:${NC}"
        echo "    Edit: $path/config/config.inc.php"
        echo '    $config["db_dsnw"] = "mysql://roundcube:NEWPASS@localhost/roundcubemail";'

        cat >> "$CRED_FILE" << EOF
ROUNDCUBE CONFIG
----------------
Config File: $path/config/config.inc.php
Note: Update db_dsnw with new database password if changed

EOF
        break
    fi
done

#===============================================================================
echo ""
echo -e "${YELLOW}=== Webmail Admin Account ===${NC}"
echo ""

echo "To reset Roundcube user passwords, connect to the database:"
echo "  mysql -u root -p roundcubemail"
echo "  UPDATE users SET password = '' WHERE username = 'USER';"
echo "  (User will need to use IMAP password)"
echo ""

#===============================================================================
echo ""
echo -e "${YELLOW}=== Application Config Passwords ===${NC}"
echo ""

# Check for other config files with passwords
echo "Searching for config files with passwords..."

CONFIG_LOCATIONS=(
    "/var/www/html"
    "/etc/roundcubemail"
    "/etc/squirrelmail"
)

for loc in "${CONFIG_LOCATIONS[@]}"; do
    if [ -d "$loc" ]; then
        grep -rl "password\|passwd\|pass" "$loc" 2>/dev/null | grep -E "\.(php|conf|ini|cfg)$" | head -10 | while read -r f; do
            echo "  Config file with password: $f"
        done
    fi
done

cat >> "$CRED_FILE" << EOF

APPLICATION CONFIGS
-------------------
Check these files for hardcoded passwords:
$(find /var/www -name "config*.php" 2>/dev/null | head -10)

EOF

#===============================================================================
echo ""
echo -e "${GREEN}========================================"
echo "  Credential Rotation Complete"
echo -e "========================================${NC}"
echo ""

# Finalize credentials file
cat >> "$CRED_FILE" << EOF
================================================================================
END OF CREDENTIALS - $(date)
================================================================================
DELETE THIS FILE AFTER SECURELY RECORDING PASSWORDS
================================================================================
EOF

echo -e "${RED}========================================"
echo "  CREDENTIALS SAVED TO:"
echo "  $CRED_FILE"
echo -e "========================================${NC}"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC}"
echo "  1. Record these credentials securely"
echo "  2. Delete the credentials file"
echo "  3. Update application configs with new passwords"
echo "  4. Restart services: systemctl restart httpd mariadb"
echo "  5. Test web application login"
echo ""
