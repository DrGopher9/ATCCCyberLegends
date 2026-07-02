#!/bin/bash
#===============================================================================
# CCDC Fedora Webmail/Apps - Backup Script
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

BACKUP_DIR="/opt/ccdc-backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/backup_$TIMESTAMP"

echo -e "${CYAN}========================================"
echo "  CCDC Fedora Webmail Backup"
echo -e "========================================${NC}"
echo ""

mkdir -p "$BACKUP_PATH"

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Backing up system configuration...${NC}"

mkdir -p "$BACKUP_PATH/system"

# User/group files
cp /etc/passwd "$BACKUP_PATH/system/"
cp /etc/shadow "$BACKUP_PATH/system/"
cp /etc/group "$BACKUP_PATH/system/"
chmod 600 "$BACKUP_PATH/system/shadow"
echo "    [+] User/group files"

# SSH config
cp -r /etc/ssh "$BACKUP_PATH/system/" 2>/dev/null
cp -r /root/.ssh "$BACKUP_PATH/system/root_ssh" 2>/dev/null
echo "    [+] SSH configuration"

# Sudoers
cp /etc/sudoers "$BACKUP_PATH/system/" 2>/dev/null
cp -r /etc/sudoers.d "$BACKUP_PATH/system/" 2>/dev/null
echo "    [+] Sudoers"

# Crontabs
crontab -l > "$BACKUP_PATH/system/root_crontab" 2>/dev/null
cp -r /etc/cron.d "$BACKUP_PATH/system/" 2>/dev/null
echo "    [+] Cron jobs"

# Firewall
firewall-cmd --list-all > "$BACKUP_PATH/system/firewalld_rules.txt" 2>/dev/null
iptables-save > "$BACKUP_PATH/system/iptables.rules" 2>/dev/null
echo "    [+] Firewall rules"

# SELinux
if command -v getsebool &>/dev/null; then
    getsebool -a > "$BACKUP_PATH/system/selinux_booleans.txt" 2>/dev/null
fi
echo "    [+] SELinux settings"

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Backing up web server configuration...${NC}"

mkdir -p "$BACKUP_PATH/webserver"

# Apache
if [ -d /etc/httpd ]; then
    cp -r /etc/httpd "$BACKUP_PATH/webserver/"
    echo "    [+] Apache (httpd) configuration"
fi

# Nginx
if [ -d /etc/nginx ]; then
    cp -r /etc/nginx "$BACKUP_PATH/webserver/"
    echo "    [+] Nginx configuration"
fi

# PHP
if [ -d /etc/php.d ]; then
    cp -r /etc/php.d "$BACKUP_PATH/webserver/"
fi
if [ -f /etc/php.ini ]; then
    cp /etc/php.ini "$BACKUP_PATH/webserver/"
fi
echo "    [+] PHP configuration"

# SSL certificates
mkdir -p "$BACKUP_PATH/ssl"
cp -r /etc/pki/tls "$BACKUP_PATH/ssl/" 2>/dev/null
cp -r /etc/letsencrypt "$BACKUP_PATH/ssl/" 2>/dev/null
echo "    [+] SSL certificates"

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Backing up webmail applications...${NC}"

mkdir -p "$BACKUP_PATH/webapps"

# Find and backup Roundcube
for path in /var/www/html/roundcube /var/www/roundcube /usr/share/roundcubemail /var/www/html/roundcubemail; do
    if [ -d "$path" ]; then
        echo "    [*] Found Roundcube at $path"
        # Backup config only (not entire app)
        mkdir -p "$BACKUP_PATH/webapps/roundcube"
        cp -r "$path/config" "$BACKUP_PATH/webapps/roundcube/" 2>/dev/null
        cp -r "$path/plugins" "$BACKUP_PATH/webapps/roundcube/" 2>/dev/null
        echo "    [+] Roundcube configuration"
    fi
done

# Find and backup SquirrelMail
for path in /var/www/html/squirrelmail /usr/share/squirrelmail; do
    if [ -d "$path" ]; then
        mkdir -p "$BACKUP_PATH/webapps/squirrelmail"
        cp -r "$path/config" "$BACKUP_PATH/webapps/squirrelmail/" 2>/dev/null
        echo "    [+] SquirrelMail configuration"
    fi
done

# Backup entire web root (compressed)
if [ -d /var/www/html ]; then
    tar -czf "$BACKUP_PATH/webapps/www_html.tar.gz" -C /var/www html 2>/dev/null
    echo "    [+] Web root (/var/www/html)"
fi

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Backing up mail server configuration...${NC}"

mkdir -p "$BACKUP_PATH/mail"

# Postfix
if [ -d /etc/postfix ]; then
    cp -r /etc/postfix "$BACKUP_PATH/mail/"
    echo "    [+] Postfix configuration"
fi

# Dovecot
if [ -d /etc/dovecot ]; then
    cp -r /etc/dovecot "$BACKUP_PATH/mail/"
    echo "    [+] Dovecot configuration"
fi

# Mail aliases
cp /etc/aliases "$BACKUP_PATH/mail/" 2>/dev/null
echo "    [+] Mail aliases"

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Backing up database...${NC}"

mkdir -p "$BACKUP_PATH/database"

# MariaDB/MySQL
if systemctl is-active mariadb &>/dev/null || systemctl is-active mysql &>/dev/null; then
    echo "    [*] MariaDB/MySQL detected"
    read -p "    Enter MySQL root password (or skip): " mysql_pass
    if [ -n "$mysql_pass" ]; then
        # Dump all databases
        mysqldump -u root -p"$mysql_pass" --all-databases > "$BACKUP_PATH/database/all_databases.sql" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "    [+] All databases backed up"
        else
            echo "    [-] Database backup failed"
        fi

        # Backup MySQL users
        mysql -u root -p"$mysql_pass" -e "SELECT User, Host FROM mysql.user;" > "$BACKUP_PATH/database/mysql_users.txt" 2>/dev/null
    fi
fi

# SQLite databases
find /var -name "*.db" -o -name "*.sqlite" 2>/dev/null | while read dbfile; do
    cp "$dbfile" "$BACKUP_PATH/database/" 2>/dev/null
    echo "    [+] SQLite: $dbfile"
done

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Creating backup manifest...${NC}"

cat > "$BACKUP_PATH/MANIFEST.txt" << EOF
CCDC Fedora Webmail Backup Manifest
====================================
Timestamp: $(date)
Hostname: $(hostname)
Backup Path: $BACKUP_PATH

Contents:
- system/         : System configuration (users, SSH, sudo, firewall)
- webserver/      : Apache/Nginx and PHP configuration
- ssl/            : SSL/TLS certificates
- webapps/        : Webmail application configurations
- mail/           : Postfix/Dovecot configuration
- database/       : Database dumps

Restore Notes:
1. Stop services before restoring
2. Restore configs to original locations
3. Fix ownership: chown -R apache:apache /var/www/html
4. Restore SELinux contexts: restorecon -Rv /var/www
5. Restart services

EOF

#-------------------------------------------------------------------------------
# Set permissions
chmod -R 700 "$BACKUP_PATH"

BACKUP_SIZE=$(du -sh "$BACKUP_PATH" | cut -f1)

echo ""
echo -e "${GREEN}========================================"
echo "  Backup Complete"
echo -e "========================================${NC}"
echo ""
echo "Backup Location: $BACKUP_PATH"
echo "Backup Size: $BACKUP_SIZE"
echo ""
echo "Contents:"
ls -la "$BACKUP_PATH"
echo ""
echo -e "${CYAN}To create archive:${NC}"
echo "  tar -czf webmail_backup_$TIMESTAMP.tar.gz -C $BACKUP_DIR backup_$TIMESTAMP"
echo ""
