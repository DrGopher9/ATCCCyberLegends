#!/bin/bash
###############################################################################
# 01-backup-critical.sh - Emergency Backup Script
# Target: Ubuntu 24 E-Commerce Server (PrestaShop + MySQL)
# Purpose: Create backups BEFORE any modifications
# Run this FIRST before hardening!
###############################################################################

set -euo pipefail

BACKUP_ROOT="/root/ccdc-backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"

log() {
    echo "[$(date '+%H:%M:%S')] $1"
}

log "Starting critical backup process..."

mkdir -p "$BACKUP_DIR"/{configs,web,database,users}

# System configuration files
log "Backing up system configurations..."
cp -a /etc/passwd "$BACKUP_DIR/users/" 2>/dev/null || true
cp -a /etc/shadow "$BACKUP_DIR/users/" 2>/dev/null || true
cp -a /etc/group "$BACKUP_DIR/users/" 2>/dev/null || true
cp -a /etc/sudoers "$BACKUP_DIR/users/" 2>/dev/null || true
cp -a /etc/sudoers.d "$BACKUP_DIR/users/" 2>/dev/null || true

# SSH configs
log "Backing up SSH configuration..."
cp -a /etc/ssh "$BACKUP_DIR/configs/" 2>/dev/null || true
cp -a /root/.ssh "$BACKUP_DIR/configs/root_ssh" 2>/dev/null || true

# Backup all authorized_keys
for dir in /home/*; do
    if [ -d "$dir/.ssh" ]; then
        user=$(basename "$dir")
        mkdir -p "$BACKUP_DIR/users/${user}_ssh"
        cp -a "$dir/.ssh" "$BACKUP_DIR/users/${user}_ssh/" 2>/dev/null || true
    fi
done

# Web server configs
log "Backing up web server configuration..."
cp -a /etc/apache2 "$BACKUP_DIR/configs/" 2>/dev/null || true
cp -a /etc/nginx "$BACKUP_DIR/configs/" 2>/dev/null || true
cp -a /etc/php "$BACKUP_DIR/configs/" 2>/dev/null || true

# MySQL configs
log "Backing up MySQL configuration..."
cp -a /etc/mysql "$BACKUP_DIR/configs/" 2>/dev/null || true
cp -a /etc/my.cnf "$BACKUP_DIR/configs/" 2>/dev/null || true
cp -a /etc/my.cnf.d "$BACKUP_DIR/configs/" 2>/dev/null || true

# Firewall
log "Backing up firewall rules..."
iptables-save > "$BACKUP_DIR/configs/iptables.rules" 2>/dev/null || true
cp -a /etc/ufw "$BACKUP_DIR/configs/" 2>/dev/null || true

# Cron
log "Backing up cron configuration..."
cp -a /etc/crontab "$BACKUP_DIR/configs/" 2>/dev/null || true
cp -a /etc/cron.d "$BACKUP_DIR/configs/" 2>/dev/null || true
cp -a /var/spool/cron "$BACKUP_DIR/configs/user_crons" 2>/dev/null || true

# Web application files
log "Backing up web application..."
if [ -d "/var/www/html" ]; then
    tar czf "$BACKUP_DIR/web/www_html.tar.gz" -C /var/www html 2>/dev/null || true
fi
if [ -d "/var/www/prestashop" ]; then
    tar czf "$BACKUP_DIR/web/prestashop.tar.gz" -C /var/www prestashop 2>/dev/null || true
fi

# Find and backup PrestaShop config specifically
log "Backing up PrestaShop configuration..."
find /var/www -name "parameters.php" -exec cp {} "$BACKUP_DIR/web/" \; 2>/dev/null || true
find /var/www -name "settings.inc.php" -exec cp {} "$BACKUP_DIR/web/" \; 2>/dev/null || true

# MySQL database dump
log "Backing up MySQL databases..."
if command -v mysqldump &> /dev/null; then
    # Try without password first (socket auth), then prompt
    if mysqldump --all-databases > "$BACKUP_DIR/database/all_databases.sql" 2>/dev/null; then
        log "Database backup successful (socket auth)"
    else
        log "Database backup requires credentials - skipping automatic dump"
        echo "Run manually: mysqldump -u root -p --all-databases > $BACKUP_DIR/database/all_databases.sql"
    fi
fi

# Create manifest
log "Creating backup manifest..."
cat > "$BACKUP_DIR/MANIFEST.txt" << EOF
CCDC Backup Manifest
====================
Created: $(date)
Hostname: $(hostname)
Backup Location: $BACKUP_DIR

Contents:
- configs/     System configuration files
- web/         Web application files
- database/    Database dumps
- users/       User accounts and SSH keys

RESTORE INSTRUCTIONS:
---------------------
1. User accounts:
   cp $BACKUP_DIR/users/passwd /etc/passwd
   cp $BACKUP_DIR/users/shadow /etc/shadow

2. SSH config:
   cp -a $BACKUP_DIR/configs/ssh/* /etc/ssh/
   systemctl restart sshd

3. Web files:
   tar xzf $BACKUP_DIR/web/www_html.tar.gz -C /var/www/

4. Database:
   mysql < $BACKUP_DIR/database/all_databases.sql

5. Firewall:
   iptables-restore < $BACKUP_DIR/configs/iptables.rules
EOF

# Calculate backup size
BACKUP_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)

log "Backup complete!"
echo ""
echo "============================================"
echo "BACKUP SUMMARY"
echo "============================================"
echo "Location: $BACKUP_DIR"
echo "Size: $BACKUP_SIZE"
echo "Manifest: $BACKUP_DIR/MANIFEST.txt"
echo ""
echo "Contents:"
ls -la "$BACKUP_DIR/"
echo ""
echo "IMPORTANT: If database backup failed, run manually:"
echo "  mysqldump -u root -p --all-databases > $BACKUP_DIR/database/all_databases.sql"
