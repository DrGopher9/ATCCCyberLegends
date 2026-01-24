#!/bin/bash
###############################################################################
# 01-mail-backup.sh - Mail Server Backup Script
# Target: Linux Mail Server (Postfix + Dovecot)
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

log "Starting mail server backup..."

mkdir -p "$BACKUP_DIR"/{postfix,dovecot,ssl,users,system,aliases}

# System user files
log "Backing up system user files..."
cp -a /etc/passwd "$BACKUP_DIR/users/" 2>/dev/null || true
cp -a /etc/shadow "$BACKUP_DIR/users/" 2>/dev/null || true
cp -a /etc/group "$BACKUP_DIR/users/" 2>/dev/null || true
cp -a /etc/sudoers "$BACKUP_DIR/users/" 2>/dev/null || true
cp -a /etc/sudoers.d "$BACKUP_DIR/users/" 2>/dev/null || true

# SSH configuration
log "Backing up SSH configuration..."
cp -a /etc/ssh "$BACKUP_DIR/system/" 2>/dev/null || true
cp -a /root/.ssh "$BACKUP_DIR/system/root_ssh" 2>/dev/null || true

# Postfix configuration
log "Backing up Postfix configuration..."
cp -a /etc/postfix "$BACKUP_DIR/postfix/" 2>/dev/null || true
# Backup main.cf and master.cf explicitly
cp /etc/postfix/main.cf "$BACKUP_DIR/postfix/main.cf.backup" 2>/dev/null || true
cp /etc/postfix/master.cf "$BACKUP_DIR/postfix/master.cf.backup" 2>/dev/null || true
# Export current running config
postconf -n > "$BACKUP_DIR/postfix/postconf-n.txt" 2>/dev/null || true
postconf > "$BACKUP_DIR/postfix/postconf-all.txt" 2>/dev/null || true

# Dovecot configuration
log "Backing up Dovecot configuration..."
cp -a /etc/dovecot "$BACKUP_DIR/dovecot/" 2>/dev/null || true
# Export current running config
doveconf -n > "$BACKUP_DIR/dovecot/doveconf-n.txt" 2>/dev/null || true

# Mail aliases
log "Backing up mail aliases..."
cp /etc/aliases "$BACKUP_DIR/aliases/" 2>/dev/null || true
cp /etc/aliases.db "$BACKUP_DIR/aliases/" 2>/dev/null || true
# Virtual aliases if they exist
cp /etc/postfix/virtual* "$BACKUP_DIR/aliases/" 2>/dev/null || true
cp /etc/postfix/vmailbox* "$BACKUP_DIR/aliases/" 2>/dev/null || true

# SSL certificates
log "Backing up SSL certificates..."
CERT_FILE=$(postconf -h smtpd_tls_cert_file 2>/dev/null || echo "")
KEY_FILE=$(postconf -h smtpd_tls_key_file 2>/dev/null || echo "")
if [ -n "$CERT_FILE" ] && [ -f "$CERT_FILE" ]; then
    cp "$CERT_FILE" "$BACKUP_DIR/ssl/" 2>/dev/null || true
fi
if [ -n "$KEY_FILE" ] && [ -f "$KEY_FILE" ]; then
    cp "$KEY_FILE" "$BACKUP_DIR/ssl/" 2>/dev/null || true
fi
# Common certificate locations
cp -a /etc/ssl/certs/mail* "$BACKUP_DIR/ssl/" 2>/dev/null || true
cp -a /etc/ssl/private/mail* "$BACKUP_DIR/ssl/" 2>/dev/null || true
cp -a /etc/letsencrypt/live/* "$BACKUP_DIR/ssl/letsencrypt/" 2>/dev/null || true
cp -a /etc/pki/tls/certs/mail* "$BACKUP_DIR/ssl/" 2>/dev/null || true
cp -a /etc/pki/tls/private/mail* "$BACKUP_DIR/ssl/" 2>/dev/null || true

# SASL configuration
log "Backing up SASL configuration..."
cp -a /etc/sasl2 "$BACKUP_DIR/system/" 2>/dev/null || true
cp -a /etc/saslauthd.conf "$BACKUP_DIR/system/" 2>/dev/null || true

# Firewall rules
log "Backing up firewall rules..."
iptables-save > "$BACKUP_DIR/system/iptables.rules" 2>/dev/null || true
cp -a /etc/firewalld "$BACKUP_DIR/system/" 2>/dev/null || true
firewall-cmd --list-all > "$BACKUP_DIR/system/firewalld-rules.txt" 2>/dev/null || true

# Cron jobs
log "Backing up cron jobs..."
cp -a /etc/crontab "$BACKUP_DIR/system/" 2>/dev/null || true
cp -a /etc/cron.d "$BACKUP_DIR/system/" 2>/dev/null || true
crontab -l > "$BACKUP_DIR/system/root_crontab.txt" 2>/dev/null || true

# Mail queue snapshot
log "Capturing mail queue state..."
mailq > "$BACKUP_DIR/postfix/mailq_snapshot.txt" 2>/dev/null || true

# Create manifest
log "Creating backup manifest..."
cat > "$BACKUP_DIR/MANIFEST.txt" << EOF
CCDC Mail Server Backup Manifest
=================================
Created: $(date)
Hostname: $(hostname)
Backup Location: $BACKUP_DIR

Contents:
- postfix/      Postfix configuration and queue snapshot
- dovecot/      Dovecot configuration
- ssl/          SSL/TLS certificates
- users/        System user accounts
- aliases/      Mail aliases and virtual maps
- system/       SSH, firewall, cron, SASL

RESTORE INSTRUCTIONS:
---------------------
1. Postfix:
   cp -a $BACKUP_DIR/postfix/* /etc/postfix/
   postfix reload

2. Dovecot:
   cp -a $BACKUP_DIR/dovecot/* /etc/dovecot/
   systemctl restart dovecot

3. User accounts:
   cp $BACKUP_DIR/users/passwd /etc/passwd
   cp $BACKUP_DIR/users/shadow /etc/shadow

4. SSH config:
   cp -a $BACKUP_DIR/system/ssh/* /etc/ssh/
   systemctl restart sshd

5. Firewall (iptables):
   iptables-restore < $BACKUP_DIR/system/iptables.rules

6. Aliases:
   cp $BACKUP_DIR/aliases/aliases /etc/aliases
   newaliases
EOF

# Calculate backup size
BACKUP_SIZE=$(du -sh "$BACKUP_DIR" | cut -f1)

log "Backup complete!"
echo ""
echo "============================================"
echo "MAIL SERVER BACKUP SUMMARY"
echo "============================================"
echo "Location: $BACKUP_DIR"
echo "Size: $BACKUP_SIZE"
echo "Manifest: $BACKUP_DIR/MANIFEST.txt"
echo ""
echo "Contents:"
ls -la "$BACKUP_DIR/"
echo ""
echo "Postfix config backed up: $([ -f "$BACKUP_DIR/postfix/main.cf.backup" ] && echo 'Yes' || echo 'No')"
echo "Dovecot config backed up: $([ -d "$BACKUP_DIR/dovecot" ] && echo 'Yes' || echo 'No')"
