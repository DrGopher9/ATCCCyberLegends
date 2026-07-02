#!/bin/bash
###############################################################################
# 01-panos-backup.sh - Palo Alto Firewall Backup
# Target: Palo Alto VM (PAN-OS 11.x)
# Purpose: Backup firewall configuration BEFORE making changes
#
# Run this FIRST before any modifications!
###############################################################################

FIREWALL_IP="${1:-172.20.242.150}"
BACKUP_DIR="/Users/mattmccullough/Documents/CCDC/firewall/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "============================================"
echo "PALO ALTO FIREWALL BACKUP"
echo "============================================"
echo ""
echo "Firewall: $FIREWALL_IP"
echo "Backup Dir: $BACKUP_DIR"
echo ""

mkdir -p "$BACKUP_DIR"

cat << 'BACKUP_COMMANDS'
================================================================================
BACKUP COMMANDS - Run on PAN-OS CLI
================================================================================

#=============================================================================
# METHOD 1: EXPORT CONFIGURATION (Recommended)
#=============================================================================

# Save named configuration snapshot
save config to ccdc-backup-before-hardening

# List saved configurations
show config saved

# Export running config to a file (on the firewall)
scp export configuration from running-config.xml to <your-scp-server>:/path/

#=============================================================================
# METHOD 2: BACKUP VIA WEB GUI (Easiest)
#=============================================================================

# 1. Login to https://172.20.242.150
# 2. Go to: Device > Setup > Operations
# 3. Click "Export named configuration snapshot"
# 4. Select "running-config.xml"
# 5. Save the file locally

# Or: Export device state (includes all config + certificates)
# Device > Setup > Operations > Export device state

#=============================================================================
# METHOD 3: API EXPORT (If API is enabled)
#=============================================================================

# Get API key first (from browser):
# https://172.20.242.150/api/?type=keygen&user=admin&password=<password>

# Then export config:
# https://172.20.242.150/api/?type=export&category=configuration&key=<api-key>

#=============================================================================
# BACKUP TECH SUPPORT FILE (Comprehensive)
#=============================================================================

# Generate tech support file (includes logs, config, system state)
request tech-support dump

# This creates a file you can export via SCP or download from GUI

#=============================================================================
# VERIFY BACKUP
#=============================================================================

# List saved configurations
show config saved

# Compare running to saved
diff config running saved <backup-name>

BACKUP_COMMANDS

echo ""
echo "============================================"
echo "QUICK BACKUP VIA SSH"
echo "============================================"
echo ""
echo "Run this command to backup via SSH (if SCP is available):"
echo ""
echo "  ssh admin@$FIREWALL_IP 'show config running' > $BACKUP_DIR/running-config-$TIMESTAMP.txt"
echo ""

# Attempt SSH backup if available
read -p "Attempt SSH config backup now? (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    read -p "Enter admin password: " -rs ADMIN_PASS
    echo ""

    echo "Backing up running config..."
    sshpass -p "$ADMIN_PASS" ssh -o StrictHostKeyChecking=no "admin@$FIREWALL_IP" \
        "show config running" > "$BACKUP_DIR/running-config-$TIMESTAMP.txt" 2>/dev/null

    if [ $? -eq 0 ]; then
        echo "Backup saved to: $BACKUP_DIR/running-config-$TIMESTAMP.txt"
    else
        echo "SSH backup failed. Use web GUI method instead."
    fi
fi

echo ""
echo "============================================"
echo "BACKUP CHECKLIST"
echo "============================================"
echo ""
echo "[ ] Save named config: save config to ccdc-backup"
echo "[ ] Export via GUI: Device > Setup > Operations > Export"
echo "[ ] Verify backup: show config saved"
echo "[ ] Document current admin accounts"
echo "[ ] Screenshot current security policy rules"
echo ""
echo "IMPORTANT: Do NOT proceed with hardening until backup is confirmed!"
