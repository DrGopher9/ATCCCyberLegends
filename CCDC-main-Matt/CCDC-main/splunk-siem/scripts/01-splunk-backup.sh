#!/bin/bash
#===============================================================================
# CCDC Splunk SIEM - Backup Script
# Target: Splunk Enterprise on Linux
# Run as: root
#===============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

BACKUP_DIR="/opt/splunk-ccdc-backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/backup_$TIMESTAMP"

echo -e "${CYAN}========================================"
echo "  CCDC Splunk SIEM Backup"
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
    echo -e "${RED}[!] Splunk installation not found${NC}"
    read -p "Enter Splunk installation path: " SPLUNK_HOME
fi

echo "Splunk Home: $SPLUNK_HOME"
echo "Backup Path: $BACKUP_PATH"
echo ""

mkdir -p "$BACKUP_PATH"

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Backing up Splunk configuration...${NC}"

# Backup entire etc directory (all configs)
if [ -d "$SPLUNK_HOME/etc" ]; then
    tar -czf "$BACKUP_PATH/splunk_etc.tar.gz" -C "$SPLUNK_HOME" etc 2>/dev/null
    echo -e "${GREEN}    [+] etc/ directory backed up${NC}"
fi

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Backing up specific configuration files...${NC}"

mkdir -p "$BACKUP_PATH/configs"

# Key configuration files
CONFIG_FILES=(
    "etc/system/local/server.conf"
    "etc/system/local/web.conf"
    "etc/system/local/inputs.conf"
    "etc/system/local/outputs.conf"
    "etc/system/local/authentication.conf"
    "etc/system/local/authorize.conf"
    "etc/system/local/indexes.conf"
    "etc/system/local/limits.conf"
    "etc/system/local/props.conf"
    "etc/system/local/transforms.conf"
    "etc/system/local/deploymentclient.conf"
    "etc/system/local/serverclass.conf"
    "etc/passwd"
)

for file in "${CONFIG_FILES[@]}"; do
    if [ -f "$SPLUNK_HOME/$file" ]; then
        dir=$(dirname "$file")
        mkdir -p "$BACKUP_PATH/configs/$dir"
        cp "$SPLUNK_HOME/$file" "$BACKUP_PATH/configs/$file"
        echo "    [+] Backed up: $file"
    fi
done

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Backing up Splunk apps...${NC}"

if [ -d "$SPLUNK_HOME/etc/apps" ]; then
    tar -czf "$BACKUP_PATH/splunk_apps.tar.gz" -C "$SPLUNK_HOME/etc" apps 2>/dev/null
    echo -e "${GREEN}    [+] Apps directory backed up${NC}"

    # Also list apps for reference
    ls -la "$SPLUNK_HOME/etc/apps/" > "$BACKUP_PATH/apps_list.txt"
fi

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Backing up SSL certificates...${NC}"

if [ -d "$SPLUNK_HOME/etc/auth" ]; then
    tar -czf "$BACKUP_PATH/splunk_auth.tar.gz" -C "$SPLUNK_HOME/etc" auth 2>/dev/null
    echo -e "${GREEN}    [+] SSL/auth directory backed up${NC}"
fi

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Backing up user-seed.conf (initial password)...${NC}"

if [ -f "$SPLUNK_HOME/etc/system/local/user-seed.conf" ]; then
    cp "$SPLUNK_HOME/etc/system/local/user-seed.conf" "$BACKUP_PATH/configs/"
    echo -e "${GREEN}    [+] user-seed.conf backed up${NC}"
fi

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Backing up deployment apps (if deployment server)...${NC}"

if [ -d "$SPLUNK_HOME/etc/deployment-apps" ]; then
    tar -czf "$BACKUP_PATH/deployment_apps.tar.gz" -C "$SPLUNK_HOME/etc" deployment-apps 2>/dev/null
    echo -e "${GREEN}    [+] Deployment apps backed up${NC}"
fi

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Exporting Splunk KV stores (if any)...${NC}"

mkdir -p "$BACKUP_PATH/kvstore"
if [ -d "$SPLUNK_HOME/var/lib/splunk/kvstore" ]; then
    cp -r "$SPLUNK_HOME/var/lib/splunk/kvstore" "$BACKUP_PATH/" 2>/dev/null
    echo -e "${GREEN}    [+] KV Store backed up${NC}"
fi

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Backing up saved searches and dashboards...${NC}"

mkdir -p "$BACKUP_PATH/knowledge"

# Find all savedsearches.conf files
find "$SPLUNK_HOME/etc" -name "savedsearches.conf" -exec cp --parents {} "$BACKUP_PATH/knowledge/" \; 2>/dev/null
echo "    [+] Saved searches backed up"

# Find all dashboard XML files
find "$SPLUNK_HOME/etc/apps" -name "*.xml" -path "*/data/ui/views/*" -exec cp --parents {} "$BACKUP_PATH/knowledge/" \; 2>/dev/null
echo "    [+] Dashboards backed up"

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Backing up system configuration...${NC}"

mkdir -p "$BACKUP_PATH/system"

# SSH config
cp /etc/ssh/sshd_config "$BACKUP_PATH/system/" 2>/dev/null && echo "    [+] SSH config"

# Users and groups
cp /etc/passwd "$BACKUP_PATH/system/passwd.bak" 2>/dev/null
cp /etc/shadow "$BACKUP_PATH/system/shadow.bak" 2>/dev/null
cp /etc/group "$BACKUP_PATH/system/group.bak" 2>/dev/null
echo "    [+] User/group files"

# Sudoers
cp /etc/sudoers "$BACKUP_PATH/system/" 2>/dev/null
cp -r /etc/sudoers.d "$BACKUP_PATH/system/" 2>/dev/null
echo "    [+] Sudoers"

# Crontabs
crontab -l > "$BACKUP_PATH/system/root_crontab.bak" 2>/dev/null
crontab -u splunk -l > "$BACKUP_PATH/system/splunk_crontab.bak" 2>/dev/null
echo "    [+] Crontabs"

# Firewall rules
if command -v ufw &>/dev/null; then
    ufw status verbose > "$BACKUP_PATH/system/ufw_rules.bak" 2>/dev/null
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --list-all > "$BACKUP_PATH/system/firewalld_rules.bak" 2>/dev/null
fi
iptables-save > "$BACKUP_PATH/system/iptables.bak" 2>/dev/null
echo "    [+] Firewall rules"

# Splunk systemd service
cp /etc/systemd/system/Splunkd.service "$BACKUP_PATH/system/" 2>/dev/null
cp /etc/systemd/system/splunk.service "$BACKUP_PATH/system/" 2>/dev/null
cp /etc/init.d/splunk "$BACKUP_PATH/system/" 2>/dev/null
echo "    [+] Splunk service files"

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Recording current Splunk state...${NC}"

SPLUNK_CMD="$SPLUNK_HOME/bin/splunk"

if [ -x "$SPLUNK_CMD" ]; then
    # Get current settings
    $SPLUNK_CMD btool server list > "$BACKUP_PATH/btool_server.txt" 2>/dev/null
    $SPLUNK_CMD btool web list > "$BACKUP_PATH/btool_web.txt" 2>/dev/null
    $SPLUNK_CMD btool inputs list > "$BACKUP_PATH/btool_inputs.txt" 2>/dev/null
    $SPLUNK_CMD btool outputs list > "$BACKUP_PATH/btool_outputs.txt" 2>/dev/null
    $SPLUNK_CMD btool authentication list > "$BACKUP_PATH/btool_auth.txt" 2>/dev/null
    echo -e "${GREEN}    [+] btool outputs saved${NC}"

    # List indexes
    $SPLUNK_CMD list index > "$BACKUP_PATH/index_list.txt" 2>/dev/null
    echo "    [+] Index list saved"
fi

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Creating backup manifest...${NC}"

cat > "$BACKUP_PATH/MANIFEST.txt" << EOF
CCDC Splunk Backup Manifest
============================
Timestamp: $(date)
Splunk Home: $SPLUNK_HOME
Hostname: $(hostname)

Contents:
- splunk_etc.tar.gz     : Complete etc/ directory
- splunk_apps.tar.gz    : All installed apps
- splunk_auth.tar.gz    : SSL certificates and auth files
- configs/              : Individual config files
- knowledge/            : Saved searches and dashboards
- system/               : OS-level configs (SSH, users, firewall)
- kvstore/              : KV Store data

Restore Instructions:
1. Stop Splunk: $SPLUNK_HOME/bin/splunk stop
2. Backup current configs (just in case)
3. Extract: tar -xzf splunk_etc.tar.gz -C $SPLUNK_HOME
4. Fix permissions: chown -R splunk:splunk $SPLUNK_HOME/etc
5. Start Splunk: $SPLUNK_HOME/bin/splunk start

EOF

echo -e "${GREEN}    [+] Manifest created${NC}"

#-------------------------------------------------------------------------------
# Set permissions
chmod 600 "$BACKUP_PATH/system/shadow.bak" 2>/dev/null
chmod -R 700 "$BACKUP_PATH"

# Calculate backup size
BACKUP_SIZE=$(du -sh "$BACKUP_PATH" | cut -f1)

echo ""
echo -e "${GREEN}========================================"
echo "  Backup Complete"
echo -e "========================================${NC}"
echo ""
echo -e "${YELLOW}Backup Location: $BACKUP_PATH${NC}"
echo "Backup Size: $BACKUP_SIZE"
echo ""
echo "Contents:"
ls -la "$BACKUP_PATH"
echo ""
echo -e "${CYAN}To create an archive:${NC}"
echo "  tar -czf splunk_backup_$TIMESTAMP.tar.gz -C $BACKUP_DIR backup_$TIMESTAMP"
echo ""
