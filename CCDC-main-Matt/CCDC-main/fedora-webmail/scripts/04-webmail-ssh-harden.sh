#!/bin/bash
#===============================================================================
# CCDC Fedora Webmail/Apps - SSH Hardening Script
# Target: Fedora Server
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
mkdir -p "$BACKUP_DIR"

echo -e "${CYAN}========================================"
echo "  CCDC Fedora SSH Hardening"
echo -e "========================================${NC}"
echo ""

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Backing up SSH configuration...${NC}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.bak.$TIMESTAMP"
echo -e "${GREEN}    [+] Backup: $BACKUP_DIR/sshd_config.bak.$TIMESTAMP${NC}"
echo ""

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Current SSH Configuration:${NC}"
grep -E "^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|MaxAuthTries)" /etc/ssh/sshd_config 2>/dev/null || echo "  Using defaults"
echo ""

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Applying SSH Hardening...${NC}"

SSHD_CONFIG="/etc/ssh/sshd_config"

set_ssh_config() {
    local key="$1"
    local value="$2"
    if grep -q "^${key}" "$SSHD_CONFIG"; then
        sed -i "s/^${key}.*/${key} ${value}/" "$SSHD_CONFIG"
    elif grep -q "^#${key}" "$SSHD_CONFIG"; then
        sed -i "s/^#${key}.*/${key} ${value}/" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
}

# Root login
read -p "Disable root SSH login? (y/N): " disable_root
if [ "$disable_root" = "y" ]; then
    set_ssh_config "PermitRootLogin" "no"
    echo -e "${GREEN}    [+] Root login disabled${NC}"
else
    set_ssh_config "PermitRootLogin" "prohibit-password"
    echo -e "${GREEN}    [+] Root login: key-only${NC}"
fi

# Password authentication
read -p "Disable password authentication (key-only)? (y/N): " disable_pass
if [ "$disable_pass" = "y" ]; then
    set_ssh_config "PasswordAuthentication" "no"
    echo -e "${GREEN}    [+] Password authentication disabled${NC}"
else
    set_ssh_config "PasswordAuthentication" "yes"
    echo -e "${YELLOW}    [!] Password authentication enabled${NC}"
fi

# Standard hardening options
set_ssh_config "PubkeyAuthentication" "yes"
echo -e "${GREEN}    [+] Public key authentication enabled${NC}"

set_ssh_config "MaxAuthTries" "3"
echo -e "${GREEN}    [+] Max auth tries: 3${NC}"

set_ssh_config "PermitEmptyPasswords" "no"
echo -e "${GREEN}    [+] Empty passwords disabled${NC}"

set_ssh_config "X11Forwarding" "no"
echo -e "${GREEN}    [+] X11 forwarding disabled${NC}"

set_ssh_config "LoginGraceTime" "60"
echo -e "${GREEN}    [+] Login grace time: 60s${NC}"

set_ssh_config "ClientAliveInterval" "300"
set_ssh_config "ClientAliveCountMax" "2"
echo -e "${GREEN}    [+] Client alive settings configured${NC}"

set_ssh_config "Protocol" "2"
echo -e "${GREEN}    [+] SSH Protocol 2 only${NC}"

#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[*] Configure allowed users...${NC}"

read -p "Restrict SSH to specific users? (y/N): " restrict_users
if [ "$restrict_users" = "y" ]; then
    echo "Users with login shells:"
    grep -v "nologin\|false" /etc/passwd | cut -d: -f1
    echo ""
    read -p "Enter allowed users (space-separated): " allowed_users
    if [ -n "$allowed_users" ]; then
        sed -i '/^AllowUsers/d' "$SSHD_CONFIG"
        echo "AllowUsers $allowed_users" >> "$SSHD_CONFIG"
        echo -e "${GREEN}    [+] Allowed users: $allowed_users${NC}"
    fi
fi

#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[*] SSH Banner...${NC}"

read -p "Set SSH warning banner? (y/N): " set_banner
if [ "$set_banner" = "y" ]; then
    cat > /etc/ssh/banner << 'EOF'
================================================================================
                        AUTHORIZED ACCESS ONLY
================================================================================
All activity is monitored and logged. Unauthorized access is prohibited.
================================================================================
EOF
    set_ssh_config "Banner" "/etc/ssh/banner"
    echo -e "${GREEN}    [+] SSH banner configured${NC}"
fi

#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[*] Validating SSH configuration...${NC}"

sshd -t 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}    [+] SSH configuration valid${NC}"
else
    echo -e "${RED}    [-] SSH configuration has errors!${NC}"
    echo "Restoring backup..."
    cp "$BACKUP_DIR/sshd_config.bak.$TIMESTAMP" /etc/ssh/sshd_config
    exit 1
fi

#-------------------------------------------------------------------------------
echo ""
echo -e "${RED}[!] Keep this session open while testing SSH!${NC}"
read -p "Restart SSH now? (y/N): " restart_ssh
if [ "$restart_ssh" = "y" ]; then
    systemctl restart sshd
    echo -e "${GREEN}    [+] SSH service restarted${NC}"
fi

echo ""
echo -e "${GREEN}========================================"
echo "  SSH Hardening Complete"
echo -e "========================================${NC}"
echo ""
echo -e "${RED}TEST SSH IN A NEW TERMINAL BEFORE CLOSING THIS SESSION!${NC}"
echo ""
