#!/bin/bash
#===============================================================================
# CCDC Splunk SIEM - SSH Hardening Script
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

LOGDIR="/opt/splunk-ccdc-logs"
BACKUP_DIR="/opt/splunk-ccdc-backups"
mkdir -p "$LOGDIR" "$BACKUP_DIR"

echo -e "${CYAN}========================================"
echo "  CCDC Splunk SSH Hardening"
echo -e "========================================${NC}"
echo ""

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Backing up SSH configuration...${NC}"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.bak.$TIMESTAMP"
echo -e "${GREEN}    [+] Backup: $BACKUP_DIR/sshd_config.bak.$TIMESTAMP${NC}"

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Current SSH Configuration:${NC}"
echo ""

echo "Key settings:"
grep -E "^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|MaxAuthTries|AllowUsers|AllowGroups)" /etc/ssh/sshd_config 2>/dev/null || echo "  Using defaults"
echo ""

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Applying SSH Hardening...${NC}"
echo ""

SSHD_CONFIG="/etc/ssh/sshd_config"

# Function to set SSH config
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

# Disable root login (optional - ask first)
read -p "Disable root SSH login? (y/N): " disable_root
if [ "$disable_root" = "y" ]; then
    set_ssh_config "PermitRootLogin" "no"
    echo -e "${GREEN}    [+] Root login disabled${NC}"
else
    set_ssh_config "PermitRootLogin" "prohibit-password"
    echo -e "${GREEN}    [+] Root login: key-only${NC}"
fi

# Disable password authentication (optional)
read -p "Disable password authentication (key-only)? (y/N): " disable_pass
if [ "$disable_pass" = "y" ]; then
    set_ssh_config "PasswordAuthentication" "no"
    echo -e "${GREEN}    [+] Password authentication disabled${NC}"
else
    set_ssh_config "PasswordAuthentication" "yes"
    echo -e "${YELLOW}    [!] Password authentication enabled${NC}"
fi

# Enable public key authentication
set_ssh_config "PubkeyAuthentication" "yes"
echo -e "${GREEN}    [+] Public key authentication enabled${NC}"

# Limit authentication attempts
set_ssh_config "MaxAuthTries" "3"
echo -e "${GREEN}    [+] Max auth tries: 3${NC}"

# Disable empty passwords
set_ssh_config "PermitEmptyPasswords" "no"
echo -e "${GREEN}    [+] Empty passwords disabled${NC}"

# Disable X11 forwarding
set_ssh_config "X11Forwarding" "no"
echo -e "${GREEN}    [+] X11 forwarding disabled${NC}"

# Set login grace time
set_ssh_config "LoginGraceTime" "60"
echo -e "${GREEN}    [+] Login grace time: 60s${NC}"

# Client alive settings (prevents idle disconnects while detecting dead sessions)
set_ssh_config "ClientAliveInterval" "300"
set_ssh_config "ClientAliveCountMax" "2"
echo -e "${GREEN}    [+] Client alive interval: 300s${NC}"

# Disable TCP forwarding (optional)
read -p "Disable TCP forwarding? (y/N): " disable_tcp
if [ "$disable_tcp" = "y" ]; then
    set_ssh_config "AllowTcpForwarding" "no"
    echo -e "${GREEN}    [+] TCP forwarding disabled${NC}"
fi

# Protocol version (SSH2 only - usually default)
set_ssh_config "Protocol" "2"
echo -e "${GREEN}    [+] SSH Protocol 2 only${NC}"

#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[*] Configure allowed users...${NC}"

read -p "Restrict SSH to specific users? (y/N): " restrict_users
if [ "$restrict_users" = "y" ]; then
    echo "Current users with shells:"
    grep -v "nologin\|false" /etc/passwd | cut -d: -f1
    echo ""

    read -p "Enter allowed users (space-separated): " allowed_users
    if [ -n "$allowed_users" ]; then
        # Remove existing AllowUsers line
        sed -i '/^AllowUsers/d' "$SSHD_CONFIG"
        echo "AllowUsers $allowed_users" >> "$SSHD_CONFIG"
        echo -e "${GREEN}    [+] Allowed users: $allowed_users${NC}"
    fi
fi

#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[*] SSH Banner Configuration...${NC}"

read -p "Set SSH warning banner? (y/N): " set_banner
if [ "$set_banner" = "y" ]; then
    cat > /etc/ssh/banner << 'EOF'
================================================================================
                        AUTHORIZED ACCESS ONLY
================================================================================
This system is for authorized users only. All activity is monitored and logged.
Unauthorized access attempts will be reported.
================================================================================
EOF

    set_ssh_config "Banner" "/etc/ssh/banner"
    echo -e "${GREEN}    [+] SSH banner configured${NC}"
fi

#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[*] Reviewing authorized keys...${NC}"

echo "Checking for SSH keys:"
for user_home in /home/* /root; do
    if [ -d "$user_home" ]; then
        username=$(basename "$user_home")
        if [ -f "$user_home/.ssh/authorized_keys" ]; then
            key_count=$(wc -l < "$user_home/.ssh/authorized_keys" 2>/dev/null || echo "0")
            if [ "$key_count" -gt 0 ]; then
                echo -e "  ${YELLOW}$username${NC}: $key_count key(s)"
            fi
        fi
    fi
done

echo ""
read -p "Review and clean authorized_keys files? (y/N): " clean_keys
if [ "$clean_keys" = "y" ]; then
    for user_home in /home/* /root; do
        if [ -d "$user_home" ]; then
            username=$(basename "$user_home")
            keyfile="$user_home/.ssh/authorized_keys"
            if [ -f "$keyfile" ] && [ -s "$keyfile" ]; then
                echo ""
                echo "Keys for $username:"
                cat -n "$keyfile"
                echo ""
                read -p "Remove any keys for $username? (line numbers, 'all', or skip): " remove_keys
                if [ "$remove_keys" = "all" ]; then
                    cp "$keyfile" "$BACKUP_DIR/authorized_keys_${username}.bak.$TIMESTAMP"
                    > "$keyfile"
                    echo -e "${GREEN}    [+] Removed all keys for $username (backed up)${NC}"
                elif [ -n "$remove_keys" ]; then
                    cp "$keyfile" "$BACKUP_DIR/authorized_keys_${username}.bak.$TIMESTAMP"
                    for line in $remove_keys; do
                        sed -i "${line}d" "$keyfile" 2>/dev/null
                    done
                    echo -e "${GREEN}    [+] Removed specified keys${NC}"
                fi
            fi
        fi
    done
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
    echo -e "${YELLOW}    [!] Original config restored${NC}"
    exit 1
fi

#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[*] Restarting SSH service...${NC}"

# Keep current session alive
echo -e "${RED}[!] WARNING: Keep this session open while testing SSH!${NC}"
read -p "Restart SSH now? (y/N): " restart_ssh
if [ "$restart_ssh" = "y" ]; then
    systemctl restart sshd 2>/dev/null || service sshd restart 2>/dev/null || service ssh restart 2>/dev/null
    echo -e "${GREEN}    [+] SSH service restarted${NC}"
    echo ""
    echo -e "${YELLOW}[!] Test SSH in a NEW terminal before closing this session!${NC}"
fi

#-------------------------------------------------------------------------------
echo ""
echo -e "${GREEN}========================================"
echo "  SSH Hardening Complete"
echo -e "========================================${NC}"
echo ""
echo "Applied settings:"
grep -E "^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|MaxAuthTries|AllowUsers)" /etc/ssh/sshd_config 2>/dev/null
echo ""
echo -e "${YELLOW}Backup location: $BACKUP_DIR/sshd_config.bak.$TIMESTAMP${NC}"
echo ""
echo -e "${RED}IMPORTANT: Test SSH access before closing this session!${NC}"
echo ""
