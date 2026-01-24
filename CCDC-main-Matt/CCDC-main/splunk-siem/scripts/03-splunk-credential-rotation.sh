#!/bin/bash
#===============================================================================
# CCDC Splunk SIEM - Credential Rotation Script
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
mkdir -p "$LOGDIR"
CRED_FILE="$LOGDIR/CREDENTIALS_$(date +%Y%m%d_%H%M%S).txt"

# Secure the credentials file
touch "$CRED_FILE"
chmod 600 "$CRED_FILE"

echo -e "${CYAN}========================================"
echo "  CCDC Splunk Credential Rotation"
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

SPLUNK_CMD="$SPLUNK_HOME/bin/splunk"

# Function to generate secure password
generate_password() {
    # 20 character password with mixed characters
    < /dev/urandom tr -dc 'A-Za-z0-9!@#$%^&*' | head -c 20
    echo ""
}

# Header for credentials file
cat >> "$CRED_FILE" << EOF
================================================================================
CCDC SPLUNK CREDENTIALS - $(date)
================================================================================
KEEP THIS FILE SECURE - DELETE AFTER RECORDING PASSWORDS
================================================================================

EOF

echo -e "${RED}[!] IMPORTANT: Back up before rotating credentials!${NC}"
echo ""

#===============================================================================
# SPLUNK ADMIN PASSWORD
#===============================================================================

echo -e "${YELLOW}[*] Splunk Admin Password Rotation${NC}"
echo ""

read -p "Change Splunk admin password? (y/N): " change_admin
if [ "$change_admin" = "y" ]; then
    NEW_ADMIN_PASS=$(generate_password)

    echo ""
    echo "Current Splunk admin user is typically 'admin'"
    read -p "Enter admin username [admin]: " ADMIN_USER
    ADMIN_USER=${ADMIN_USER:-admin}

    read -sp "Enter CURRENT admin password: " CURRENT_PASS
    echo ""

    echo "[*] Changing Splunk admin password..."

    # Use Splunk CLI to change password
    if $SPLUNK_CMD edit user "$ADMIN_USER" -password "$NEW_ADMIN_PASS" -auth "$ADMIN_USER:$CURRENT_PASS" 2>/dev/null; then
        echo -e "${GREEN}[+] Splunk admin password changed${NC}"

        cat >> "$CRED_FILE" << EOF
SPLUNK ADMIN
------------
Username: $ADMIN_USER
Password: $NEW_ADMIN_PASS
URL: https://$(hostname):8000

EOF
    else
        echo -e "${RED}[-] Failed to change password via CLI${NC}"
        echo ""
        echo "Alternative method - use REST API:"
        echo "  curl -k -u $ADMIN_USER:OLDPASS https://localhost:8089/services/authentication/users/$ADMIN_USER -d password=NEWPASS"
        echo ""
        echo "Or reset via user-seed.conf:"
        echo "  1. Stop Splunk"
        echo "  2. Remove $SPLUNK_HOME/etc/passwd"
        echo "  3. Create $SPLUNK_HOME/etc/system/local/user-seed.conf:"
        echo "     [user_info]"
        echo "     USERNAME = admin"
        echo "     PASSWORD = newpassword"
        echo "  4. Start Splunk"
    fi
fi

#===============================================================================
# CREATE NEW ADMIN ACCOUNT
#===============================================================================

echo ""
echo -e "${YELLOW}[*] Create Backup Admin Account${NC}"
echo ""

read -p "Create a new admin account? (y/N): " create_admin
if [ "$create_admin" = "y" ]; then
    read -p "Enter new admin username: " NEW_ADMIN_USER
    NEW_ADMIN_PASS=$(generate_password)

    read -sp "Enter current admin password for authentication: " AUTH_PASS
    echo ""

    if $SPLUNK_CMD add user "$NEW_ADMIN_USER" -password "$NEW_ADMIN_PASS" -role admin -auth "admin:$AUTH_PASS" 2>/dev/null; then
        echo -e "${GREEN}[+] Created new admin user: $NEW_ADMIN_USER${NC}"

        cat >> "$CRED_FILE" << EOF
SPLUNK BACKUP ADMIN
-------------------
Username: $NEW_ADMIN_USER
Password: $NEW_ADMIN_PASS
Role: admin

EOF
    else
        echo -e "${RED}[-] Failed to create user${NC}"
    fi
fi

#===============================================================================
# LINUX ROOT PASSWORD
#===============================================================================

echo ""
echo -e "${YELLOW}[*] Linux Root Password${NC}"
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
Host: $(hostname)

EOF
    else
        echo -e "${RED}[-] Failed to change root password${NC}"
    fi
fi

#===============================================================================
# SPLUNK SERVICE ACCOUNT
#===============================================================================

echo ""
echo -e "${YELLOW}[*] Splunk Service Account${NC}"
echo ""

# Detect Splunk user
SPLUNK_USER=$(stat -c '%U' "$SPLUNK_HOME/bin/splunk" 2>/dev/null)
if [ -z "$SPLUNK_USER" ] || [ "$SPLUNK_USER" = "root" ]; then
    SPLUNK_USER=$(ps aux | grep "[s]plunkd" | head -1 | awk '{print $1}')
fi

if [ -n "$SPLUNK_USER" ] && [ "$SPLUNK_USER" != "root" ]; then
    echo "Splunk service user: $SPLUNK_USER"

    read -p "Change $SPLUNK_USER password? (y/N): " change_splunk_user
    if [ "$change_splunk_user" = "y" ]; then
        NEW_SPLUNK_USER_PASS=$(generate_password)

        echo "$NEW_SPLUNK_USER_PASS" | passwd --stdin "$SPLUNK_USER" 2>/dev/null || \
        echo "$SPLUNK_USER:$NEW_SPLUNK_USER_PASS" | chpasswd

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+] $SPLUNK_USER password changed${NC}"

            cat >> "$CRED_FILE" << EOF
SPLUNK SERVICE ACCOUNT
----------------------
Username: $SPLUNK_USER
Password: $NEW_SPLUNK_USER_PASS
Note: This is the Linux account Splunk runs as

EOF
        fi
    fi
else
    echo "Splunk appears to run as root"
fi

#===============================================================================
# OTHER LINUX USERS
#===============================================================================

echo ""
echo -e "${YELLOW}[*] Other Linux User Accounts${NC}"
echo ""

echo "Users with login shells:"
grep -v "nologin\|false" /etc/passwd | while IFS=':' read -r user x uid gid desc home shell; do
    if [ "$uid" -ge 1000 ] && [ "$user" != "$SPLUNK_USER" ]; then
        echo "  - $user (UID: $uid)"
    fi
done
echo ""

read -p "Change password for another user? (enter username or skip): " other_user
while [ -n "$other_user" ]; do
    if id "$other_user" &>/dev/null; then
        NEW_USER_PASS=$(generate_password)

        echo "$NEW_USER_PASS" | passwd --stdin "$other_user" 2>/dev/null || \
        echo "$other_user:$NEW_USER_PASS" | chpasswd

        if [ $? -eq 0 ]; then
            echo -e "${GREEN}[+] Password changed for $other_user${NC}"

            cat >> "$CRED_FILE" << EOF
LINUX USER: $other_user
-----------------------
Username: $other_user
Password: $NEW_USER_PASS

EOF
        fi
    else
        echo -e "${RED}User not found${NC}"
    fi

    read -p "Change password for another user? (enter username or skip): " other_user
done

#===============================================================================
# SPLUNK SECRET KEY
#===============================================================================

echo ""
echo -e "${YELLOW}[*] Splunk Secret Key (splunk.secret)${NC}"
echo ""
echo -e "${RED}WARNING: Changing splunk.secret will invalidate all encrypted passwords!${NC}"
echo "This includes:"
echo "  - Saved credentials in apps"
echo "  - Encrypted passwords in configuration files"
echo "  - HEC tokens"
echo ""

read -p "Regenerate splunk.secret? (y/N) [DANGEROUS]: " regen_secret
if [ "$regen_secret" = "y" ]; then
    read -p "Are you SURE? Type 'YES' to confirm: " confirm
    if [ "$confirm" = "YES" ]; then
        # Backup current secret
        cp "$SPLUNK_HOME/etc/auth/splunk.secret" "$LOGDIR/splunk.secret.bak.$(date +%Y%m%d_%H%M%S)"

        # Stop Splunk
        $SPLUNK_CMD stop 2>/dev/null

        # Remove old secret (new one generated on start)
        rm -f "$SPLUNK_HOME/etc/auth/splunk.secret"

        echo -e "${YELLOW}[!] splunk.secret removed - new one will be generated on restart${NC}"
        echo -e "${YELLOW}[!] You will need to re-enter all encrypted passwords${NC}"

        cat >> "$CRED_FILE" << EOF
SPLUNK SECRET
-------------
Action: Regenerated
Note: All encrypted passwords must be re-entered
Old secret backed up to: $LOGDIR/splunk.secret.bak.*

EOF

        # Start Splunk
        $SPLUNK_CMD start 2>/dev/null
    fi
fi

#===============================================================================
# HTTP EVENT COLLECTOR (HEC) TOKENS
#===============================================================================

echo ""
echo -e "${YELLOW}[*] HTTP Event Collector (HEC) Tokens${NC}"
echo ""

# Check for HEC configuration
if [ -f "$SPLUNK_HOME/etc/system/local/inputs.conf" ]; then
    if grep -q "\[http\]" "$SPLUNK_HOME/etc/system/local/inputs.conf"; then
        echo "HEC appears to be configured"

        # List tokens
        echo "Checking for HEC tokens..."
        find "$SPLUNK_HOME/etc/apps" -path "*/local/inputs.conf" -exec grep -l "\[http://" {} \; 2>/dev/null

        echo ""
        echo "To manage HEC tokens:"
        echo "  1. Go to Settings > Data Inputs > HTTP Event Collector"
        echo "  2. Review and rotate tokens as needed"
        echo "  3. Or use REST API:"
        echo '     curl -k -u admin:pass https://localhost:8089/services/data/inputs/http'
    else
        echo "HEC does not appear to be enabled"
    fi
fi

#===============================================================================
# DEPLOYMENT SERVER CREDENTIALS
#===============================================================================

echo ""
echo -e "${YELLOW}[*] Deployment Server Credentials${NC}"
echo ""

if [ -f "$SPLUNK_HOME/etc/system/local/serverclass.conf" ]; then
    echo "This appears to be a deployment server"
    echo "Deployment clients use pass4SymmKey for authentication"
    echo ""
    echo "Current pass4SymmKey (encrypted):"
    grep "pass4SymmKey" "$SPLUNK_HOME/etc/system/local/server.conf" 2>/dev/null || echo "  Not explicitly set"

    read -p "Change deployment server pass4SymmKey? (y/N): " change_ds_key
    if [ "$change_ds_key" = "y" ]; then
        NEW_DS_KEY=$(generate_password)

        echo -e "${YELLOW}[!] You must update this key on ALL deployment clients${NC}"
        echo ""

        cat >> "$CRED_FILE" << EOF
DEPLOYMENT SERVER KEY
---------------------
pass4SymmKey: $NEW_DS_KEY
Note: Update this in server.conf on all deployment clients

To set on server:
  [general]
  pass4SymmKey = $NEW_DS_KEY

EOF

        echo "Add to $SPLUNK_HOME/etc/system/local/server.conf:"
        echo "  [general]"
        echo "  pass4SymmKey = $NEW_DS_KEY"
    fi
fi

#===============================================================================
# SUMMARY
#===============================================================================

echo ""
echo -e "${GREEN}========================================"
echo "  Credential Rotation Complete"
echo -e "========================================${NC}"
echo ""

# Final credential file message
cat >> "$CRED_FILE" << EOF
================================================================================
END OF CREDENTIALS
Generated: $(date)
================================================================================
DELETE THIS FILE AFTER SECURELY RECORDING ALL PASSWORDS
================================================================================
EOF

echo -e "${RED}========================================${NC}"
echo -e "${RED}  CREDENTIALS SAVED TO:${NC}"
echo -e "${RED}  $CRED_FILE${NC}"
echo -e "${RED}========================================${NC}"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC}"
echo "  1. Record these credentials securely"
echo "  2. Delete the credentials file after recording"
echo "  3. Test Splunk login with new credentials"
echo "  4. Update any scripts/integrations using old passwords"
echo ""

# Verify Splunk is running
echo "Verifying Splunk status..."
$SPLUNK_CMD status 2>/dev/null || echo -e "${RED}[!] Splunk may not be running - check manually${NC}"
echo ""
