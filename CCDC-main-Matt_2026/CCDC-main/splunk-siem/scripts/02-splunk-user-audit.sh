#!/bin/bash
#===============================================================================
# CCDC Splunk SIEM - User Audit Script
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

echo -e "${CYAN}========================================"
echo "  CCDC Splunk User Audit"
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

#===============================================================================
# SPLUNK USER AUDIT
#===============================================================================

echo -e "${YELLOW}[*] Auditing Splunk Users...${NC}"
echo ""

echo -e "${CYAN}=== Splunk Local Users (passwd file) ===${NC}"
if [ -f "$SPLUNK_HOME/etc/passwd" ]; then
    echo "Contents of $SPLUNK_HOME/etc/passwd:"
    cat "$SPLUNK_HOME/etc/passwd"
    echo ""

    # Parse users
    echo "User accounts found:"
    while IFS=':' read -r username hash rest; do
        if [ -n "$username" ] && [ "$username" != "#" ]; then
            echo -e "  ${YELLOW}- $username${NC}"
        fi
    done < "$SPLUNK_HOME/etc/passwd"
else
    echo "  No local passwd file found"
fi
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== Splunk User Roles ===${NC}"

# Check authorize.conf for roles
echo "Role definitions:"
find "$SPLUNK_HOME/etc" -name "authorize.conf" 2>/dev/null | while read -r authfile; do
    echo "  File: $authfile"
    grep "^\[role_" "$authfile" 2>/dev/null | sed 's/\[role_/    - /; s/\]//'
done
echo ""

# Check for admin role assignments
echo -e "${YELLOW}Users with admin capabilities:${NC}"
find "$SPLUNK_HOME/etc" -name "authorize.conf" 2>/dev/null | while read -r authfile; do
    if grep -q "admin" "$authfile" 2>/dev/null; then
        echo "  In $authfile:"
        grep -A10 "admin" "$authfile" 2>/dev/null | head -15
    fi
done
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== Splunk Authentication Configuration ===${NC}"

AUTH_CONF="$SPLUNK_HOME/etc/system/local/authentication.conf"
if [ -f "$AUTH_CONF" ]; then
    echo "Authentication method:"
    cat "$AUTH_CONF"

    # Check for LDAP/AD integration
    if grep -qi "LDAP\|ActiveDirectory" "$AUTH_CONF" 2>/dev/null; then
        echo -e "${YELLOW}[!] External authentication (LDAP/AD) configured${NC}"
    fi
else
    echo "  Using default Splunk authentication"
fi
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== Splunk User Directories ===${NC}"

echo "Checking for user-specific directories in apps:"
find "$SPLUNK_HOME/etc/users" -maxdepth 1 -type d 2>/dev/null | while read -r userdir; do
    username=$(basename "$userdir")
    if [ "$username" != "users" ]; then
        echo -e "  ${YELLOW}- $username${NC}"
        # Check for suspicious saved searches
        if [ -f "$userdir/search/local/savedsearches.conf" ]; then
            echo "    Has saved searches"
        fi
    fi
done
echo ""

#===============================================================================
# SYSTEM USER AUDIT
#===============================================================================

echo -e "${YELLOW}[*] Auditing System Users...${NC}"
echo ""

echo -e "${CYAN}=== Users with Login Shells ===${NC}"
grep -v "nologin\|false" /etc/passwd | while IFS=':' read -r user x uid gid desc home shell; do
    if [ "$uid" -ge 1000 ] || [ "$uid" -eq 0 ]; then
        echo -e "  ${YELLOW}$user${NC} (UID: $uid) - $shell"
    fi
done
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== Splunk Service Account ===${NC}"

# Find what user Splunk runs as
SPLUNK_USER=$(ps aux | grep "[s]plunkd" | head -1 | awk '{print $1}')
if [ -n "$SPLUNK_USER" ]; then
    echo "Splunk running as: $SPLUNK_USER"
    id "$SPLUNK_USER" 2>/dev/null
else
    echo "Splunk process not found or not running"
fi
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== Sudo Access ===${NC}"

echo "Users/groups with sudo access:"
grep -v "^#" /etc/sudoers 2>/dev/null | grep -E "ALL.*ALL" | head -20
echo ""

echo "Sudoers.d entries:"
for f in /etc/sudoers.d/*; do
    if [ -f "$f" ]; then
        echo "  $f:"
        grep -v "^#" "$f" 2>/dev/null | grep -v "^$" | sed 's/^/    /'
    fi
done
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== SSH Authorized Keys ===${NC}"

for user_home in /home/* /root; do
    if [ -d "$user_home" ]; then
        username=$(basename "$user_home")
        if [ -f "$user_home/.ssh/authorized_keys" ]; then
            key_count=$(wc -l < "$user_home/.ssh/authorized_keys")
            echo -e "  ${YELLOW}$username${NC}: $key_count key(s)"
            cat "$user_home/.ssh/authorized_keys" | while read -r key; do
                # Extract key comment/identifier
                key_id=$(echo "$key" | awk '{print $NF}')
                echo "    - $key_id"
            done
        fi
    fi
done
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== Recent Login Activity ===${NC}"

echo "Last logins:"
last -10 2>/dev/null || echo "  Could not retrieve login history"
echo ""

echo "Failed login attempts:"
grep "Failed password" /var/log/auth.log 2>/dev/null | tail -10 || \
grep "Failed password" /var/log/secure 2>/dev/null | tail -10 || \
echo "  Could not retrieve failed logins"
echo ""

#===============================================================================
# SUSPICIOUS ACTIVITY CHECK
#===============================================================================

echo -e "${YELLOW}[*] Checking for Suspicious Activity...${NC}"
echo ""

echo -e "${CYAN}=== Unusual Splunk Apps ===${NC}"
echo "Non-standard apps in $SPLUNK_HOME/etc/apps:"
for app in "$SPLUNK_HOME/etc/apps/"*/; do
    appname=$(basename "$app")
    # List of known/expected apps
    case "$appname" in
        search|launcher|splunk_*|learned|legacy|SplunkForwarder|introspection_generator_addon|sample_app)
            ;;
        *)
            echo -e "  ${YELLOW}[?] $appname${NC} - Verify this app"
            # Check for scripted inputs
            if [ -d "$app/bin" ]; then
                echo "      Has bin/ directory with scripts:"
                ls -la "$app/bin/" 2>/dev/null | head -5
            fi
            ;;
    esac
done
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== Scripted Inputs ===${NC}"

echo "Checking for script-based inputs:"
find "$SPLUNK_HOME/etc" -name "inputs.conf" -exec grep -l "\[script://" {} \; 2>/dev/null | while read -r conf; do
    echo "  Found in: $conf"
    grep -A3 "\[script://" "$conf" 2>/dev/null
done
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== Suspicious Scheduled Searches ===${NC}"

echo "Checking saved searches with script actions:"
find "$SPLUNK_HOME/etc" -name "savedsearches.conf" 2>/dev/null | while read -r ssconf; do
    if grep -qE "action\.script|alert\.execute" "$ssconf" 2>/dev/null; then
        echo -e "  ${RED}[!] Script actions found in: $ssconf${NC}"
        grep -B5 -A5 "action\.script\|alert\.execute" "$ssconf" 2>/dev/null
    fi
done
echo ""

#-------------------------------------------------------------------------------
echo -e "${CYAN}=== Custom Commands ===${NC}"

echo "Checking for custom search commands:"
find "$SPLUNK_HOME/etc/apps" -name "commands.conf" 2>/dev/null | while read -r cmdconf; do
    echo "  Found in: $cmdconf"
    cat "$cmdconf" 2>/dev/null
done
echo ""

#===============================================================================
# INTERACTIVE ACTIONS
#===============================================================================

echo ""
echo -e "${YELLOW}========================================"
echo "  User Management Actions"
echo -e "========================================${NC}"
echo ""

echo "Options:"
echo "  1) Remove a Splunk user"
echo "  2) Disable a Linux user"
echo "  3) Remove SSH authorized key"
echo "  4) Remove suspicious app"
echo "  5) Exit"
echo ""

read -p "Select action (1-5): " action

case $action in
    1)
        echo ""
        echo "Current Splunk users:"
        cat "$SPLUNK_HOME/etc/passwd" 2>/dev/null
        echo ""
        read -p "Enter username to remove: " splunk_user
        if [ -n "$splunk_user" ]; then
            # Remove from passwd file
            if grep -q "^$splunk_user:" "$SPLUNK_HOME/etc/passwd" 2>/dev/null; then
                sed -i "/^$splunk_user:/d" "$SPLUNK_HOME/etc/passwd"
                echo -e "${GREEN}[+] Removed $splunk_user from Splunk${NC}"
                echo "[$(date)] Removed Splunk user: $splunk_user" >> "$LOGDIR/user_changes.log"
            else
                echo -e "${RED}User not found${NC}"
            fi
        fi
        ;;
    2)
        echo ""
        read -p "Enter Linux username to disable: " linux_user
        if [ -n "$linux_user" ]; then
            usermod -L "$linux_user" 2>/dev/null && \
                echo -e "${GREEN}[+] Locked account: $linux_user${NC}"
            usermod -s /sbin/nologin "$linux_user" 2>/dev/null && \
                echo -e "${GREEN}[+] Set shell to nologin: $linux_user${NC}"
            echo "[$(date)] Disabled Linux user: $linux_user" >> "$LOGDIR/user_changes.log"
        fi
        ;;
    3)
        echo ""
        read -p "Enter username to remove SSH key from: " ssh_user
        if [ -n "$ssh_user" ]; then
            if [ "$ssh_user" = "root" ]; then
                keyfile="/root/.ssh/authorized_keys"
            else
                keyfile="/home/$ssh_user/.ssh/authorized_keys"
            fi
            if [ -f "$keyfile" ]; then
                echo "Current keys:"
                cat -n "$keyfile"
                read -p "Enter line number to remove (or 'all'): " linenum
                if [ "$linenum" = "all" ]; then
                    > "$keyfile"
                    echo -e "${GREEN}[+] Removed all SSH keys for $ssh_user${NC}"
                elif [ -n "$linenum" ]; then
                    sed -i "${linenum}d" "$keyfile"
                    echo -e "${GREEN}[+] Removed key line $linenum${NC}"
                fi
                echo "[$(date)] Modified SSH keys for: $ssh_user" >> "$LOGDIR/user_changes.log"
            else
                echo "No authorized_keys file found"
            fi
        fi
        ;;
    4)
        echo ""
        echo "Apps in $SPLUNK_HOME/etc/apps:"
        ls -1 "$SPLUNK_HOME/etc/apps/"
        echo ""
        read -p "Enter app name to disable: " appname
        if [ -n "$appname" ] && [ -d "$SPLUNK_HOME/etc/apps/$appname" ]; then
            # Disable by creating local/app.conf with state = disabled
            mkdir -p "$SPLUNK_HOME/etc/apps/$appname/local"
            echo -e "[install]\nstate = disabled" > "$SPLUNK_HOME/etc/apps/$appname/local/app.conf"
            echo -e "${GREEN}[+] Disabled app: $appname${NC}"
            echo -e "${YELLOW}[!] Restart Splunk to apply: $SPLUNK_HOME/bin/splunk restart${NC}"
            echo "[$(date)] Disabled Splunk app: $appname" >> "$LOGDIR/user_changes.log"
        else
            echo "App not found"
        fi
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
