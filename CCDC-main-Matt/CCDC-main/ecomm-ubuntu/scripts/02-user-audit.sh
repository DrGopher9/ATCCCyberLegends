#!/bin/bash
###############################################################################
# 02-user-audit.sh - User Account Audit and Cleanup
# Target: Ubuntu 24 E-Commerce Server
# Purpose: Identify and manage user accounts, remove unauthorized access
###############################################################################

set -euo pipefail

LOGFILE="/root/ccdc-logs/user_audit_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$(dirname "$LOGFILE")"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOGFILE"
}

section() {
    echo "" | tee -a "$LOGFILE"
    echo "========================================" | tee -a "$LOGFILE"
    echo "=== $1" | tee -a "$LOGFILE"
    echo "========================================" | tee -a "$LOGFILE"
}

log "Starting user audit..."

section "SYSTEM USERS WITH LOGIN SHELLS"
echo "Users that can log in:" | tee -a "$LOGFILE"
grep -E '/bin/(bash|sh|zsh|fish)$' /etc/passwd | while read -r line; do
    user=$(echo "$line" | cut -d: -f1)
    uid=$(echo "$line" | cut -d: -f3)
    home=$(echo "$line" | cut -d: -f6)
    shell=$(echo "$line" | cut -d: -f7)
    echo "  $user (UID: $uid, Home: $home, Shell: $shell)" | tee -a "$LOGFILE"
done

section "USERS IN SUDO/ADMIN GROUPS"
echo "sudo group members:" | tee -a "$LOGFILE"
getent group sudo 2>/dev/null | tee -a "$LOGFILE" || echo "  (no sudo group)" | tee -a "$LOGFILE"
echo "adm group members:" | tee -a "$LOGFILE"
getent group adm 2>/dev/null | tee -a "$LOGFILE" || echo "  (no adm group)" | tee -a "$LOGFILE"
echo "wheel group members:" | tee -a "$LOGFILE"
getent group wheel 2>/dev/null | tee -a "$LOGFILE" || echo "  (no wheel group)" | tee -a "$LOGFILE"

section "SUDOERS FILES"
echo "Main sudoers:" | tee -a "$LOGFILE"
grep -v '^#' /etc/sudoers 2>/dev/null | grep -v '^$' | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"
echo "sudoers.d contents:" | tee -a "$LOGFILE"
for f in /etc/sudoers.d/*; do
    if [ -f "$f" ]; then
        echo "--- $f ---" | tee -a "$LOGFILE"
        cat "$f" 2>/dev/null | tee -a "$LOGFILE"
    fi
done

section "SSH AUTHORIZED KEYS"
for dir in /root /home/*; do
    if [ -f "$dir/.ssh/authorized_keys" ]; then
        user=$(basename "$dir")
        [ "$user" = "root" ] || user=$(basename "$dir")
        keycount=$(wc -l < "$dir/.ssh/authorized_keys" 2>/dev/null || echo 0)
        echo "$user: $keycount keys in $dir/.ssh/authorized_keys" | tee -a "$LOGFILE"
        cat "$dir/.ssh/authorized_keys" 2>/dev/null | while read -r key; do
            echo "  -> ${key:0:80}..." | tee -a "$LOGFILE"
        done
    fi
done

section "ACCOUNTS WITH EMPTY PASSWORDS"
echo "Checking for accounts with empty passwords..." | tee -a "$LOGFILE"
awk -F: '($2 == "" || $2 == "!") {print "WARNING: " $1 " has no password!"}' /etc/shadow 2>/dev/null | tee -a "$LOGFILE"

section "ACCOUNTS WITH UID 0 (ROOT EQUIVALENTS)"
echo "Accounts with UID 0:" | tee -a "$LOGFILE"
awk -F: '$3 == 0 {print "  " $1}' /etc/passwd | tee -a "$LOGFILE"

section "RECENT USER ACTIVITY"
echo "Last logins:" | tee -a "$LOGFILE"
last -10 2>/dev/null | tee -a "$LOGFILE" || true
echo "" | tee -a "$LOGFILE"
echo "Currently logged in:" | tee -a "$LOGFILE"
who 2>/dev/null | tee -a "$LOGFILE" || true

section "RECOMMENDATIONS"
cat << 'EOF' | tee -a "$LOGFILE"

IMMEDIATE ACTIONS:
1. Remove unauthorized SSH keys:
   > /root/.ssh/authorized_keys
   > /home/<user>/.ssh/authorized_keys

2. Disable suspicious accounts:
   usermod -L <username>        # Lock account
   usermod -s /sbin/nologin <username>  # Disable shell

3. Remove from sudo:
   deluser <username> sudo

4. Change all passwords (use 03-credential-rotation.sh)

5. Remove unauthorized sudoers.d files:
   rm /etc/sudoers.d/<suspicious_file>

EOF

echo ""
log "Audit complete. Review $LOGFILE for full details."
echo ""
echo "============================================"
echo "INTERACTIVE: Remove unauthorized SSH keys?"
echo "============================================"
read -p "Clear ALL authorized_keys files? (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log "Clearing authorized_keys files..."
    > /root/.ssh/authorized_keys 2>/dev/null || true
    for dir in /home/*; do
        if [ -f "$dir/.ssh/authorized_keys" ]; then
            > "$dir/.ssh/authorized_keys"
            log "Cleared: $dir/.ssh/authorized_keys"
        fi
    done
    log "All authorized_keys files cleared."
else
    log "Skipped clearing authorized_keys."
fi
