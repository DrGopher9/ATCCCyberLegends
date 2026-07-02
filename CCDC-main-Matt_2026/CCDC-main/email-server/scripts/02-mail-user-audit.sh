#!/bin/bash
###############################################################################
# 02-mail-user-audit.sh - Mail Server User Audit
# Target: Linux Mail Server (Postfix + Dovecot)
# Purpose: Audit system users, mail users, and access controls
###############################################################################

set -euo pipefail

LOGFILE="/root/ccdc-logs/mail_user_audit_$(date +%Y%m%d_%H%M%S).log"
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

log "Starting mail server user audit..."

section "SYSTEM USERS WITH LOGIN SHELLS"
echo "Users that can log in:" | tee -a "$LOGFILE"
grep -E '/bin/(bash|sh|zsh|fish)$' /etc/passwd | while read -r line; do
    user=$(echo "$line" | cut -d: -f1)
    uid=$(echo "$line" | cut -d: -f3)
    home=$(echo "$line" | cut -d: -f6)
    shell=$(echo "$line" | cut -d: -f7)
    echo "  $user (UID: $uid, Home: $home, Shell: $shell)" | tee -a "$LOGFILE"
done

section "MAIL SERVICE ACCOUNTS"
echo "Checking for mail-related system accounts..." | tee -a "$LOGFILE"
for user in postfix dovecot dovenull vmail mail; do
    if id "$user" &>/dev/null; then
        echo "  $user: $(id $user)" | tee -a "$LOGFILE"
    fi
done

section "SUDO/ADMIN ACCESS"
echo "sudo group members:" | tee -a "$LOGFILE"
getent group sudo 2>/dev/null | tee -a "$LOGFILE" || echo "  (no sudo group)" | tee -a "$LOGFILE"
echo "wheel group members:" | tee -a "$LOGFILE"
getent group wheel 2>/dev/null | tee -a "$LOGFILE" || echo "  (no wheel group)" | tee -a "$LOGFILE"
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

section "VIRTUAL MAIL USERS"
echo "Checking for virtual mailbox configuration..." | tee -a "$LOGFILE"

# Check Postfix virtual mailbox maps
VMAIL_MAPS=$(postconf -h virtual_mailbox_maps 2>/dev/null || echo "")
echo "virtual_mailbox_maps: $VMAIL_MAPS" | tee -a "$LOGFILE"

if echo "$VMAIL_MAPS" | grep -q "hash:"; then
    VMAIL_FILE=$(echo "$VMAIL_MAPS" | sed 's/hash://')
    if [ -f "$VMAIL_FILE" ]; then
        echo "Virtual mailboxes from $VMAIL_FILE:" | tee -a "$LOGFILE"
        cat "$VMAIL_FILE" 2>/dev/null | tee -a "$LOGFILE"
    fi
fi

# Check for virtual alias maps
VALIAS_MAPS=$(postconf -h virtual_alias_maps 2>/dev/null || echo "")
echo "" | tee -a "$LOGFILE"
echo "virtual_alias_maps: $VALIAS_MAPS" | tee -a "$LOGFILE"

if echo "$VALIAS_MAPS" | grep -q "hash:"; then
    VALIAS_FILE=$(echo "$VALIAS_MAPS" | sed 's/hash://')
    if [ -f "$VALIAS_FILE" ]; then
        echo "Virtual aliases from $VALIAS_FILE:" | tee -a "$LOGFILE"
        cat "$VALIAS_FILE" 2>/dev/null | tee -a "$LOGFILE"
    fi
fi

section "DOVECOT USER DATABASE"
echo "Checking Dovecot passdb/userdb configuration..." | tee -a "$LOGFILE"

# Check passdb configuration
echo "--- Passdb settings ---" | tee -a "$LOGFILE"
doveconf -n passdb 2>/dev/null | tee -a "$LOGFILE" || true

# Check userdb configuration
echo "" | tee -a "$LOGFILE"
echo "--- Userdb settings ---" | tee -a "$LOGFILE"
doveconf -n userdb 2>/dev/null | tee -a "$LOGFILE" || true

# Check for passwd-file
PASSWD_FILE=$(doveconf -h passdb 2>/dev/null | grep -oP 'args\s*=\s*\K/[^\s]+' | head -1 || echo "")
if [ -n "$PASSWD_FILE" ] && [ -f "$PASSWD_FILE" ]; then
    echo "" | tee -a "$LOGFILE"
    echo "Dovecot passwd file ($PASSWD_FILE):" | tee -a "$LOGFILE"
    cat "$PASSWD_FILE" 2>/dev/null | tee -a "$LOGFILE"
fi

# Check for common passwd-file locations
for pfile in /etc/dovecot/users /etc/dovecot/passwd /etc/dovecot/userdb; do
    if [ -f "$pfile" ]; then
        echo "" | tee -a "$LOGFILE"
        echo "Found user file: $pfile" | tee -a "$LOGFILE"
        cat "$pfile" 2>/dev/null | tee -a "$LOGFILE"
    fi
done

section "MAIL ALIASES"
echo "System aliases (/etc/aliases):" | tee -a "$LOGFILE"
cat /etc/aliases 2>/dev/null | grep -v "^#" | grep -v "^$" | tee -a "$LOGFILE"

section "RECENT MAIL AUTHENTICATION"
echo "Recent successful logins:" | tee -a "$LOGFILE"
grep -i "login.*ok\|authentication succeeded\|logged in" /var/log/mail.log 2>/dev/null | tail -10 | tee -a "$LOGFILE" || \
grep -i "login.*ok\|authentication succeeded\|logged in" /var/log/maillog 2>/dev/null | tail -10 | tee -a "$LOGFILE" || \
journalctl -u dovecot --no-pager 2>/dev/null | grep -i "login\|auth" | tail -10 | tee -a "$LOGFILE" || true

echo "" | tee -a "$LOGFILE"
echo "Recent failed logins:" | tee -a "$LOGFILE"
grep -i "auth.*fail\|login.*fail\|authentication failed" /var/log/mail.log 2>/dev/null | tail -10 | tee -a "$LOGFILE" || \
grep -i "auth.*fail\|login.*fail\|authentication failed" /var/log/maillog 2>/dev/null | tail -10 | tee -a "$LOGFILE" || true

section "ACCOUNTS WITH EMPTY PASSWORDS"
echo "Checking for accounts with empty passwords..." | tee -a "$LOGFILE"
awk -F: '($2 == "" || $2 == "!") {print "WARNING: " $1 " has no password!"}' /etc/shadow 2>/dev/null | tee -a "$LOGFILE"

section "ACCOUNTS WITH UID 0"
echo "Accounts with UID 0 (root equivalents):" | tee -a "$LOGFILE"
awk -F: '$3 == 0 {print "  " $1}' /etc/passwd | tee -a "$LOGFILE"

section "RECOMMENDATIONS"
cat << 'EOF' | tee -a "$LOGFILE"

IMMEDIATE ACTIONS FOR MAIL SERVER:

1. Remove unauthorized SSH keys:
   > /root/.ssh/authorized_keys
   > /home/<user>/.ssh/authorized_keys

2. Disable suspicious system accounts:
   usermod -L <username>
   usermod -s /sbin/nologin <username>

3. Remove from sudo/wheel:
   gpasswd -d <username> sudo
   gpasswd -d <username> wheel

4. Change all passwords (use 03-mail-credential-rotation.sh)

5. Review virtual mail users - remove unauthorized accounts

6. Check mail aliases for suspicious redirects

7. Verify SASL authentication users

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
