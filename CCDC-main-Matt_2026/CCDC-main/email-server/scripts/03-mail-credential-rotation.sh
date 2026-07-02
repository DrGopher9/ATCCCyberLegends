#!/bin/bash
###############################################################################
# 03-mail-credential-rotation.sh - Mail Server Credential Rotation
# Target: Linux Mail Server (Postfix + Dovecot)
# Purpose: Change all critical passwords systematically
###############################################################################

set -euo pipefail

LOGFILE="/root/ccdc-logs/mail_cred_rotation_$(date +%Y%m%d_%H%M%S).log"
CRED_FILE="/root/ccdc-logs/MAIL_CREDENTIALS_$(date +%Y%m%d_%H%M%S).txt"
mkdir -p "$(dirname "$LOGFILE")"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOGFILE"
}

generate_password() {
    # Generate a competition-friendly password
    openssl rand -base64 12 | tr -dc 'A-Za-z0-9' | head -c 16
}

log "Starting mail server credential rotation..."

# Initialize credentials file
cat > "$CRED_FILE" << EOF
============================================
CCDC MAIL SERVER CREDENTIAL ROTATION - $(date)
Host: $(hostname)
============================================
KEEP THIS FILE SECURE - DELETE AFTER RECORDING

EOF

chmod 600 "$CRED_FILE"

echo ""
echo "============================================"
echo "LINUX SYSTEM USERS"
echo "============================================"

# Get list of users with login shells
USERS=$(grep -E '/bin/(bash|sh|zsh)$' /etc/passwd | cut -d: -f1)

for user in $USERS; do
    echo ""
    read -p "Change password for '$user'? (y/N/skip-all): " -r REPLY

    if [[ $REPLY =~ ^[Ss] ]]; then
        log "Skipping remaining system users"
        break
    fi

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        NEW_PASS=$(generate_password)
        echo "$user:$NEW_PASS" | chpasswd
        if [ $? -eq 0 ]; then
            log "Password changed for: $user"
            echo "LINUX USER: $user" >> "$CRED_FILE"
            echo "PASSWORD:   $NEW_PASS" >> "$CRED_FILE"
            echo "" >> "$CRED_FILE"
        else
            log "FAILED to change password for: $user"
        fi
    fi
done

echo ""
echo "============================================"
echo "DOVECOT MAIL USERS"
echo "============================================"

# Check for Dovecot passwd-file authentication
PASSDB_ARGS=$(doveconf -h passdb 2>/dev/null | grep "args" | head -1 || echo "")

# Try common passwd-file locations
DOVECOT_PASSWD=""
for pfile in /etc/dovecot/users /etc/dovecot/passwd /etc/dovecot/userdb /etc/dovecot/passwd.db; do
    if [ -f "$pfile" ]; then
        DOVECOT_PASSWD="$pfile"
        break
    fi
done

# Extract from config if not found in common locations
if [ -z "$DOVECOT_PASSWD" ] && [ -n "$PASSDB_ARGS" ]; then
    DOVECOT_PASSWD=$(echo "$PASSDB_ARGS" | grep -oP '/[^\s:]+' | head -1)
fi

if [ -n "$DOVECOT_PASSWD" ] && [ -f "$DOVECOT_PASSWD" ]; then
    log "Found Dovecot passwd file: $DOVECOT_PASSWD"
    echo "Current mail users:"
    cat "$DOVECOT_PASSWD" | cut -d: -f1

    echo ""
    read -p "Rotate Dovecot user passwords? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        # Backup the file
        cp "$DOVECOT_PASSWD" "$DOVECOT_PASSWD.bak.$(date +%Y%m%d_%H%M%S)"

        # Get users from file
        MAIL_USERS=$(cat "$DOVECOT_PASSWD" | cut -d: -f1)

        for mailuser in $MAIL_USERS; do
            read -p "Change password for mail user '$mailuser'? (y/N): " -r REPLY
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                NEW_PASS=$(generate_password)

                # Generate password hash (Dovecot format)
                # Try doveadm first, fall back to openssl
                if command -v doveadm &> /dev/null; then
                    HASH=$(doveadm pw -s SHA512-CRYPT -p "$NEW_PASS" 2>/dev/null || doveadm pw -s SSHA512 -p "$NEW_PASS" 2>/dev/null || echo "")
                fi

                if [ -z "$HASH" ]; then
                    # Fallback to SHA512 via openssl
                    SALT=$(openssl rand -base64 12 | tr -dc 'A-Za-z0-9' | head -c 16)
                    HASH=$(openssl passwd -6 -salt "$SALT" "$NEW_PASS" 2>/dev/null || openssl passwd -1 -salt "$SALT" "$NEW_PASS")
                fi

                if [ -n "$HASH" ]; then
                    # Update the password in the file
                    # Format is typically: user:password:uid:gid:gecos:home:shell
                    # or simply: user:password
                    sed -i "s|^${mailuser}:[^:]*|${mailuser}:${HASH}|" "$DOVECOT_PASSWD"
                    log "Password changed for mail user: $mailuser"
                    echo "MAIL USER: $mailuser" >> "$CRED_FILE"
                    echo "PASSWORD: $NEW_PASS" >> "$CRED_FILE"
                    echo "" >> "$CRED_FILE"
                else
                    log "FAILED to generate hash for: $mailuser"
                fi
            fi
        done

        # Restart Dovecot to apply
        echo ""
        read -p "Restart Dovecot to apply changes? (y/N): " -r REPLY
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            systemctl restart dovecot
            log "Dovecot restarted"
        fi
    fi
else
    log "Dovecot passwd-file not found or using different auth method"
    echo "Dovecot may be using PAM, LDAP, or SQL authentication."
    echo "Check: doveconf -n passdb"

    # Check if using PAM
    if doveconf -n passdb 2>/dev/null | grep -q "pam"; then
        echo "Dovecot is using PAM authentication (system users)."
        echo "System user passwords were handled above."
    fi

    # Check if using SQL
    if doveconf -n passdb 2>/dev/null | grep -q "sql"; then
        echo ""
        echo "Dovecot is using SQL authentication."
        echo "You may need to update passwords in the database directly."

        SQL_CONF=$(doveconf -h passdb 2>/dev/null | grep -oP '/[^\s]+\.conf' | head -1 || echo "")
        if [ -n "$SQL_CONF" ] && [ -f "$SQL_CONF" ]; then
            echo "SQL config: $SQL_CONF"
            echo "Database connection info:"
            grep -E "^(driver|connect|password_query)" "$SQL_CONF" 2>/dev/null | head -5
        fi
    fi
fi

echo ""
echo "============================================"
echo "SASL AUTHENTICATION"
echo "============================================"

# Check for SASL database (sasldb2)
if [ -f "/etc/sasldb2" ]; then
    log "Found SASL database: /etc/sasldb2"
    echo "SASL users:"
    sasldblistusers2 2>/dev/null || true

    read -p "Rotate SASL user passwords? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        SASL_USERS=$(sasldblistusers2 2>/dev/null | cut -d@ -f1 | sort -u)
        REALM=$(postconf -h myhostname 2>/dev/null || hostname)

        for sasluser in $SASL_USERS; do
            read -p "Change password for SASL user '$sasluser'? (y/N): " -r REPLY
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                NEW_PASS=$(generate_password)
                echo "$NEW_PASS" | saslpasswd2 -c -u "$REALM" "$sasluser" 2>/dev/null
                if [ $? -eq 0 ]; then
                    log "SASL password changed for: $sasluser@$REALM"
                    echo "SASL USER: $sasluser@$REALM" >> "$CRED_FILE"
                    echo "PASSWORD:  $NEW_PASS" >> "$CRED_FILE"
                    echo "" >> "$CRED_FILE"
                else
                    log "FAILED to change SASL password for: $sasluser"
                fi
            fi
        done
    fi
else
    echo "No SASL database found (may be using different auth method)"
fi

echo ""
echo "============================================"
echo "DATABASE CREDENTIALS (if applicable)"
echo "============================================"

# Check for MySQL/MariaDB auth in Dovecot
SQL_CONF=""
if doveconf -n passdb 2>/dev/null | grep -q "sql"; then
    SQL_CONF=$(doveconf -h passdb 2>/dev/null | grep -oP '/[^\s]+\.conf' | head -1 || echo "")
fi

# Also check Postfix for MySQL maps
POSTFIX_MYSQL=$(postconf -h virtual_mailbox_maps 2>/dev/null | grep "mysql:" || echo "")

if [ -n "$SQL_CONF" ] || [ -n "$POSTFIX_MYSQL" ]; then
    echo "Mail server appears to use database authentication."
    echo ""
    echo "Relevant config files:"
    [ -n "$SQL_CONF" ] && echo "  Dovecot SQL: $SQL_CONF"
    [ -n "$POSTFIX_MYSQL" ] && echo "  Postfix MySQL: $POSTFIX_MYSQL"
    echo ""
    echo "To change database user passwords:"
    echo "  1. Connect to MySQL/MariaDB"
    echo "  2. ALTER USER 'mailuser'@'localhost' IDENTIFIED BY 'newpassword';"
    echo "  3. Update the password in the config files above"
    echo "  4. Restart Postfix and Dovecot"
fi

echo ""
echo "============================================"
echo "WEBMAIL APPLICATIONS"
echo "============================================"

# Check for common webmail installations
WEBMAIL_FOUND=0

# Roundcube
if [ -d "/var/www/roundcube" ] || [ -d "/usr/share/roundcube" ] || [ -d "/var/www/html/roundcube" ]; then
    echo "Roundcube webmail detected."
    echo "Admin credentials may be in database or config.inc.php"
    WEBMAIL_FOUND=1
fi

# Squirrelmail
if [ -d "/usr/share/squirrelmail" ] || [ -d "/var/www/squirrelmail" ]; then
    echo "SquirrelMail webmail detected."
    WEBMAIL_FOUND=1
fi

# Rainloop
if [ -d "/var/www/rainloop" ] || [ -d "/var/www/html/rainloop" ]; then
    echo "Rainloop webmail detected."
    echo "Admin panel: http://server/?admin (default: admin/12345)"
    WEBMAIL_FOUND=1
fi

if [ $WEBMAIL_FOUND -eq 0 ]; then
    echo "No common webmail applications detected."
fi

echo ""
echo "============================================"
echo "CREDENTIAL ROTATION COMPLETE"
echo "============================================"
echo ""
echo "New credentials saved to: $CRED_FILE"
echo ""
echo "IMPORTANT POST-ROTATION STEPS:"
echo "1. Record credentials securely"
echo "2. Test mail authentication:"
echo "   - IMAP: openssl s_client -connect localhost:993"
echo "   - SMTP: openssl s_client -connect localhost:587 -starttls smtp"
echo "3. Test sending/receiving email"
echo "4. Update any mail clients with new passwords"
echo "5. Delete $CRED_FILE after recording"
echo ""

log "Credential rotation complete"
