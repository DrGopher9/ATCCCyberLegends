#!/bin/bash
###############################################################################
# 06-postfix-harden.sh - Postfix MTA Hardening
# Target: Linux Mail Server with Postfix
# Purpose: Secure Postfix configuration, prevent open relay
###############################################################################

set -euo pipefail

LOGFILE="/root/ccdc-logs/postfix_harden_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR="/root/ccdc-backups/postfix_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$(dirname "$LOGFILE")" "$BACKUP_DIR"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOGFILE"
}

section() {
    echo "" | tee -a "$LOGFILE"
    echo "========================================" | tee -a "$LOGFILE"
    echo "=== $1" | tee -a "$LOGFILE"
    echo "========================================" | tee -a "$LOGFILE"
}

log "Starting Postfix hardening..."

# Check if Postfix is installed
if ! command -v postconf &> /dev/null; then
    log "ERROR: Postfix is not installed"
    exit 1
fi

# Backup current configuration
log "Backing up Postfix configuration..."
cp -a /etc/postfix "$BACKUP_DIR/"
postconf -n > "$BACKUP_DIR/postconf-n-before.txt"

section "CURRENT POSTFIX CONFIGURATION AUDIT"

echo "--- Version ---" | tee -a "$LOGFILE"
postconf mail_version 2>/dev/null | tee -a "$LOGFILE"

echo "" | tee -a "$LOGFILE"
echo "--- Critical Security Settings ---" | tee -a "$LOGFILE"
echo "myhostname: $(postconf -h myhostname)" | tee -a "$LOGFILE"
echo "mydomain: $(postconf -h mydomain)" | tee -a "$LOGFILE"
echo "mynetworks: $(postconf -h mynetworks)" | tee -a "$LOGFILE"
echo "relay_domains: $(postconf -h relay_domains)" | tee -a "$LOGFILE"
echo "smtpd_relay_restrictions: $(postconf -h smtpd_relay_restrictions 2>/dev/null || echo 'not set')" | tee -a "$LOGFILE"
echo "smtpd_recipient_restrictions: $(postconf -h smtpd_recipient_restrictions 2>/dev/null || echo 'not set')" | tee -a "$LOGFILE"

# Check for open relay
MYNETWORKS=$(postconf -h mynetworks)
if echo "$MYNETWORKS" | grep -qE "0\.0\.0\.0/0|::/0"; then
    echo "" | tee -a "$LOGFILE"
    echo "[CRITICAL] SERVER MAY BE AN OPEN RELAY!" | tee -a "$LOGFILE"
    echo "mynetworks contains 0.0.0.0/0 - this allows anyone to relay!" | tee -a "$LOGFILE"
fi

echo ""
echo "============================================"
echo "POSTFIX HARDENING OPTIONS"
echo "============================================"
echo ""

read -p "Apply Postfix security hardening? (y/N): " -r REPLY
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log "Aborted by user"
    exit 0
fi

section "APPLYING POSTFIX HARDENING"

# 1. Fix mynetworks (prevent open relay)
log "Configuring mynetworks (prevent open relay)..."
echo ""
echo "Current mynetworks: $MYNETWORKS"
echo ""
echo "Recommended: 127.0.0.0/8 [::1]/128 (localhost only)"
echo "Or add your internal network: 127.0.0.0/8 [::1]/128 172.20.0.0/16"
echo ""
read -p "Set mynetworks to localhost only? (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    postconf -e "mynetworks = 127.0.0.0/8 [::1]/128"
    log "mynetworks set to localhost only"
else
    read -p "Enter custom mynetworks (or press Enter to skip): " -r CUSTOM_NETWORKS
    if [ -n "$CUSTOM_NETWORKS" ]; then
        postconf -e "mynetworks = $CUSTOM_NETWORKS"
        log "mynetworks set to: $CUSTOM_NETWORKS"
    fi
fi

# 2. Configure relay restrictions
log "Configuring relay restrictions..."
postconf -e "smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination"
log "smtpd_relay_restrictions configured"

# 3. Configure recipient restrictions (anti-spam)
log "Configuring recipient restrictions..."
postconf -e "smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, reject_unknown_recipient_domain"
log "smtpd_recipient_restrictions configured"

# 4. Configure HELO restrictions
log "Configuring HELO restrictions..."
postconf -e "smtpd_helo_required = yes"
postconf -e "smtpd_helo_restrictions = permit_mynetworks, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname"
log "HELO restrictions configured"

# 5. Configure sender restrictions
log "Configuring sender restrictions..."
postconf -e "smtpd_sender_restrictions = reject_unknown_sender_domain, reject_non_fqdn_sender"
log "Sender restrictions configured"

# 6. Disable VRFY command (user enumeration)
log "Disabling VRFY command..."
postconf -e "disable_vrfy_command = yes"
log "VRFY disabled"

# 7. Hide version in banner
log "Configuring SMTP banner..."
HOSTNAME=$(postconf -h myhostname)
postconf -e "smtpd_banner = \$myhostname ESMTP"
log "SMTP banner simplified (version hidden)"

# 8. TLS Configuration
section "TLS/SSL CONFIGURATION"
echo "Current TLS settings:" | tee -a "$LOGFILE"
postconf smtpd_tls_cert_file 2>/dev/null | tee -a "$LOGFILE" || true
postconf smtpd_tls_key_file 2>/dev/null | tee -a "$LOGFILE" || true
postconf smtpd_tls_security_level 2>/dev/null | tee -a "$LOGFILE" || true

read -p "Configure TLS settings? (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Check for existing certificates
    CERT_FILE=$(postconf -h smtpd_tls_cert_file 2>/dev/null || echo "")

    if [ -z "$CERT_FILE" ] || [ ! -f "$CERT_FILE" ]; then
        echo "No TLS certificate configured or file not found."
        echo "Common certificate locations:"
        echo "  /etc/ssl/certs/ssl-cert-snakeoil.pem (self-signed)"
        echo "  /etc/letsencrypt/live/domain/fullchain.pem"
        echo "  /etc/pki/tls/certs/mail.crt"
        read -p "Enter certificate path (or Enter to skip TLS): " -r CERT_PATH
        if [ -n "$CERT_PATH" ] && [ -f "$CERT_PATH" ]; then
            read -p "Enter key path: " -r KEY_PATH
            if [ -n "$KEY_PATH" ] && [ -f "$KEY_PATH" ]; then
                postconf -e "smtpd_tls_cert_file = $CERT_PATH"
                postconf -e "smtpd_tls_key_file = $KEY_PATH"
                CERT_FILE="$CERT_PATH"
            fi
        fi
    fi

    if [ -n "$CERT_FILE" ] && [ -f "$CERT_FILE" ]; then
        # Configure TLS
        postconf -e "smtpd_tls_security_level = may"
        postconf -e "smtpd_tls_auth_only = yes"
        postconf -e "smtpd_tls_loglevel = 1"
        postconf -e "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
        postconf -e "smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
        postconf -e "smtpd_tls_mandatory_ciphers = high"
        postconf -e "smtpd_tls_exclude_ciphers = aNULL, MD5, DES, 3DES, RC4"

        # Outbound TLS
        postconf -e "smtp_tls_security_level = may"
        postconf -e "smtp_tls_loglevel = 1"

        log "TLS configured with modern settings"
    fi
fi

# 9. Rate limiting
section "RATE LIMITING"
read -p "Configure rate limiting? (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Connection rate limiting
    postconf -e "smtpd_client_connection_rate_limit = 50"
    postconf -e "smtpd_client_message_rate_limit = 100"
    postconf -e "smtpd_client_recipient_rate_limit = 100"
    postconf -e "smtpd_error_sleep_time = 1s"
    postconf -e "smtpd_soft_error_limit = 5"
    postconf -e "smtpd_hard_error_limit = 10"

    log "Rate limiting configured"
fi

# 10. Message size limits
section "MESSAGE SIZE LIMITS"
CURRENT_SIZE=$(postconf -h message_size_limit)
echo "Current message_size_limit: $CURRENT_SIZE bytes ($(( CURRENT_SIZE / 1024 / 1024 ))MB)" | tee -a "$LOGFILE"
read -p "Set message size limit to 25MB? (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    postconf -e "message_size_limit = 26214400"
    log "Message size limit set to 25MB"
fi

# 11. Mailbox size limits
CURRENT_MAILBOX=$(postconf -h mailbox_size_limit)
echo "Current mailbox_size_limit: $CURRENT_MAILBOX bytes" | tee -a "$LOGFILE"
read -p "Set mailbox size limit to 500MB? (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    postconf -e "mailbox_size_limit = 524288000"
    log "Mailbox size limit set to 500MB"
fi

# Verify configuration
section "VERIFYING CONFIGURATION"
log "Checking Postfix configuration..."
if postfix check 2>&1 | tee -a "$LOGFILE"; then
    log "Postfix configuration is valid"
else
    log "WARNING: Postfix configuration check returned warnings"
fi

# Restart Postfix
echo ""
read -p "Restart Postfix to apply changes? (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log "Restarting Postfix..."
    systemctl restart postfix
    if systemctl is-active --quiet postfix; then
        log "Postfix restarted successfully"
    else
        log "ERROR: Postfix failed to restart!"
        echo "Restoring backup..."
        cp "$BACKUP_DIR/main.cf" /etc/postfix/main.cf
        systemctl restart postfix
        exit 1
    fi
else
    log "Restart skipped. Run 'systemctl restart postfix' when ready."
fi

# Show final configuration
section "FINAL CONFIGURATION"
echo "Key security settings after hardening:" | tee -a "$LOGFILE"
postconf mynetworks smtpd_relay_restrictions smtpd_recipient_restrictions disable_vrfy_command smtpd_helo_required smtpd_tls_security_level 2>/dev/null | tee -a "$LOGFILE"

echo ""
echo "============================================"
echo "POSTFIX HARDENING COMPLETE"
echo "============================================"
echo ""
echo "Applied hardening:"
echo "  - mynetworks restricted"
echo "  - Relay restrictions configured"
echo "  - VRFY command disabled"
echo "  - HELO/sender restrictions enabled"
echo "  - SMTP banner simplified"
echo "  - TLS configured (if certificates available)"
echo "  - Rate limiting (if selected)"
echo ""
echo "Backup location: $BACKUP_DIR"
echo ""
echo "VERIFICATION:"
echo "  1. Send test email from external source"
echo "  2. Check relay is blocked: telnet localhost 25"
echo "     MAIL FROM: test@external.com"
echo "     RCPT TO: test@anotherdomain.com"
echo "     (should be rejected with 'Relay access denied')"
echo "  3. Check logs: tail -f /var/log/mail.log"
echo ""

log "Postfix hardening complete"
