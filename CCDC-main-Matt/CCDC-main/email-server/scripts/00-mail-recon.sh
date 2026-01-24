#!/bin/bash
###############################################################################
# 00-mail-recon.sh - Mail Server Reconnaissance
# Target: Linux Mail Server (Postfix + Dovecot)
# Purpose: Gather critical mail server information in first 5 minutes
# DEFENSIVE ONLY - No modifications made
###############################################################################

set -euo pipefail

LOGDIR="/root/ccdc-logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="${LOGDIR}/mail_recon_${TIMESTAMP}.txt"

mkdir -p "$LOGDIR"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$REPORT"
}

section() {
    echo "" | tee -a "$REPORT"
    echo "============================================================" | tee -a "$REPORT"
    echo "=== $1" | tee -a "$REPORT"
    echo "============================================================" | tee -a "$REPORT"
}

log "Starting mail server reconnaissance on $(hostname)"

section "SYSTEM INFORMATION"
echo "Hostname: $(hostname)" >> "$REPORT"
echo "FQDN: $(hostname -f 2>/dev/null || echo 'unknown')" >> "$REPORT"
echo "IP Addresses:" >> "$REPORT"
ip -4 addr show | grep inet >> "$REPORT" 2>/dev/null || true
echo "OS Version:" >> "$REPORT"
cat /etc/os-release >> "$REPORT" 2>/dev/null || true
echo "Kernel: $(uname -r)" >> "$REPORT"

section "MAIL SERVICES STATUS"
echo "--- Postfix ---" >> "$REPORT"
systemctl status postfix 2>/dev/null >> "$REPORT" || echo "Postfix not found via systemctl" >> "$REPORT"
postconf mail_version 2>/dev/null >> "$REPORT" || true
echo "" >> "$REPORT"
echo "--- Dovecot ---" >> "$REPORT"
systemctl status dovecot 2>/dev/null >> "$REPORT" || echo "Dovecot not found via systemctl" >> "$REPORT"
dovecot --version 2>/dev/null >> "$REPORT" || true

section "POSTFIX CONFIGURATION"
echo "--- Main Settings ---" >> "$REPORT"
postconf -n 2>/dev/null >> "$REPORT" || echo "Cannot read Postfix config" >> "$REPORT"
echo "" >> "$REPORT"
echo "--- Virtual Domains ---" >> "$REPORT"
postconf virtual_mailbox_domains 2>/dev/null >> "$REPORT" || true
postconf virtual_alias_maps 2>/dev/null >> "$REPORT" || true
echo "" >> "$REPORT"
echo "--- Relay Settings ---" >> "$REPORT"
postconf mynetworks 2>/dev/null >> "$REPORT" || true
postconf relay_domains 2>/dev/null >> "$REPORT" || true
postconf smtpd_relay_restrictions 2>/dev/null >> "$REPORT" || true

section "DOVECOT CONFIGURATION"
echo "--- Protocols ---" >> "$REPORT"
doveconf protocols 2>/dev/null >> "$REPORT" || true
echo "" >> "$REPORT"
echo "--- Auth Settings ---" >> "$REPORT"
doveconf -n auth 2>/dev/null | head -50 >> "$REPORT" || true
echo "" >> "$REPORT"
echo "--- SSL Settings ---" >> "$REPORT"
doveconf ssl 2>/dev/null >> "$REPORT" || true
doveconf ssl_cert 2>/dev/null >> "$REPORT" || true

section "MAIL QUEUE"
echo "--- Queue Status ---" >> "$REPORT"
mailq 2>/dev/null | tail -20 >> "$REPORT" || postqueue -p 2>/dev/null | tail -20 >> "$REPORT" || echo "Cannot check queue" >> "$REPORT"
echo "" >> "$REPORT"
echo "Queue count: $(mailq 2>/dev/null | grep -c "^[A-F0-9]" || echo 'unknown')" >> "$REPORT"

section "MAIL USERS"
echo "--- Virtual Mailboxes (if configured) ---" >> "$REPORT"
VMAIL_FILE=$(postconf -h virtual_mailbox_maps 2>/dev/null | sed 's/hash://' | sed 's/mysql:.*/[mysql]/' | sed 's/ldap:.*/[ldap]/')
if [ -f "$VMAIL_FILE" ]; then
    cat "$VMAIL_FILE" 2>/dev/null >> "$REPORT" || true
else
    echo "Virtual mailbox file: $VMAIL_FILE" >> "$REPORT"
fi
echo "" >> "$REPORT"
echo "--- System mail users ---" >> "$REPORT"
grep -E '/var/(mail|spool/mail)' /etc/passwd 2>/dev/null >> "$REPORT" || true
echo "" >> "$REPORT"
echo "--- Mail directories ---" >> "$REPORT"
ls -la /var/mail/ 2>/dev/null >> "$REPORT" || true
ls -la /var/vmail/ 2>/dev/null >> "$REPORT" || true
ls -la /home/vmail/ 2>/dev/null >> "$REPORT" || true

section "SSL/TLS CERTIFICATES"
echo "--- Postfix SSL ---" >> "$REPORT"
postconf smtpd_tls_cert_file 2>/dev/null >> "$REPORT" || true
postconf smtpd_tls_key_file 2>/dev/null >> "$REPORT" || true
CERT_FILE=$(postconf -h smtpd_tls_cert_file 2>/dev/null)
if [ -f "$CERT_FILE" ]; then
    echo "Certificate expires:" >> "$REPORT"
    openssl x509 -in "$CERT_FILE" -noout -enddate 2>/dev/null >> "$REPORT" || true
fi
echo "" >> "$REPORT"
echo "--- Dovecot SSL ---" >> "$REPORT"
doveconf ssl_cert 2>/dev/null >> "$REPORT" || true

section "LISTENING PORTS"
echo "--- Mail-related ports ---" >> "$REPORT"
ss -tlnp 2>/dev/null | grep -E ':(25|110|143|465|587|993|995)\s' >> "$REPORT" || netstat -tlnp 2>/dev/null | grep -E ':(25|110|143|465|587|993|995)\s' >> "$REPORT" || true
echo "" >> "$REPORT"
echo "--- All listening TCP ---" >> "$REPORT"
ss -tlnp 2>/dev/null >> "$REPORT" || netstat -tlnp >> "$REPORT" 2>/dev/null || true

section "SYSTEM USERS"
echo "--- Users with login shells ---" >> "$REPORT"
grep -E '/bin/(bash|sh|zsh)$' /etc/passwd >> "$REPORT" 2>/dev/null || true
echo "" >> "$REPORT"
echo "--- Sudoers ---" >> "$REPORT"
getent group sudo 2>/dev/null >> "$REPORT" || getent group wheel 2>/dev/null >> "$REPORT" || true

section "SSH CONFIGURATION"
echo "--- SSH authorized_keys ---" >> "$REPORT"
find /home /root -name "authorized_keys" -type f 2>/dev/null >> "$REPORT" || true
echo "" >> "$REPORT"
echo "--- SSHD key settings ---" >> "$REPORT"
grep -E '^(PermitRootLogin|PasswordAuthentication|Port)' /etc/ssh/sshd_config 2>/dev/null >> "$REPORT" || true

section "FIREWALL STATUS"
echo "--- iptables ---" >> "$REPORT"
iptables -L -n 2>/dev/null | head -30 >> "$REPORT" || true
echo "" >> "$REPORT"
echo "--- firewalld ---" >> "$REPORT"
firewall-cmd --list-all 2>/dev/null >> "$REPORT" || echo "firewalld not active" >> "$REPORT"
echo "" >> "$REPORT"
echo "--- ufw ---" >> "$REPORT"
ufw status 2>/dev/null >> "$REPORT" || echo "ufw not active" >> "$REPORT"

section "RECENT MAIL LOGS"
echo "--- Last 30 mail log entries ---" >> "$REPORT"
tail -30 /var/log/mail.log 2>/dev/null >> "$REPORT" || tail -30 /var/log/maillog 2>/dev/null >> "$REPORT" || journalctl -u postfix -n 30 2>/dev/null >> "$REPORT" || true

section "SUSPICIOUS INDICATORS"
echo "--- Open relays check ---" >> "$REPORT"
MYNETWORKS=$(postconf -h mynetworks 2>/dev/null)
echo "mynetworks = $MYNETWORKS" >> "$REPORT"
if echo "$MYNETWORKS" | grep -q "0.0.0.0/0"; then
    echo "[CRITICAL] Server may be an open relay!" >> "$REPORT"
fi
echo "" >> "$REPORT"
echo "--- Auth mechanisms ---" >> "$REPORT"
postconf smtpd_sasl_auth_enable 2>/dev/null >> "$REPORT" || true
echo "" >> "$REPORT"
echo "--- Recent authentication failures ---" >> "$REPORT"
grep -i "auth.*fail\|login.*fail\|authentication fail" /var/log/mail.log 2>/dev/null | tail -10 >> "$REPORT" || true
grep -i "auth.*fail\|login.*fail\|authentication fail" /var/log/maillog 2>/dev/null | tail -10 >> "$REPORT" || true

section "CRON JOBS"
echo "--- Root crontab ---" >> "$REPORT"
crontab -l 2>/dev/null >> "$REPORT" || echo "No root crontab" >> "$REPORT"
echo "" >> "$REPORT"
echo "--- /etc/cron.d ---" >> "$REPORT"
ls -la /etc/cron.d/ 2>/dev/null >> "$REPORT" || true

log "Reconnaissance complete. Report saved to: $REPORT"
echo ""
echo "QUICK SUMMARY:"
echo "=============="
echo "Postfix: $(systemctl is-active postfix 2>/dev/null || echo 'unknown')"
echo "Dovecot: $(systemctl is-active dovecot 2>/dev/null || echo 'unknown')"
echo "Mail queue: $(mailq 2>/dev/null | grep -c "^[A-F0-9]" || echo 'unknown') messages"
echo "Users with shells: $(grep -cE '/bin/(bash|sh|zsh)$' /etc/passwd)"
echo ""
echo "Review full report: $REPORT"
