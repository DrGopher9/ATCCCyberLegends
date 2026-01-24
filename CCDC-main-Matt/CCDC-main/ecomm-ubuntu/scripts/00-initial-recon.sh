#!/bin/bash
###############################################################################
# 00-initial-recon.sh - Initial System Reconnaissance
# Target: Ubuntu 24 E-Commerce Server (PrestaShop + MySQL)
# Purpose: Gather critical system information in first 5 minutes
# DEFENSIVE ONLY - No modifications made
###############################################################################

set -euo pipefail

LOGDIR="/root/ccdc-logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="${LOGDIR}/recon_${TIMESTAMP}.txt"

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

log "Starting reconnaissance on $(hostname)"

section "SYSTEM INFORMATION"
echo "Hostname: $(hostname)" >> "$REPORT"
echo "IP Addresses:" >> "$REPORT"
ip -4 addr show | grep inet >> "$REPORT" 2>/dev/null || true
echo "OS Version:" >> "$REPORT"
cat /etc/os-release >> "$REPORT" 2>/dev/null || true
echo "Kernel: $(uname -r)" >> "$REPORT"
echo "Uptime: $(uptime)" >> "$REPORT"

section "USER ACCOUNTS"
echo "--- /etc/passwd (human users UID >= 1000) ---" >> "$REPORT"
awk -F: '$3 >= 1000 && $3 < 65534 {print $1":"$3":"$6":"$7}' /etc/passwd >> "$REPORT"
echo "" >> "$REPORT"
echo "--- Users with login shells ---" >> "$REPORT"
grep -E '/bin/(bash|sh|zsh)$' /etc/passwd >> "$REPORT" 2>/dev/null || true
echo "" >> "$REPORT"
echo "--- Sudoers ---" >> "$REPORT"
getent group sudo 2>/dev/null >> "$REPORT" || true
getent group wheel 2>/dev/null >> "$REPORT" || true
cat /etc/sudoers.d/* 2>/dev/null >> "$REPORT" || echo "No sudoers.d files" >> "$REPORT"

section "SSH CONFIGURATION"
echo "--- SSH authorized_keys locations ---" >> "$REPORT"
find /home /root -name "authorized_keys" -type f 2>/dev/null >> "$REPORT" || true
echo "" >> "$REPORT"
echo "--- SSHD Config (key settings) ---" >> "$REPORT"
grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|Port)' /etc/ssh/sshd_config 2>/dev/null >> "$REPORT" || true

section "LISTENING SERVICES"
echo "--- Listening TCP Ports ---" >> "$REPORT"
ss -tlnp 2>/dev/null >> "$REPORT" || netstat -tlnp >> "$REPORT" 2>/dev/null || true
echo "" >> "$REPORT"
echo "--- Listening UDP Ports ---" >> "$REPORT"
ss -ulnp 2>/dev/null >> "$REPORT" || netstat -ulnp >> "$REPORT" 2>/dev/null || true

section "RUNNING SERVICES"
systemctl list-units --type=service --state=running 2>/dev/null >> "$REPORT" || true

section "CRON JOBS"
echo "--- System crontabs ---" >> "$REPORT"
cat /etc/crontab 2>/dev/null >> "$REPORT" || true
echo "" >> "$REPORT"
echo "--- Cron directories ---" >> "$REPORT"
ls -la /etc/cron.d/ 2>/dev/null >> "$REPORT" || true
ls -la /etc/cron.daily/ 2>/dev/null >> "$REPORT" || true
echo "" >> "$REPORT"
echo "--- User crontabs ---" >> "$REPORT"
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -l -u "$user" 2>/dev/null && echo "^^^ $user ^^^" >> "$REPORT"
done

section "SUSPICIOUS PROCESSES"
echo "--- Processes running as root ---" >> "$REPORT"
ps aux | grep -E '^root' | head -30 >> "$REPORT"
echo "" >> "$REPORT"
echo "--- Processes with network connections ---" >> "$REPORT"
lsof -i -n -P 2>/dev/null | head -50 >> "$REPORT" || true

section "WEB SERVER"
echo "--- Apache/Nginx Status ---" >> "$REPORT"
systemctl status apache2 2>/dev/null >> "$REPORT" || true
systemctl status nginx 2>/dev/null >> "$REPORT" || true
echo "" >> "$REPORT"
echo "--- Web root contents ---" >> "$REPORT"
ls -la /var/www/ 2>/dev/null >> "$REPORT" || true
ls -la /var/www/html/ 2>/dev/null >> "$REPORT" || true

section "MYSQL STATUS"
echo "--- MySQL Service ---" >> "$REPORT"
systemctl status mysql 2>/dev/null >> "$REPORT" || systemctl status mariadb 2>/dev/null >> "$REPORT" || true
echo "" >> "$REPORT"
echo "--- MySQL Users (if accessible) ---" >> "$REPORT"
mysql -e "SELECT User,Host,plugin FROM mysql.user;" 2>/dev/null >> "$REPORT" || echo "Cannot access MySQL without credentials" >> "$REPORT"

section "PRESTASHOP INFO"
echo "--- Looking for PrestaShop installations ---" >> "$REPORT"
find /var/www -name "parameters.php" -o -name "settings.inc.php" 2>/dev/null >> "$REPORT" || true
echo "" >> "$REPORT"
echo "--- PrestaShop config (if found) ---" >> "$REPORT"
PSCONFIG=$(find /var/www -path "*/app/config/parameters.php" 2>/dev/null | head -1)
if [ -n "$PSCONFIG" ]; then
    echo "Found: $PSCONFIG" >> "$REPORT"
    grep -E '(database_|_prefix|cookie_key)' "$PSCONFIG" 2>/dev/null >> "$REPORT" || true
fi

section "FIREWALL STATUS"
echo "--- UFW Status ---" >> "$REPORT"
ufw status verbose 2>/dev/null >> "$REPORT" || echo "UFW not installed/configured" >> "$REPORT"
echo "" >> "$REPORT"
echo "--- iptables rules ---" >> "$REPORT"
iptables -L -n -v 2>/dev/null | head -50 >> "$REPORT" || true

section "RECENT LOGINS"
echo "--- Last logins ---" >> "$REPORT"
last -20 2>/dev/null >> "$REPORT" || true
echo "" >> "$REPORT"
echo "--- Failed logins ---" >> "$REPORT"
lastb -20 2>/dev/null >> "$REPORT" || grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20 >> "$REPORT" || true

section "SUSPICIOUS FILES"
echo "--- SUID binaries ---" >> "$REPORT"
find / -perm -4000 -type f 2>/dev/null | head -30 >> "$REPORT"
echo "" >> "$REPORT"
echo "--- World-writable files in /etc ---" >> "$REPORT"
find /etc -perm -002 -type f 2>/dev/null >> "$REPORT" || true
echo "" >> "$REPORT"
echo "--- Files modified in last 24h in /etc ---" >> "$REPORT"
find /etc -mtime -1 -type f 2>/dev/null >> "$REPORT" || true

log "Reconnaissance complete. Report saved to: $REPORT"
echo ""
echo "QUICK SUMMARY:"
echo "=============="
echo "Users with shells: $(grep -cE '/bin/(bash|sh|zsh)$' /etc/passwd)"
echo "Listening TCP ports: $(ss -tln 2>/dev/null | grep -c LISTEN || echo 'unknown')"
echo "Running services: $(systemctl list-units --type=service --state=running 2>/dev/null | grep -c running || echo 'unknown')"
echo ""
echo "Review full report: $REPORT"
