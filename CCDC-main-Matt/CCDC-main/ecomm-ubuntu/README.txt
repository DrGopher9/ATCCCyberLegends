================================================================================
CCDC E-COMMERCE SERVER HARDENING SCRIPTS
Ubuntu 24 + PrestaShop + MySQL
================================================================================

QUICK START:
  cd scripts/
  chmod +x *.sh
  sudo ./00-MASTER-RUNBOOK.sh

================================================================================
SCRIPT EXECUTION ORDER (First 15 Minutes)
================================================================================

PHASE 1 - RECON (Minute 0-2)
  ./00-initial-recon.sh
  - Gathers system info, users, services, network
  - READ-ONLY, makes no changes
  - Output: /root/ccdc-logs/recon_*.txt

PHASE 2 - BACKUP (Minute 2-4)
  ./01-backup-critical.sh
  - Backs up /etc, SSH, MySQL, web files
  - RUN THIS BEFORE ANY CHANGES
  - Output: /root/ccdc-backups/

PHASE 3 - ACCESS CONTROL (Minute 4-10)
  ./02-user-audit.sh
  - Lists all users, sudo access, SSH keys
  - Option to clear authorized_keys

  ./03-credential-rotation.sh
  - Changes Linux user passwords
  - Changes MySQL passwords
  - Changes PrestaShop admin password
  - Output: /root/ccdc-logs/NEW_CREDENTIALS_*.txt

  ./04-ssh-harden.sh
  - Disables root password login
  - Limits auth attempts
  - Disables forwarding
  - KEEP SESSION OPEN while testing!

PHASE 4 - NETWORK (Minute 10-12)
  ./05-firewall-setup.sh
  - Configures UFW firewall
  - Allows: SSH (22), HTTP (80), HTTPS (443)
  - Denies: Everything else inbound
  - Does NOT block scoring engine

PHASE 5 - APPLICATION (Minute 12-15)
  ./06-mysql-harden.sh
  - Removes anonymous users
  - Removes remote root access
  - Binds to localhost only

  ./07-prestashop-harden.sh
  - Removes install directory
  - Renames admin folder
  - Fixes permissions
  - Disables debug mode
  - Adds security headers

PHASE 6 - MONITORING (After Initial Hardening)
  ./08-logging-setup.sh
  - Configures auditd
  - Sets up fail2ban
  - Creates monitoring scripts

================================================================================
POST-HARDENING QUICK REFERENCE
================================================================================

MONITOR LOGS:
  /root/ccdc-logs/monitor.sh auth    # Watch authentication
  /root/ccdc-logs/monitor.sh web     # Watch web server
  /root/ccdc-logs/monitor.sh all     # Watch everything

DETECT THREATS:
  /root/ccdc-logs/detect.sh

ANALYZE WEB LOGS:
  /root/ccdc-logs/web-analyze.sh /var/log/apache2/access.log

BLOCK MALICIOUS IP:
  ufw deny from <IP> to any

VIEW BANNED IPS (fail2ban):
  fail2ban-client status sshd

UNBAN IP:
  fail2ban-client set sshd unbanip <IP>

CHECK SERVICES:
  systemctl status apache2 mysql ssh ufw

================================================================================
EMERGENCY ROLLBACK
================================================================================

If something breaks:

SSH Config:
  cp /root/ccdc-backups/<timestamp>/configs/ssh/sshd_config /etc/ssh/
  systemctl restart sshd

Firewall:
  ufw disable

MySQL:
  cp /root/ccdc-backups/<timestamp>/configs/mysql/* /etc/mysql/
  systemctl restart mysql

Full restore:
  Review /root/ccdc-backups/<timestamp>/MANIFEST.txt

================================================================================
IMPORTANT REMINDERS
================================================================================

1. NEVER block the scoring engine
2. Keep HTTP/HTTPS open to all (public access required)
3. Document all changes for White Team
4. Test services after each change
5. Keep one SSH session open during hardening
6. Record new credentials securely
7. Monitor logs for Red Team activity

================================================================================
