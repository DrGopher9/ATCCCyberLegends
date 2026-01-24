================================================================================
CCDC MAIL SERVER HARDENING SCRIPTS
Postfix + Dovecot on Linux
================================================================================

QUICK START:
  cd scripts/
  chmod +x *.sh
  sudo ./00-MAIL-RUNBOOK.sh

================================================================================
SCRIPT EXECUTION ORDER (First 15 Minutes)
================================================================================

PHASE 1 - RECON (Minute 0-2)
  ./00-mail-recon.sh
  - Gathers Postfix/Dovecot config, users, queue status
  - READ-ONLY, makes no changes
  - Output: /root/ccdc-logs/mail_recon_*.txt

PHASE 2 - BACKUP (Minute 2-4)
  ./01-mail-backup.sh
  - Backs up Postfix, Dovecot, SSL certs, aliases
  - RUN THIS BEFORE ANY CHANGES
  - Output: /root/ccdc-backups/

PHASE 3 - ACCESS CONTROL (Minute 4-10)
  ./02-mail-user-audit.sh
  - Lists system users, mail users, SSH keys
  - Option to clear authorized_keys

  ./03-mail-credential-rotation.sh
  - Changes Linux user passwords
  - Changes Dovecot user passwords
  - Changes SASL passwords
  - Output: /root/ccdc-logs/MAIL_CREDENTIALS_*.txt

  ./04-mail-ssh-harden.sh
  - Disables root password login
  - Limits auth attempts
  - KEEP SESSION OPEN while testing!

PHASE 4 - NETWORK (Minute 10-12)
  ./05-mail-firewall.sh
  - Configures firewall for mail ports
  - Allows: SSH, SMTP, SMTPS, Submission, IMAPS
  - Supports: firewalld, ufw, iptables

PHASE 5 - MAIL SERVICES (Minute 12-18) - CRITICAL!
  ./06-postfix-harden.sh
  - PREVENTS OPEN RELAY (most important!)
  - Restricts mynetworks
  - Configures relay restrictions
  - Enables TLS
  - Hides version banner

  ./07-dovecot-harden.sh
  - Enforces SSL/TLS
  - Disables plaintext auth
  - Configures modern ciphers
  - Sets up SASL for Postfix

PHASE 6 - MONITORING (After Initial Hardening)
  ./08-mail-logging.sh
  - Configures auditd for mail configs
  - Sets up fail2ban for mail services
  - Creates monitoring scripts

PHASE 7 - INCIDENT RESPONSE (As Needed)
  ./09-mail-incident-response.sh
  - Block IPs, clear queue, emergency fixes

================================================================================
MAIL SERVER QUICK REFERENCE
================================================================================

CHECK STATUS:
  systemctl status postfix dovecot

CHECK MAIL QUEUE:
  mailq
  postqueue -p

FLUSH QUEUE:
  postqueue -f                    # Try to deliver deferred
  postsuper -d ALL                # Delete ALL mail
  postsuper -d ALL deferred       # Delete deferred only

TEST SMTP:
  telnet localhost 25
  openssl s_client -connect localhost:465
  openssl s_client -connect localhost:587 -starttls smtp

TEST IMAP:
  openssl s_client -connect localhost:993
  openssl s_client -connect localhost:143 -starttls imap

CHECK OPEN RELAY:
  postconf mynetworks
  postconf smtpd_relay_restrictions
  # Test from external host:
  telnet mailserver 25
  MAIL FROM: <test@external.com>
  RCPT TO: <test@anotherdomain.com>
  # Should get: "Relay access denied"

VIEW LOGS:
  tail -f /var/log/mail.log       # Debian/Ubuntu
  tail -f /var/log/maillog        # RHEL/CentOS
  journalctl -u postfix -f
  journalctl -u dovecot -f

================================================================================
MONITORING SCRIPTS (after running 08-mail-logging.sh)
================================================================================

  /root/ccdc-logs/mail-monitor.sh auth     # Watch auth attempts
  /root/ccdc-logs/mail-monitor.sh queue    # Watch mail queue
  /root/ccdc-logs/mail-monitor.sh attacks  # Watch for attacks
  /root/ccdc-logs/mail-monitor.sh all      # Watch all logs

  /root/ccdc-logs/mail-detect.sh           # Run threat detection
  /root/ccdc-logs/mail-stats.sh            # Mail statistics

================================================================================
EMERGENCY PROCEDURES
================================================================================

STOP SPAM FLOOD:
  postsuper -d ALL                # Clear queue
  postconf -e "smtpd_client_connection_rate_limit = 5"
  postfix reload

BLOCK MALICIOUS IP:
  echo "1.2.3.4 REJECT" >> /etc/postfix/client_access
  postmap /etc/postfix/client_access
  postfix reload

EMERGENCY DISABLE RELAY:
  postconf -e "mynetworks = 127.0.0.0/8"
  postconf -e "smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination"
  postfix reload

RESTART SERVICES:
  systemctl restart postfix
  systemctl restart dovecot

================================================================================
IMPORTANT REMINDERS
================================================================================

1. NEVER allow open relay - check mynetworks immediately
2. Keep SMTP (25) open for receiving mail from scoring engine
3. Submission (587) and SMTPS (465) for authenticated sending
4. IMAPS (993) for mail clients
5. Document all changes for White Team
6. Test sending AND receiving after changes
7. Watch for spam abuse - check queue frequently
8. Monitor for brute force auth attempts

================================================================================
COMMON ISSUES
================================================================================

"Relay access denied" for legitimate users:
  - Ensure SASL auth is working
  - Check: postconf smtpd_sasl_auth_enable
  - User must authenticate before sending

Mail not being received:
  - Check MX records point to this server
  - Check firewall allows port 25
  - Check: postconf mydestination
  - Check: postconf virtual_mailbox_domains

Users can't login to IMAP:
  - Check Dovecot is running
  - Check SSL certificates are valid
  - Check auth mechanism in Dovecot config
  - Check: doveconf -n passdb

================================================================================
