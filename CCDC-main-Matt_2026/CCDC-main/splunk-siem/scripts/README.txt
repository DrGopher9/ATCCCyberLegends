================================================================================
CCDC SPLUNK SIEM HARDENING SCRIPTS
================================================================================

Target: Splunk Enterprise on Linux
Network: Public Zone

================================================================================
QUICK START
================================================================================

1. Transfer scripts to the Splunk server:
   scp -r scripts/ root@splunk-server:/opt/splunk-ccdc-scripts/

2. Make scripts executable:
   chmod +x /opt/splunk-ccdc-scripts/*.sh

3. Run the master runbook:
   cd /opt/splunk-ccdc-scripts
   ./00-SPLUNK-RUNBOOK.sh

================================================================================
SCRIPTS
================================================================================

00-SPLUNK-RUNBOOK.sh     - Master runbook with guided execution
00-splunk-recon.sh       - Reconnaissance and information gathering
01-splunk-backup.sh      - Backup Splunk configuration and data
02-splunk-user-audit.sh  - Audit Splunk and system users
03-splunk-credential-rotation.sh - Rotate passwords
04-splunk-ssh-harden.sh  - SSH hardening
05-splunk-firewall.sh    - Firewall configuration
06-splunk-harden.sh      - Splunk application hardening
07-splunk-logging.sh     - Logging and monitoring setup
08-splunk-incident-response.sh - Incident response actions

================================================================================
STANDARD SPLUNK PORTS
================================================================================

8000  - Splunk Web Interface (HTTPS)
8089  - Splunkd REST API / Management Port
9997  - Forwarder Receiving Port (Indexer input)
8088  - HTTP Event Collector (HEC)
514   - Syslog receiving (TCP/UDP)
9998  - Replication port (clustering)
8191  - KV Store

================================================================================
CRITICAL FILES
================================================================================

Configuration:
  /opt/splunk/etc/system/local/   - Local configuration overrides
  /opt/splunk/etc/passwd          - Splunk user accounts
  /opt/splunk/etc/auth/           - SSL certificates and secrets

Logs:
  /opt/splunk/var/log/splunk/audit.log        - User activity audit
  /opt/splunk/var/log/splunk/splunkd.log      - Main Splunk daemon log
  /opt/splunk/var/log/splunk/splunkd_access.log - Web access log

Data:
  /opt/splunk/var/lib/splunk/     - Index data storage

================================================================================
QUICK COMMANDS
================================================================================

# Check status
/opt/splunk/bin/splunk status

# Restart Splunk
/opt/splunk/bin/splunk restart

# List users
/opt/splunk/bin/splunk list user -auth admin:password

# Change password
/opt/splunk/bin/splunk edit user USERNAME -password NEWPASS -auth admin:pass

# Validate configuration
/opt/splunk/bin/splunk btool check

# View effective configuration
/opt/splunk/bin/splunk btool server list --debug

# Search audit log for failed logins
grep "login_failed" /opt/splunk/var/log/splunk/audit.log

================================================================================
USEFUL SPLUNK SEARCHES
================================================================================

# Failed login attempts
index=_audit action=login_failed | stats count by user, src

# All admin activity
index=_audit user=admin | table _time, action, info

# Configuration changes
index=_audit action=edit_* | table _time, user, action, object

# New users created
index=_audit action=edit_user info=granted | table _time, user, object

# Forwarder status
| metadata type=hosts index=* | table host, lastTime

# Index health
| dbinspect index=* | stats sum(sizeOnDiskMB) by index

================================================================================
SCORING ENGINE CONSIDERATIONS
================================================================================

Ensure the following are allowed through the firewall:
- Splunk Web (8000) for scoring checks
- REST API (8089) for health checks
- Forwarder receiving (9997) if receiving data from scoring

Do NOT disable services required for scoring!

================================================================================
INCIDENT RESPONSE QUICK ACTIONS
================================================================================

Disable Splunk user:
  /opt/splunk/bin/splunk edit user USERNAME -locked-out true -auth admin:pass

Block IP:
  ufw deny from IP_ADDRESS
  # or
  iptables -I INPUT -s IP_ADDRESS -j DROP

Kill process:
  kill -9 PID

Export audit logs:
  cp /opt/splunk/var/log/splunk/audit.log /tmp/audit_backup.log

Emergency - disable web:
  echo "[settings]" > /opt/splunk/etc/system/local/web.conf
  echo "startwebserver = false" >> /opt/splunk/etc/system/local/web.conf
  /opt/splunk/bin/splunk restart

================================================================================
AFTER HARDENING CHECKLIST
================================================================================

[ ] Splunk Web accessible at https://hostname:8000
[ ] Can login with new admin credentials
[ ] Forwarders are sending data (check index=_internal)
[ ] Alerts are configured and triggering
[ ] Audit logging is enabled
[ ] SSH access works with new configuration
[ ] Firewall rules allow required traffic
[ ] Credentials documented securely

================================================================================
