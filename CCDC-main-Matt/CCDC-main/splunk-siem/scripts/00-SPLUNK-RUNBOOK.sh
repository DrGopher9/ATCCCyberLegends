#!/bin/bash
#===============================================================================
# CCDC Splunk SIEM - First 15 Minutes Runbook
#===============================================================================
#
# Target: Splunk Enterprise on Linux
# Network: Public Zone
#
# Standard Splunk Ports:
#   8000  - Splunk Web (HTTPS)
#   8089  - Splunkd REST API / Management
#   9997  - Forwarder receiving
#   8088  - HTTP Event Collector (HEC)
#   514   - Syslog (TCP/UDP)
#
#===============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

cat << 'BANNER'

================================================================================
  CCDC SPLUNK SIEM - FIRST 15 MINUTES RUNBOOK
================================================================================

  Server Role: Security Information and Event Management (SIEM)
  Network: Public Zone

================================================================================
  SCRIPT EXECUTION ORDER
================================================================================

  PHASE 1: RECONNAISSANCE (Minute 0-2)
  ------------------------------------
  ./00-splunk-recon.sh

  - Check Splunk version and status
  - Review Splunk users and roles
  - List installed apps
  - Check data inputs and forwarders
  - Review SSL/TLS configuration
  - Output: /opt/splunk-ccdc-logs/splunk_recon_*.txt


  PHASE 2: BACKUP (Minute 2-4) - CRITICAL!
  ----------------------------------------
  ./01-splunk-backup.sh

  - Backup Splunk etc/ directory
  - Backup apps and configurations
  - Backup SSL certificates
  - Export saved searches and dashboards
  - Output: /opt/splunk-ccdc-backups/


  PHASE 3: USER AUDIT (Minute 4-6)
  --------------------------------
  ./02-splunk-user-audit.sh

  - Audit Splunk users and roles
  - Check Linux system users
  - Review SSH authorized keys
  - Identify suspicious apps
  - Option to disable users/apps


  PHASE 4: CREDENTIAL ROTATION (Minute 6-9) - CRITICAL!
  -----------------------------------------------------
  ./03-splunk-credential-rotation.sh

  - Change Splunk admin password
  - Create backup admin account
  - Change Linux root password
  - Change Splunk service account password
  - Output: /opt/splunk-ccdc-logs/CREDENTIALS_*.txt


  PHASE 5: SSH HARDENING (Minute 9-10)
  ------------------------------------
  ./04-splunk-ssh-harden.sh

  - Harden SSH configuration
  - Configure authentication methods
  - Review authorized keys
  - Set up SSH banner


  PHASE 6: FIREWALL CONFIGURATION (Minute 10-12)
  ----------------------------------------------
  ./05-splunk-firewall.sh

  - Configure firewall (UFW/firewalld/iptables)
  - Allow required Splunk ports
  - Block unauthorized access
  - Document allowed connections


  PHASE 7: SPLUNK HARDENING (Minute 12-14)
  ----------------------------------------
  ./06-splunk-harden.sh

  - Enable SSL/TLS
  - Configure password complexity
  - Disable unnecessary features
  - Secure file permissions
  - Restrict REST API access


  PHASE 8: LOGGING & MONITORING (Minute 14-16)
  --------------------------------------------
  ./07-splunk-logging.sh

  - Configure audit logging
  - Enable system logging (auditd)
  - Create monitoring alerts
  - Install monitoring scripts


  INCIDENT RESPONSE (As Needed)
  -----------------------------
  ./08-splunk-incident-response.sh

  - Disable user accounts
  - Block IP addresses
  - Check for persistence
  - Export logs
  - Emergency shutdown options

================================================================================
  QUICK REFERENCE COMMANDS
================================================================================

  # Check Splunk status
  /opt/splunk/bin/splunk status

  # Restart Splunk
  /opt/splunk/bin/splunk restart

  # List users
  /opt/splunk/bin/splunk list user -auth admin:password

  # Change password
  /opt/splunk/bin/splunk edit user USERNAME -password NEWPASS -auth admin:password

  # Check configuration
  /opt/splunk/bin/splunk btool server list --debug

  # View audit log
  tail -f /opt/splunk/var/log/splunk/audit.log

  # Search for failed logins
  index=_audit action=login_failed | stats count by user

================================================================================
  CRITICAL REMINDERS
================================================================================

  [!] BACKUP before making changes
  [!] Change admin password FIRST
  [!] Keep SSH session open while testing changes
  [!] Document all credential changes
  [!] Test Splunk Web access after changes
  [!] Verify forwarders can still send data
  [!] Check that alerts are still functioning

================================================================================
  SPLUNK IMPORTANT FILES
================================================================================

  Configuration:
    /opt/splunk/etc/system/local/       - Local config overrides
    /opt/splunk/etc/passwd              - Splunk users
    /opt/splunk/etc/auth/               - SSL certificates

  Logs:
    /opt/splunk/var/log/splunk/audit.log       - User activity
    /opt/splunk/var/log/splunk/splunkd.log     - Main log
    /opt/splunk/var/log/splunk/splunkd_access.log - Web access

  Data:
    /opt/splunk/var/lib/splunk/         - Index data

================================================================================

BANNER

SCRIPT_DIR=$(dirname "$0")

echo -e "${YELLOW}Scripts available in: $SCRIPT_DIR${NC}"
echo ""

read -p "Run scripts in guided mode? (y/N): " response
if [ "$response" = "y" ]; then
    echo ""
    echo -e "${CYAN}[*] Starting guided execution...${NC}"

    # Phase 1
    echo ""
    echo -e "${YELLOW}=== PHASE 1: RECONNAISSANCE ===${NC}"
    read -p "Run 00-splunk-recon.sh? (Y/n): " run
    if [ "$run" != "n" ]; then
        bash "$SCRIPT_DIR/00-splunk-recon.sh"
    fi

    # Phase 2
    echo ""
    echo -e "${YELLOW}=== PHASE 2: BACKUP ===${NC}"
    read -p "Run 01-splunk-backup.sh? (Y/n): " run
    if [ "$run" != "n" ]; then
        bash "$SCRIPT_DIR/01-splunk-backup.sh"
    fi

    # Phase 3
    echo ""
    echo -e "${YELLOW}=== PHASE 3: USER AUDIT ===${NC}"
    read -p "Run 02-splunk-user-audit.sh? (Y/n): " run
    if [ "$run" != "n" ]; then
        bash "$SCRIPT_DIR/02-splunk-user-audit.sh"
    fi

    # Phase 4
    echo ""
    echo -e "${YELLOW}=== PHASE 4: CREDENTIAL ROTATION ===${NC}"
    read -p "Run 03-splunk-credential-rotation.sh? (Y/n): " run
    if [ "$run" != "n" ]; then
        bash "$SCRIPT_DIR/03-splunk-credential-rotation.sh"
    fi

    # Phase 5
    echo ""
    echo -e "${YELLOW}=== PHASE 5: SSH HARDENING ===${NC}"
    read -p "Run 04-splunk-ssh-harden.sh? (Y/n): " run
    if [ "$run" != "n" ]; then
        bash "$SCRIPT_DIR/04-splunk-ssh-harden.sh"
    fi

    # Phase 6
    echo ""
    echo -e "${YELLOW}=== PHASE 6: FIREWALL ===${NC}"
    read -p "Run 05-splunk-firewall.sh? (Y/n): " run
    if [ "$run" != "n" ]; then
        bash "$SCRIPT_DIR/05-splunk-firewall.sh"
    fi

    # Phase 7
    echo ""
    echo -e "${YELLOW}=== PHASE 7: SPLUNK HARDENING ===${NC}"
    read -p "Run 06-splunk-harden.sh? (Y/n): " run
    if [ "$run" != "n" ]; then
        bash "$SCRIPT_DIR/06-splunk-harden.sh"
    fi

    # Phase 8
    echo ""
    echo -e "${YELLOW}=== PHASE 8: LOGGING ===${NC}"
    read -p "Run 07-splunk-logging.sh? (Y/n): " run
    if [ "$run" != "n" ]; then
        bash "$SCRIPT_DIR/07-splunk-logging.sh"
    fi

    echo ""
    echo -e "${GREEN}========================================"
    echo "  Guided Execution Complete!"
    echo -e "========================================${NC}"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "  1. Verify Splunk Web access (https://hostname:8000)"
    echo "  2. Test Splunk login with new credentials"
    echo "  3. Verify forwarders are sending data"
    echo "  4. Check that alerts are firing"
    echo "  5. Review /opt/splunk-ccdc-logs/ for reports"
    echo ""
    echo -e "${CYAN}For incident response:${NC}"
    echo "  ./08-splunk-incident-response.sh"
    echo ""
fi
