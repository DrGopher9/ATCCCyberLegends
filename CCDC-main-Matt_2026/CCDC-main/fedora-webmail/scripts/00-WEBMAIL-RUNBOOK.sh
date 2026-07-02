#!/bin/bash
#===============================================================================
# CCDC Fedora Webmail/Apps - First 15 Minutes Runbook
#===============================================================================
#
# Target: Fedora Server with Webmail (Roundcube) and Web Applications
# Network: Public Zone
#
# Common Services:
#   - Apache (httpd) or Nginx
#   - PHP / PHP-FPM
#   - Roundcube / SquirrelMail
#   - MariaDB / MySQL
#   - Postfix / Dovecot (if integrated mail)
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
  CCDC FEDORA WEBMAIL - FIRST 15 MINUTES RUNBOOK
================================================================================

  Server Role: Webmail and Web Applications
  OS: Fedora
  Network: Public Zone

================================================================================
  SCRIPT EXECUTION ORDER
================================================================================

  PHASE 1: RECONNAISSANCE (Minute 0-2)
  ------------------------------------
  ./00-webmail-recon.sh

  - Check web server status (Apache/Nginx)
  - Review installed web applications
  - List users and SSH keys
  - Check firewall and SELinux
  - Output: /opt/ccdc-logs/webmail_recon_*.txt


  PHASE 2: BACKUP (Minute 2-4) - CRITICAL!
  ----------------------------------------
  ./01-webmail-backup.sh

  - Backup web server configuration
  - Backup web application files
  - Backup database
  - Backup SSL certificates
  - Output: /opt/ccdc-backups/


  PHASE 3: USER AUDIT (Minute 4-6)
  --------------------------------
  ./02-webmail-user-audit.sh

  - Audit system users
  - Check SSH authorized keys
  - Check sudo access
  - Scan for web shells


  PHASE 4: CREDENTIAL ROTATION (Minute 6-9) - CRITICAL!
  -----------------------------------------------------
  ./03-webmail-credential-rotation.sh

  - Change root password
  - Change MySQL passwords
  - Update application configs
  - Output: /opt/ccdc-logs/CREDENTIALS_*.txt


  PHASE 5: SSH HARDENING (Minute 9-10)
  ------------------------------------
  ./04-webmail-ssh-harden.sh

  - Harden SSH configuration
  - Configure allowed users
  - Set up banner


  PHASE 6: FIREWALL (Minute 10-11)
  --------------------------------
  ./05-webmail-firewall.sh

  - Configure firewalld
  - Allow HTTP/HTTPS
  - Block unnecessary ports


  PHASE 7: WEB APPLICATION HARDENING (Minute 11-14)
  -------------------------------------------------
  ./06-webmail-harden.sh

  - Harden Apache/Nginx
  - Harden PHP
  - Secure Roundcube
  - Configure SELinux
  - Harden SSL/TLS


  PHASE 8: LOGGING (Minute 14-16)
  -------------------------------
  ./07-webmail-logging.sh

  - Configure auditd
  - Set up fail2ban
  - Create monitoring scripts


  INCIDENT RESPONSE (As Needed)
  -----------------------------
  ./08-webmail-incident-response.sh

  - Lock accounts
  - Block IPs
  - Scan for web shells
  - Check persistence

================================================================================
  QUICK REFERENCE COMMANDS
================================================================================

  # Check services
  systemctl status httpd mariadb postfix

  # View Apache logs
  tail -f /var/log/httpd/access_log
  tail -f /var/log/httpd/error_log

  # Check failed logins
  grep "Failed password" /var/log/secure | tail -20

  # Block IP
  firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=IP reject'
  firewall-cmd --reload

  # Find recent PHP files
  find /var/www -name "*.php" -mtime -1

  # Check connections
  ss -tnp

================================================================================
  CRITICAL REMINDERS
================================================================================

  [!] BACKUP before making changes
  [!] Change root and database passwords FIRST
  [!] Keep SSH session open while testing changes
  [!] Check that web applications work after hardening
  [!] Test email sending/receiving
  [!] Verify SELinux is not blocking services

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
    read -p "Run 00-webmail-recon.sh? (Y/n): " run
    if [ "$run" != "n" ]; then
        bash "$SCRIPT_DIR/00-webmail-recon.sh"
    fi

    # Phase 2
    echo ""
    echo -e "${YELLOW}=== PHASE 2: BACKUP ===${NC}"
    read -p "Run 01-webmail-backup.sh? (Y/n): " run
    if [ "$run" != "n" ]; then
        bash "$SCRIPT_DIR/01-webmail-backup.sh"
    fi

    # Phase 3
    echo ""
    echo -e "${YELLOW}=== PHASE 3: USER AUDIT ===${NC}"
    read -p "Run 02-webmail-user-audit.sh? (Y/n): " run
    if [ "$run" != "n" ]; then
        bash "$SCRIPT_DIR/02-webmail-user-audit.sh"
    fi

    # Phase 4
    echo ""
    echo -e "${YELLOW}=== PHASE 4: CREDENTIAL ROTATION ===${NC}"
    read -p "Run 03-webmail-credential-rotation.sh? (Y/n): " run
    if [ "$run" != "n" ]; then
        bash "$SCRIPT_DIR/03-webmail-credential-rotation.sh"
    fi

    # Phase 5
    echo ""
    echo -e "${YELLOW}=== PHASE 5: SSH HARDENING ===${NC}"
    read -p "Run 04-webmail-ssh-harden.sh? (Y/n): " run
    if [ "$run" != "n" ]; then
        bash "$SCRIPT_DIR/04-webmail-ssh-harden.sh"
    fi

    # Phase 6
    echo ""
    echo -e "${YELLOW}=== PHASE 6: FIREWALL ===${NC}"
    read -p "Run 05-webmail-firewall.sh? (Y/n): " run
    if [ "$run" != "n" ]; then
        bash "$SCRIPT_DIR/05-webmail-firewall.sh"
    fi

    # Phase 7
    echo ""
    echo -e "${YELLOW}=== PHASE 7: WEB APPLICATION HARDENING ===${NC}"
    read -p "Run 06-webmail-harden.sh? (Y/n): " run
    if [ "$run" != "n" ]; then
        bash "$SCRIPT_DIR/06-webmail-harden.sh"
    fi

    # Phase 8
    echo ""
    echo -e "${YELLOW}=== PHASE 8: LOGGING ===${NC}"
    read -p "Run 07-webmail-logging.sh? (Y/n): " run
    if [ "$run" != "n" ]; then
        bash "$SCRIPT_DIR/07-webmail-logging.sh"
    fi

    echo ""
    echo -e "${GREEN}========================================"
    echo "  Guided Execution Complete!"
    echo -e "========================================${NC}"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "  1. Test webmail login"
    echo "  2. Test email send/receive"
    echo "  3. Verify all web apps work"
    echo "  4. Check logs for errors"
    echo ""
fi
