#!/bin/bash
###############################################################################
# 00-MAIL-RUNBOOK.sh - CCDC Mail Server First 15 Minutes Runbook
# Target: Linux Mail Server (Postfix + Dovecot)
#
# This script guides you through the critical first actions in competition.
# Run scripts in order. Each step is reversible.
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

banner() {
    echo ""
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}============================================${NC}"
    echo ""
}

check() {
    echo -e "${GREEN}[✓]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[✗]${NC} $1"
}

banner "CCDC MAIL SERVER - FIRST 15 MINUTES RUNBOOK"

echo "This runbook will guide you through initial mail server hardening."
echo "Target: Postfix + Dovecot Mail Server"
echo ""
echo "Scripts available in: $SCRIPT_DIR"
echo ""
echo "============================================"
echo "EXECUTION ORDER (follow this sequence)"
echo "============================================"
echo ""
echo "PHASE 1: RECONNAISSANCE (Do First!)"
echo "  1. 00-mail-recon.sh       - Gather system info"
echo ""
echo "PHASE 2: BACKUP (Before ANY changes)"
echo "  2. 01-mail-backup.sh      - Backup configs"
echo ""
echo "PHASE 3: ACCESS CONTROL (Critical)"
echo "  3. 02-mail-user-audit.sh  - Audit users, remove keys"
echo "  4. 03-mail-credential-rotation.sh - Change passwords"
echo "  5. 04-mail-ssh-harden.sh  - Secure SSH"
echo ""
echo "PHASE 4: NETWORK SECURITY"
echo "  6. 05-mail-firewall.sh    - Configure firewall"
echo ""
echo "PHASE 5: MAIL SERVICE HARDENING"
echo "  7. 06-postfix-harden.sh   - Secure Postfix (CRITICAL)"
echo "  8. 07-dovecot-harden.sh   - Secure Dovecot"
echo ""
echo "PHASE 6: MONITORING"
echo "  9. 08-mail-logging.sh     - Enable logging"
echo ""
echo "============================================"
echo ""

read -p "Press Enter to begin guided execution, or Ctrl+C to run scripts manually..."

# Phase 1: Recon
banner "PHASE 1: RECONNAISSANCE"
echo "Running mail server reconnaissance..."
read -p "Execute 00-mail-recon.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/00-mail-recon.sh"
    check "Reconnaissance complete"
else
    warn "Skipped reconnaissance"
fi

# Phase 2: Backup
banner "PHASE 2: BACKUP"
echo "Creating backups before any modifications..."
read -p "Execute 01-mail-backup.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/01-mail-backup.sh"
    check "Backups created"
else
    error "WARNING: Proceeding without backup is risky!"
    read -p "Are you sure? (y/N): " -r REPLY
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborting. Run backup first."
        exit 1
    fi
fi

# Phase 3: Access Control
banner "PHASE 3: ACCESS CONTROL"
echo "This is the most critical phase for initial security."
echo ""

echo "Step 1: User Audit"
read -p "Execute 02-mail-user-audit.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/02-mail-user-audit.sh"
    check "User audit complete"
fi

echo ""
echo "Step 2: Credential Rotation"
read -p "Execute 03-mail-credential-rotation.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/03-mail-credential-rotation.sh"
    check "Credentials rotated"
fi

echo ""
echo "Step 3: SSH Hardening"
warn "Keep your current SSH session open during this step!"
read -p "Execute 04-mail-ssh-harden.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/04-mail-ssh-harden.sh"
    check "SSH hardened"
fi

# Phase 4: Network Security
banner "PHASE 4: NETWORK SECURITY"
echo "Configuring host-based firewall..."
warn "This will restrict network access. Keep mail ports open!"
read -p "Execute 05-mail-firewall.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/05-mail-firewall.sh"
    check "Firewall configured"
fi

# Phase 5: Mail Service Hardening
banner "PHASE 5: MAIL SERVICE HARDENING"
echo "Hardening Postfix and Dovecot..."
echo ""

echo "Step 1: Postfix Hardening (CRITICAL - prevents open relay)"
warn "This is essential to prevent the server from being used as spam relay!"
read -p "Execute 06-postfix-harden.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/06-postfix-harden.sh"
    check "Postfix hardened"
fi

echo ""
echo "Step 2: Dovecot Hardening"
read -p "Execute 07-dovecot-harden.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/07-dovecot-harden.sh"
    check "Dovecot hardened"
fi

# Phase 6: Monitoring
banner "PHASE 6: MONITORING"
echo "Setting up logging and monitoring..."
read -p "Execute 08-mail-logging.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/08-mail-logging.sh"
    check "Logging configured"
fi

# Final verification
banner "VERIFICATION CHECKLIST"
echo ""
echo "Please verify the following:"
echo ""
echo "[ ] Can SSH into the server from a new terminal"
echo "[ ] Postfix is running: systemctl status postfix"
echo "[ ] Dovecot is running: systemctl status dovecot"
echo "[ ] Can send email (test with external recipient)"
echo "[ ] Can receive email (test from external sender)"
echo "[ ] IMAP login works: openssl s_client -connect localhost:993"
echo "[ ] NOT an open relay (test from external):"
echo "    telnet server 25"
echo "    MAIL FROM: <test@external.com>"
echo "    RCPT TO: <test@anotherdomain.com>"
echo "    (should reject with 'Relay access denied')"
echo "[ ] Scoring engine can reach mail services"
echo ""

banner "HARDENING COMPLETE"
echo ""
echo "Quick Reference Commands:"
echo "============================================"
echo ""
echo "Check service status:"
echo "  systemctl status postfix dovecot"
echo ""
echo "Check mail queue:"
echo "  mailq"
echo ""
echo "Monitor logs:"
echo "  /root/ccdc-logs/mail-monitor.sh all"
echo ""
echo "Detect threats:"
echo "  /root/ccdc-logs/mail-detect.sh"
echo ""
echo "Block malicious IP:"
echo "  postconf -e 'smtpd_client_restrictions = reject_rbl_client <ip>'"
echo "  # Or use firewall"
echo ""
echo "Flush mail queue:"
echo "  postsuper -d ALL   # Delete all queued mail"
echo ""
echo "Check for open relay:"
echo "  postconf mynetworks"
echo "  postconf smtpd_relay_restrictions"
echo ""
echo "Emergency restart:"
echo "  systemctl restart postfix dovecot"
echo ""
echo "============================================"
echo "Good luck! Watch for spam/relay attempts."
echo "============================================"
