#!/bin/bash
###############################################################################
# 00-MASTER-RUNBOOK.sh - CCDC First 15 Minutes Runbook
# Target: Ubuntu 24 E-Commerce Server (PrestaShop + MySQL)
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

banner "CCDC ECOMM SERVER - FIRST 15 MINUTES RUNBOOK"

echo "This runbook will guide you through initial hardening."
echo "Target: Ubuntu 24 with PrestaShop + MySQL"
echo ""
echo "Scripts available in: $SCRIPT_DIR"
echo ""
echo "============================================"
echo "EXECUTION ORDER (follow this sequence)"
echo "============================================"
echo ""
echo "PHASE 1: RECONNAISSANCE (Do First!)"
echo "  1. 00-initial-recon.sh    - Gather system info"
echo ""
echo "PHASE 2: BACKUP (Before ANY changes)"
echo "  2. 01-backup-critical.sh  - Backup configs & data"
echo ""
echo "PHASE 3: ACCESS CONTROL (Critical)"
echo "  3. 02-user-audit.sh       - Audit users, remove keys"
echo "  4. 03-credential-rotation.sh - Change ALL passwords"
echo "  5. 04-ssh-harden.sh       - Secure SSH"
echo ""
echo "PHASE 4: NETWORK SECURITY"
echo "  6. 05-firewall-setup.sh   - Configure UFW"
echo ""
echo "PHASE 5: APPLICATION SECURITY"
echo "  7. 06-mysql-harden.sh     - Secure database"
echo "  8. 07-prestashop-harden.sh - Secure web app"
echo ""
echo "PHASE 6: MONITORING"
echo "  9. 08-logging-setup.sh    - Enable logging"
echo ""
echo "============================================"
echo ""

read -p "Press Enter to begin guided execution, or Ctrl+C to run scripts manually..."

# Phase 1: Recon
banner "PHASE 1: RECONNAISSANCE"
echo "Running initial reconnaissance..."
read -p "Execute 00-initial-recon.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/00-initial-recon.sh"
    check "Reconnaissance complete"
else
    warn "Skipped reconnaissance"
fi

# Phase 2: Backup
banner "PHASE 2: BACKUP"
echo "Creating backups before any modifications..."
read -p "Execute 01-backup-critical.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/01-backup-critical.sh"
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
read -p "Execute 02-user-audit.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/02-user-audit.sh"
    check "User audit complete"
fi

echo ""
echo "Step 2: Credential Rotation"
read -p "Execute 03-credential-rotation.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/03-credential-rotation.sh"
    check "Credentials rotated"
fi

echo ""
echo "Step 3: SSH Hardening"
warn "Keep your current SSH session open during this step!"
read -p "Execute 04-ssh-harden.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/04-ssh-harden.sh"
    check "SSH hardened"
fi

# Phase 4: Network Security
banner "PHASE 4: NETWORK SECURITY"
echo "Configuring host-based firewall..."
warn "This will restrict network access. Ensure scoring IPs are not blocked."
read -p "Execute 05-firewall-setup.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/05-firewall-setup.sh"
    check "Firewall configured"
fi

# Phase 5: Application Security
banner "PHASE 5: APPLICATION SECURITY"
echo "Hardening MySQL and PrestaShop..."
echo ""

echo "Step 1: MySQL Hardening"
read -p "Execute 06-mysql-harden.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/06-mysql-harden.sh"
    check "MySQL hardened"
fi

echo ""
echo "Step 2: PrestaShop Hardening"
read -p "Execute 07-prestashop-harden.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/07-prestashop-harden.sh"
    check "PrestaShop hardened"
fi

# Phase 6: Monitoring
banner "PHASE 6: MONITORING"
echo "Setting up logging and monitoring..."
read -p "Execute 08-logging-setup.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/08-logging-setup.sh"
    check "Logging configured"
fi

# Final verification
banner "VERIFICATION & TESTING"
echo ""
echo "Running automated tests..."
echo ""
read -p "Execute 10-test-and-fix.sh? (Y/n): " -r REPLY
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    bash "$SCRIPT_DIR/10-test-and-fix.sh"
    check "Testing complete"
fi

echo ""
echo "Manual verification checklist:"
echo ""
echo "[ ] Can SSH into the server from a new terminal"
echo "[ ] PrestaShop storefront loads: http://yourserver/"
echo "[ ] PrestaShop admin panel loads: http://yourserver/admin.../"
echo "[ ] Can complete a test purchase (if required by scoring)"
echo "[ ] MySQL is accessible locally"
echo "[ ] Firewall is active: ufw status"
echo "[ ] Scoring engine can reach the server"
echo ""

banner "HARDENING COMPLETE"
echo ""
echo "Quick Reference Commands:"
echo "============================================"
echo ""
echo "Test & fix issues:"
echo "  ./scripts/10-test-and-fix.sh"
echo ""
echo "Check service status:"
echo "  systemctl status apache2 mysql ssh ufw"
echo ""
echo "Monitor logs:"
echo "  /root/ccdc-logs/monitor.sh all"
echo ""
echo "Detect threats:"
echo "  /root/ccdc-logs/detect.sh"
echo ""
echo "Block malicious IP:"
echo "  ufw deny from <IP> to any"
echo ""
echo "View firewall status:"
echo "  ufw status verbose"
echo ""
echo "Emergency rollback:"
echo "  Backups in /root/ccdc-backups/"
echo ""
echo "Troubleshooting guide:"
echo "  See TROUBLESHOOTING.md in ecomm-ubuntu folder"
echo ""
echo "============================================"
echo "Good luck! Stay vigilant for Red Team activity."
echo "============================================"
