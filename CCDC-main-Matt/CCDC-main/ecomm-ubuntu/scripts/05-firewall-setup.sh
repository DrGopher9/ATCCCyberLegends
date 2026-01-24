#!/bin/bash
###############################################################################
# 05-firewall-setup.sh - UFW Firewall Configuration
# Target: Ubuntu 24 E-Commerce Server (PrestaShop)
# Purpose: Configure host-based firewall for web server
#
# IMPORTANT: Do NOT block scoring engine traffic!
# Keep HTTP/HTTPS open to all (public access required per rules)
###############################################################################

set -euo pipefail

LOGFILE="/root/ccdc-logs/firewall_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$(dirname "$LOGFILE")"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOGFILE"
}

log "Starting firewall configuration..."

# Check if UFW is installed
if ! command -v ufw &> /dev/null; then
    log "UFW not found. Installing..."
    apt-get update && apt-get install -y ufw
fi

# Backup current rules
log "Backing up current firewall state..."
ufw status verbose > "/root/ccdc-backups/ufw_status_$(date +%Y%m%d_%H%M%S).txt" 2>/dev/null || true
iptables-save > "/root/ccdc-backups/iptables_$(date +%Y%m%d_%H%M%S).rules" 2>/dev/null || true

echo ""
echo "============================================"
echo "CURRENT LISTENING SERVICES"
echo "============================================"
ss -tlnp 2>/dev/null | grep LISTEN || netstat -tlnp 2>/dev/null | grep LISTEN || true

echo ""
echo "============================================"
echo "UFW FIREWALL CONFIGURATION"
echo "============================================"
echo ""
echo "This will configure UFW for an e-commerce web server."
echo "The following ports will be ALLOWED:"
echo "  - 22/tcp   (SSH)"
echo "  - 80/tcp   (HTTP - required for scoring)"
echo "  - 443/tcp  (HTTPS - required for scoring)"
echo ""
echo "MySQL (3306) will be LOCAL ONLY by default."
echo ""

read -p "Configure UFW firewall? (y/N): " -r REPLY
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log "Aborted by user"
    exit 0
fi

# Reset UFW to defaults (but don't enable yet)
log "Resetting UFW to defaults..."
ufw --force reset

# Set default policies
log "Setting default policies..."
ufw default deny incoming
ufw default allow outgoing

# Allow SSH first (critical!)
log "Allowing SSH (port 22)..."
ufw allow 22/tcp comment 'SSH'

# Allow HTTP (required for scoring engine and public access)
log "Allowing HTTP (port 80)..."
ufw allow 80/tcp comment 'HTTP - Scoring Engine'

# Allow HTTPS
log "Allowing HTTPS (port 443)..."
ufw allow 443/tcp comment 'HTTPS'

# MySQL - localhost only (default bind is 127.0.0.1)
# If remote DB access needed, uncomment and restrict:
# ufw allow from 172.20.240.0/24 to any port 3306 comment 'MySQL from Internal'

# Optional: Rate limit SSH to prevent brute force
log "Adding SSH rate limiting..."
ufw limit 22/tcp comment 'SSH rate limit'

# Enable UFW
echo ""
read -p "Enable UFW now? Keep your SSH session open! (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log "Enabling UFW..."
    ufw --force enable

    if ufw status | grep -q "Status: active"; then
        log "UFW enabled successfully"
    else
        log "WARNING: UFW may not be active"
    fi
else
    log "UFW configured but not enabled. Run 'ufw enable' when ready."
fi

# Show final status
echo ""
echo "============================================"
echo "FIREWALL STATUS"
echo "============================================"
ufw status verbose

echo ""
echo "============================================"
echo "FIREWALL CONFIGURATION COMPLETE"
echo "============================================"
echo ""
echo "Rules applied:"
echo "  ALLOW: 22/tcp (SSH - rate limited)"
echo "  ALLOW: 80/tcp (HTTP)"
echo "  ALLOW: 443/tcp (HTTPS)"
echo "  DENY: Everything else inbound"
echo "  ALLOW: All outbound"
echo ""
echo "MySQL (3306) is NOT exposed externally."
echo ""
echo "ADDITIONAL COMMANDS:"
echo "  ufw status              - Check status"
echo "  ufw allow <port>/tcp    - Allow a port"
echo "  ufw deny from <IP>      - Block an IP"
echo "  ufw disable             - Disable firewall"
echo ""
echo "TO BLOCK A MALICIOUS IP:"
echo "  ufw deny from <IP> to any"
echo ""
echo "IF LOCKED OUT:"
echo "  Access console and run: ufw disable"
echo ""

# Log final state
log "Firewall configuration complete"
ufw status verbose >> "$LOGFILE"
