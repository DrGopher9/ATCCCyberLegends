#!/bin/bash
#===============================================================================
# CCDC Fedora Webmail/Apps - Firewall Configuration Script
# Target: Fedora Server with firewalld
# Run as: root
#===============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

LOGDIR="/opt/ccdc-logs"
BACKUP_DIR="/opt/ccdc-backups"
mkdir -p "$LOGDIR" "$BACKUP_DIR"

echo -e "${CYAN}========================================"
echo "  CCDC Fedora Firewall Configuration"
echo -e "========================================${NC}"
echo ""

#-------------------------------------------------------------------------------
echo -e "${YELLOW}=== Common Webmail Ports ===${NC}"
echo ""
echo "  22   - SSH"
echo "  80   - HTTP"
echo "  443  - HTTPS"
echo "  25   - SMTP (if mail server)"
echo "  587  - SMTP Submission"
echo "  993  - IMAPS"
echo "  995  - POP3S"
echo "  3306 - MySQL (should be local only)"
echo ""

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Current Listening Ports:${NC}"
ss -tlnp | grep -E "LISTEN" | head -20
echo ""

#-------------------------------------------------------------------------------
# Check if firewalld is installed and running
if ! command -v firewall-cmd &>/dev/null; then
    echo -e "${RED}[!] firewalld not installed${NC}"
    echo "Installing firewalld..."
    dnf install -y firewalld
fi

# Enable and start firewalld
if ! systemctl is-active firewalld &>/dev/null; then
    echo "Starting firewalld..."
    systemctl enable firewalld
    systemctl start firewalld
fi

echo -e "${YELLOW}[*] Current Firewalld Status:${NC}"
firewall-cmd --state
echo ""

# Backup current rules
firewall-cmd --list-all > "$BACKUP_DIR/firewalld_$(date +%Y%m%d_%H%M%S).bak"
echo -e "${GREEN}[+] Backed up current rules${NC}"
echo ""

echo -e "${CYAN}Current firewall configuration:${NC}"
firewall-cmd --list-all
echo ""

#-------------------------------------------------------------------------------
read -p "Configure firewall for webmail server? (y/N): " config_fw
if [ "$config_fw" = "y" ]; then
    echo ""
    echo -e "${YELLOW}[*] Configuring firewall rules...${NC}"

    # SSH (always allow)
    firewall-cmd --permanent --add-service=ssh
    echo -e "${GREEN}    [+] SSH (22) allowed${NC}"

    # HTTP
    read -p "Allow HTTP (80)? (Y/n): " allow_http
    if [ "$allow_http" != "n" ]; then
        firewall-cmd --permanent --add-service=http
        echo -e "${GREEN}    [+] HTTP (80) allowed${NC}"
    fi

    # HTTPS
    read -p "Allow HTTPS (443)? (Y/n): " allow_https
    if [ "$allow_https" != "n" ]; then
        firewall-cmd --permanent --add-service=https
        echo -e "${GREEN}    [+] HTTPS (443) allowed${NC}"
    fi

    # SMTP
    read -p "Allow SMTP (25)? (y/N): " allow_smtp
    if [ "$allow_smtp" = "y" ]; then
        firewall-cmd --permanent --add-service=smtp
        echo -e "${GREEN}    [+] SMTP (25) allowed${NC}"
    fi

    # SMTP Submission
    read -p "Allow SMTP Submission (587)? (y/N): " allow_submission
    if [ "$allow_submission" = "y" ]; then
        firewall-cmd --permanent --add-port=587/tcp
        echo -e "${GREEN}    [+] SMTP Submission (587) allowed${NC}"
    fi

    # IMAPS
    read -p "Allow IMAPS (993)? (y/N): " allow_imaps
    if [ "$allow_imaps" = "y" ]; then
        firewall-cmd --permanent --add-service=imaps
        echo -e "${GREEN}    [+] IMAPS (993) allowed${NC}"
    fi

    # POP3S
    read -p "Allow POP3S (995)? (y/N): " allow_pop3s
    if [ "$allow_pop3s" = "y" ]; then
        firewall-cmd --permanent --add-service=pop3s
        echo -e "${GREEN}    [+] POP3S (995) allowed${NC}"
    fi

    # Reload firewall
    firewall-cmd --reload
    echo ""
    echo -e "${GREEN}[+] Firewall rules applied${NC}"
fi

#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[*] Block specific IPs${NC}"

read -p "Block any IPs? (enter IP or skip): " block_ip
while [ -n "$block_ip" ]; do
    firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$block_ip' reject"
    echo -e "${GREEN}[+] Blocked: $block_ip${NC}"
    echo "$block_ip" >> "$LOGDIR/blocked_ips.txt"
    echo "[$(date)] Blocked IP: $block_ip" >> "$LOGDIR/firewall_changes.log"

    read -p "Block another IP? (enter IP or skip): " block_ip
done

if [ -n "$(firewall-cmd --list-rich-rules 2>/dev/null)" ]; then
    firewall-cmd --reload
fi

#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[*] Restrict MySQL to localhost${NC}"

# Check if MySQL is listening on all interfaces
if ss -tlnp | grep -q "0.0.0.0:3306\|:::3306"; then
    echo -e "${RED}[!] MySQL is listening on all interfaces${NC}"
    echo "Consider binding to localhost only in /etc/my.cnf.d/:"
    echo "  bind-address = 127.0.0.1"
else
    echo -e "${GREEN}[+] MySQL appears to be bound to localhost${NC}"
fi

#-------------------------------------------------------------------------------
echo ""
echo -e "${CYAN}Final firewall configuration:${NC}"
firewall-cmd --list-all

echo ""
echo -e "${GREEN}========================================"
echo "  Firewall Configuration Complete"
echo -e "========================================${NC}"
echo ""
echo "Backup saved to: $BACKUP_DIR/"
echo ""
echo -e "${YELLOW}To block an IP later:${NC}"
echo '  firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=IP reject"'
echo "  firewall-cmd --reload"
echo ""
