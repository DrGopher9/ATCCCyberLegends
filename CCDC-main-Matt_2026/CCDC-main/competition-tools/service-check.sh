#!/bin/bash
#===============================================================================
# CCDC Service Health Check Script
# Run from any Linux system with network access to all hosts
#===============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

#===============================================================================
# CONFIGURATION - UPDATE THESE IPs
#===============================================================================

# Firewall
FIREWALL_IP="172.20.240.1"
FIREWALL_MGMT_PORT="443"

# Windows AD Server
WINDOWS_AD_IP="172.20.242.10"

# E-Commerce Server (Ubuntu)
ECOMM_IP="172.20.241.10"

# Email Server
EMAIL_IP="172.20.241.20"

# Webmail/Apps Server (Fedora)
WEBMAIL_IP="172.20.241.30"

# Splunk SIEM
SPLUNK_IP="172.20.241.40"

#===============================================================================

echo ""
echo -e "${CYAN}========================================"
echo "  CCDC Service Health Check"
echo "  $(date)"
echo -e "========================================${NC}"
echo ""

# Function to check TCP port
check_port() {
    local host=$1
    local port=$2
    local service=$3

    if timeout 3 bash -c "echo > /dev/tcp/$host/$port" 2>/dev/null; then
        echo -e "  ${GREEN}[UP]${NC} $service ($host:$port)"
        return 0
    else
        echo -e "  ${RED}[DOWN]${NC} $service ($host:$port)"
        return 1
    fi
}

# Function to check HTTP
check_http() {
    local url=$1
    local service=$2

    if curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" | grep -qE "^(200|301|302|401|403)"; then
        echo -e "  ${GREEN}[UP]${NC} $service ($url)"
        return 0
    else
        echo -e "  ${RED}[DOWN]${NC} $service ($url)"
        return 1
    fi
}

# Function to check ping
check_ping() {
    local host=$1
    local name=$2

    if ping -c 1 -W 2 "$host" &>/dev/null; then
        echo -e "  ${GREEN}[UP]${NC} $name ($host) - ICMP"
        return 0
    else
        echo -e "  ${YELLOW}[?]${NC} $name ($host) - ICMP blocked or down"
        return 1
    fi
}

#===============================================================================
echo -e "${YELLOW}=== FIREWALL ===${NC}"
check_ping "$FIREWALL_IP" "Palo Alto Firewall"
check_port "$FIREWALL_IP" "$FIREWALL_MGMT_PORT" "Firewall HTTPS Management"

#===============================================================================
echo ""
echo -e "${YELLOW}=== WINDOWS AD SERVER ===${NC}"
check_ping "$WINDOWS_AD_IP" "Windows AD Server"
check_port "$WINDOWS_AD_IP" "53" "DNS"
check_port "$WINDOWS_AD_IP" "88" "Kerberos"
check_port "$WINDOWS_AD_IP" "389" "LDAP"
check_port "$WINDOWS_AD_IP" "445" "SMB"
check_port "$WINDOWS_AD_IP" "3389" "RDP"
check_port "$WINDOWS_AD_IP" "67" "DHCP" 2>/dev/null || echo -e "  ${YELLOW}[?]${NC} DHCP (UDP - cannot test)"

#===============================================================================
echo ""
echo -e "${YELLOW}=== E-COMMERCE SERVER (Ubuntu) ===${NC}"
check_ping "$ECOMM_IP" "E-Commerce Server"
check_port "$ECOMM_IP" "22" "SSH"
check_port "$ECOMM_IP" "80" "HTTP"
check_port "$ECOMM_IP" "443" "HTTPS"
check_http "http://$ECOMM_IP" "PrestaShop HTTP"
check_http "https://$ECOMM_IP" "PrestaShop HTTPS" 2>/dev/null

#===============================================================================
echo ""
echo -e "${YELLOW}=== EMAIL SERVER ===${NC}"
check_ping "$EMAIL_IP" "Email Server"
check_port "$EMAIL_IP" "22" "SSH"
check_port "$EMAIL_IP" "25" "SMTP"
check_port "$EMAIL_IP" "587" "SMTP Submission"
check_port "$EMAIL_IP" "993" "IMAPS"
check_port "$EMAIL_IP" "995" "POP3S"
check_port "$EMAIL_IP" "110" "POP3"
check_port "$EMAIL_IP" "143" "IMAP"

#===============================================================================
echo ""
echo -e "${YELLOW}=== WEBMAIL/APPS SERVER (Fedora) ===${NC}"
check_ping "$WEBMAIL_IP" "Webmail Server"
check_port "$WEBMAIL_IP" "22" "SSH"
check_port "$WEBMAIL_IP" "80" "HTTP"
check_port "$WEBMAIL_IP" "443" "HTTPS"
check_http "http://$WEBMAIL_IP" "Webmail HTTP"
check_http "https://$WEBMAIL_IP" "Webmail HTTPS" 2>/dev/null

#===============================================================================
echo ""
echo -e "${YELLOW}=== SPLUNK SIEM ===${NC}"
check_ping "$SPLUNK_IP" "Splunk Server"
check_port "$SPLUNK_IP" "22" "SSH"
check_port "$SPLUNK_IP" "8000" "Splunk Web"
check_port "$SPLUNK_IP" "8089" "Splunk Management"
check_port "$SPLUNK_IP" "9997" "Splunk Forwarder Input"
check_http "https://$SPLUNK_IP:8000" "Splunk Web Interface" 2>/dev/null

#===============================================================================
echo ""
echo -e "${CYAN}========================================"
echo "  Health Check Complete"
echo -e "========================================${NC}"
echo ""
echo "Legend:"
echo -e "  ${GREEN}[UP]${NC}   - Service responding"
echo -e "  ${RED}[DOWN]${NC} - Service not responding"
echo -e "  ${YELLOW}[?]${NC}    - Status uncertain"
echo ""
