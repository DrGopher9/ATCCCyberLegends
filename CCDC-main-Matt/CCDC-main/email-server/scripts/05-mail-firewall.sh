#!/bin/bash
###############################################################################
# 05-mail-firewall.sh - Mail Server Firewall Configuration
# Target: Linux Mail Server (Postfix + Dovecot)
# Purpose: Configure host-based firewall for mail services
#
# IMPORTANT: Do NOT block scoring engine traffic!
# Keep mail ports open to all (public access required per rules)
###############################################################################

set -euo pipefail

LOGFILE="/root/ccdc-logs/mail_firewall_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$(dirname "$LOGFILE")"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOGFILE"
}

log "Starting mail server firewall configuration..."

# Detect firewall system
FIREWALL_TYPE=""
if command -v firewall-cmd &> /dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
    FIREWALL_TYPE="firewalld"
elif command -v ufw &> /dev/null; then
    FIREWALL_TYPE="ufw"
else
    FIREWALL_TYPE="iptables"
fi

log "Detected firewall type: $FIREWALL_TYPE"

# Backup current rules
log "Backing up current firewall state..."
mkdir -p /root/ccdc-backups
iptables-save > "/root/ccdc-backups/iptables_$(date +%Y%m%d_%H%M%S).rules" 2>/dev/null || true
if [ "$FIREWALL_TYPE" = "firewalld" ]; then
    firewall-cmd --list-all > "/root/ccdc-backups/firewalld_$(date +%Y%m%d_%H%M%S).txt" 2>/dev/null || true
fi

echo ""
echo "============================================"
echo "CURRENT LISTENING MAIL SERVICES"
echo "============================================"
echo ""
echo "Port  | Service"
echo "------|--------"
ss -tlnp 2>/dev/null | grep -E ':(25|110|143|465|587|993|995)\s' | while read -r line; do
    port=$(echo "$line" | grep -oP ':\K\d+(?=\s)')
    case $port in
        25)  echo "$port   | SMTP" ;;
        110) echo "$port   | POP3" ;;
        143) echo "$port   | IMAP" ;;
        465) echo "$port   | SMTPS (implicit TLS)" ;;
        587) echo "$port   | Submission (STARTTLS)" ;;
        993) echo "$port   | IMAPS" ;;
        995) echo "$port   | POP3S" ;;
    esac
done || true

echo ""
echo "============================================"
echo "MAIL SERVER FIREWALL CONFIGURATION"
echo "============================================"
echo ""
echo "This will configure firewall for a mail server."
echo "The following ports will be ALLOWED:"
echo ""
echo "  22/tcp   - SSH"
echo "  25/tcp   - SMTP (required for receiving mail)"
echo "  80/tcp   - HTTP (for webmail, if applicable)"
echo "  110/tcp  - POP3 (optional)"
echo "  143/tcp  - IMAP (optional)"
echo "  443/tcp  - HTTPS (for webmail)"
echo "  465/tcp  - SMTPS (submission over TLS)"
echo "  587/tcp  - Submission (STARTTLS)"
echo "  993/tcp  - IMAPS (IMAP over TLS)"
echo "  995/tcp  - POP3S (optional)"
echo ""

read -p "Configure firewall? (y/N): " -r REPLY
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log "Aborted by user"
    exit 0
fi

# Ask about optional services
echo ""
echo "Optional services:"
read -p "Enable POP3 (110/tcp)? (y/N): " -r ENABLE_POP3
read -p "Enable POP3S (995/tcp)? (y/N): " -r ENABLE_POP3S
read -p "Enable unencrypted IMAP (143/tcp)? (y/N): " -r ENABLE_IMAP
read -p "Enable HTTP/HTTPS for webmail (80,443)? (y/N): " -r ENABLE_WEB

if [ "$FIREWALL_TYPE" = "firewalld" ]; then
    #############################################
    # FIREWALLD CONFIGURATION
    #############################################
    log "Configuring firewalld..."

    # Get default zone
    ZONE=$(firewall-cmd --get-default-zone)
    log "Default zone: $ZONE"

    # Essential mail ports
    log "Adding essential mail ports..."
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --permanent --add-port=25/tcp      # SMTP
    firewall-cmd --permanent --add-port=465/tcp     # SMTPS
    firewall-cmd --permanent --add-port=587/tcp     # Submission
    firewall-cmd --permanent --add-port=993/tcp     # IMAPS

    # Optional ports
    if [[ $ENABLE_POP3 =~ ^[Yy]$ ]]; then
        firewall-cmd --permanent --add-port=110/tcp
        log "Added POP3 (110)"
    fi
    if [[ $ENABLE_POP3S =~ ^[Yy]$ ]]; then
        firewall-cmd --permanent --add-port=995/tcp
        log "Added POP3S (995)"
    fi
    if [[ $ENABLE_IMAP =~ ^[Yy]$ ]]; then
        firewall-cmd --permanent --add-port=143/tcp
        log "Added IMAP (143)"
    fi
    if [[ $ENABLE_WEB =~ ^[Yy]$ ]]; then
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        log "Added HTTP/HTTPS"
    fi

    # Reload firewalld
    firewall-cmd --reload
    log "Firewalld configuration applied"

    echo ""
    echo "Current firewalld rules:"
    firewall-cmd --list-all

elif [ "$FIREWALL_TYPE" = "ufw" ]; then
    #############################################
    # UFW CONFIGURATION
    #############################################
    log "Configuring UFW..."

    # Reset and set defaults
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    # Essential ports
    log "Adding essential ports..."
    ufw allow 22/tcp comment 'SSH'
    ufw allow 25/tcp comment 'SMTP'
    ufw allow 465/tcp comment 'SMTPS'
    ufw allow 587/tcp comment 'Submission'
    ufw allow 993/tcp comment 'IMAPS'

    # Rate limit SSH
    ufw limit 22/tcp comment 'SSH rate limit'

    # Optional ports
    if [[ $ENABLE_POP3 =~ ^[Yy]$ ]]; then
        ufw allow 110/tcp comment 'POP3'
        log "Added POP3 (110)"
    fi
    if [[ $ENABLE_POP3S =~ ^[Yy]$ ]]; then
        ufw allow 995/tcp comment 'POP3S'
        log "Added POP3S (995)"
    fi
    if [[ $ENABLE_IMAP =~ ^[Yy]$ ]]; then
        ufw allow 143/tcp comment 'IMAP'
        log "Added IMAP (143)"
    fi
    if [[ $ENABLE_WEB =~ ^[Yy]$ ]]; then
        ufw allow 80/tcp comment 'HTTP'
        ufw allow 443/tcp comment 'HTTPS'
        log "Added HTTP/HTTPS"
    fi

    # Enable UFW
    echo ""
    read -p "Enable UFW now? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        ufw --force enable
        log "UFW enabled"
    else
        log "UFW configured but not enabled. Run 'ufw enable' when ready."
    fi

    echo ""
    echo "Current UFW rules:"
    ufw status verbose

else
    #############################################
    # IPTABLES CONFIGURATION (fallback)
    #############################################
    log "Configuring iptables directly..."

    # Flush existing rules (careful!)
    read -p "Flush existing iptables rules? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        iptables -F
        iptables -X
    fi

    # Default policies
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT

    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Essential ports
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT   # SSH
    iptables -A INPUT -p tcp --dport 25 -j ACCEPT   # SMTP
    iptables -A INPUT -p tcp --dport 465 -j ACCEPT  # SMTPS
    iptables -A INPUT -p tcp --dport 587 -j ACCEPT  # Submission
    iptables -A INPUT -p tcp --dport 993 -j ACCEPT  # IMAPS

    # Optional ports
    if [[ $ENABLE_POP3 =~ ^[Yy]$ ]]; then
        iptables -A INPUT -p tcp --dport 110 -j ACCEPT
    fi
    if [[ $ENABLE_POP3S =~ ^[Yy]$ ]]; then
        iptables -A INPUT -p tcp --dport 995 -j ACCEPT
    fi
    if [[ $ENABLE_IMAP =~ ^[Yy]$ ]]; then
        iptables -A INPUT -p tcp --dport 143 -j ACCEPT
    fi
    if [[ $ENABLE_WEB =~ ^[Yy]$ ]]; then
        iptables -A INPUT -p tcp --dport 80 -j ACCEPT
        iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    fi

    # Allow ICMP (ping)
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

    # Log dropped packets (optional, can be noisy)
    # iptables -A INPUT -j LOG --log-prefix "IPTables-Dropped: "

    log "iptables rules applied"

    # Save rules
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables.rules 2>/dev/null || true
        echo "Rules saved to /etc/iptables.rules"
        echo "To restore: iptables-restore < /etc/iptables.rules"
    fi

    echo ""
    echo "Current iptables rules:"
    iptables -L -n -v | head -30
fi

echo ""
echo "============================================"
echo "FIREWALL CONFIGURATION COMPLETE"
echo "============================================"
echo ""
echo "Essential mail ports opened:"
echo "  22  - SSH"
echo "  25  - SMTP (receive mail)"
echo "  465 - SMTPS (secure submission)"
echo "  587 - Submission (STARTTLS)"
echo "  993 - IMAPS (secure IMAP)"
echo ""
echo "TO BLOCK A MALICIOUS IP:"
if [ "$FIREWALL_TYPE" = "firewalld" ]; then
    echo "  firewall-cmd --add-rich-rule='rule family=ipv4 source address=<IP> reject'"
elif [ "$FIREWALL_TYPE" = "ufw" ]; then
    echo "  ufw deny from <IP> to any"
else
    echo "  iptables -I INPUT -s <IP> -j DROP"
fi
echo ""

log "Firewall configuration complete"
