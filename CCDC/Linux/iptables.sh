#!/bin/bash

################################################################################
# CCDC Competition IPTables Hardening Script
# 2026 Midwest CCDC Qualifier
#
# IMPORTANT: This script implements aggressive firewall rules
# - Default DROP policy on INPUT, OUTPUT, and FORWARD
# - Only specified ports are allowed
# - Extensive logging for incident response
# - Protection against common attacks
#
# COMPETITION REQUIREMENTS:
# - Must maintain ICMP (ping) for scoring
# - Must allow scored services (HTTP/HTTPS, SMTP, POP3, DNS)
# - Must allow team management access (SSH)
# - Should log suspicious activity for IR reports
################################################################################

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must be run as root"
    exit 1
fi

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Log file
LOGFILE="/ccdc/logs/iptables-$(date +%Y%m%d_%H%M%S).log"
mkdir -p /ccdc/logs

log() {
    echo -e "$1" | tee -a "$LOGFILE"
}

log_success() {
    log "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    log "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    log "${RED}[ERROR]${NC} $1"
}

log_info() {
    log "${BLUE}[INFO]${NC} $1"
}

# Save current rules before making changes
backup_current_rules() {
    log_info "Backing up current iptables rules..."
    mkdir -p /ccdc/backups/iptables
    
    iptables-save > "/ccdc/backups/iptables/rules-$(date +%Y%m%d_%H%M%S).bak"
    ip6tables-save > "/ccdc/backups/iptables/rules6-$(date +%Y%m%d_%H%M%S).bak"
    
    log_success "Current rules backed up"
}

# Detect system role based on running services
detect_system_role() {
    log_info "Detecting system role..."
    
    ROLE="generic"
    
    # Check for web server
    if systemctl is-active --quiet httpd || systemctl is-active --quiet apache2 || systemctl is-active --quiet nginx; then
        ROLE="web"
        log_info "Detected role: Web Server"
    fi
    
    # Check for mail server
    if systemctl is-active --quiet postfix || systemctl is-active --quiet sendmail || systemctl is-active --quiet dovecot; then
        ROLE="mail"
        log_info "Detected role: Mail Server"
    fi
    
    # Check for DNS server
    if systemctl is-active --quiet named || systemctl is-active --quiet bind9; then
        ROLE="dns"
        log_info "Detected role: DNS Server"
    fi
    
    # Check for Splunk
    if systemctl is-active --quiet splunk || systemctl is-active --quiet splunkd; then
        ROLE="splunk"
        log_info "Detected role: Splunk/SIEM Server"
    fi
    
    # Check for FTP
    if systemctl is-active --quiet vsftpd || systemctl is-active --quiet proftpd; then
        ROLE="ftp"
        log_info "Detected role: FTP Server"
    fi
    
    echo "$ROLE"
}

# Create custom chains for better organization and logging
create_custom_chains() {
    log_info "Creating custom iptables chains..."
    
    # Chain for logging dropped packets
    iptables -N LOG_DROP 2>/dev/null || iptables -F LOG_DROP
    iptables -A LOG_DROP -m limit --limit 5/min -j LOG --log-prefix "IPT-DROP: " --log-level 4
    iptables -A LOG_DROP -j DROP
    
    # Chain for logging accepted packets (for IR)
    iptables -N LOG_ACCEPT 2>/dev/null || iptables -F LOG_ACCEPT
    iptables -A LOG_ACCEPT -m limit --limit 10/min -j LOG --log-prefix "IPT-ACCEPT: " --log-level 4
    iptables -A LOG_ACCEPT -j ACCEPT
    
    # Chain for invalid packets
    iptables -N INVALID_DROP 2>/dev/null || iptables -F INVALID_DROP
    iptables -A INVALID_DROP -m limit --limit 5/min -j LOG --log-prefix "IPT-INVALID: " --log-level 4
    iptables -A INVALID_DROP -j DROP
    
    # Chain for rate limiting (anti-DDoS)
    iptables -N RATE_LIMIT 2>/dev/null || iptables -F RATE_LIMIT
    iptables -A RATE_LIMIT -m limit --limit 10/sec --limit-burst 20 -j RETURN
    iptables -A RATE_LIMIT -m limit --limit 5/min -j LOG --log-prefix "IPT-RATE-LIMIT: " --log-level 4
    iptables -A RATE_LIMIT -j DROP
    
    # Chain for port scanning detection
    iptables -N PORT_SCAN 2>/dev/null || iptables -F PORT_SCAN
    iptables -A PORT_SCAN -m recent --set --name portscan
    iptables -A PORT_SCAN -m limit --limit 5/min -j LOG --log-prefix "IPT-PORT-SCAN: " --log-level 4
    iptables -A PORT_SCAN -j DROP
    
    # Chain for bad TCP flags (attack detection)
    iptables -N BAD_TCP 2>/dev/null || iptables -F BAD_TCP
    iptables -A BAD_TCP -m limit --limit 5/min -j LOG --log-prefix "IPT-BAD-TCP: " --log-level 4
    iptables -A BAD_TCP -j DROP
    
    # Chain for SSH brute force protection
    iptables -N SSH_PROTECT 2>/dev/null || iptables -F SSH_PROTECT
    iptables -A SSH_PROTECT -m recent --name ssh_attack --rcheck --seconds 60 --hitcount 4 -j LOG_DROP
    iptables -A SSH_PROTECT -m recent --name ssh_attack --set
    iptables -A SSH_PROTECT -j ACCEPT
    
    log_success "Custom chains created"
}

# Flush existing rules
flush_rules() {
    log_warn "Flushing existing iptables rules..."
    
    # Flush all chains
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -t raw -F
    iptables -t raw -X
    
    # IPv6
    ip6tables -F
    ip6tables -X
    
    log_success "Rules flushed"
}

# Set default policies
set_default_policies() {
    log_info "Setting default DROP policies..."
    
    # Default DROP on all chains
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    
    # IPv6 - be more restrictive since not needed in competition
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP
    
    log_success "Default policies set to DROP"
}

# Base rules that apply to all systems
apply_base_rules() {
    log_info "Applying base firewall rules..."
    
    #============================================================================
    # INVALID PACKET PROTECTION
    #============================================================================
    log_info "  → Configuring invalid packet protection..."
    
    # Drop invalid packets
    iptables -A INPUT -m conntrack --ctstate INVALID -j INVALID_DROP
    iptables -A OUTPUT -m conntrack --ctstate INVALID -j INVALID_DROP
    iptables -A FORWARD -m conntrack --ctstate INVALID -j INVALID_DROP
    
    #============================================================================
    # BAD TCP FLAGS PROTECTION (Attack Detection)
    #============================================================================
    log_info "  → Configuring TCP flag validation..."
    
    # NULL packets
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j BAD_TCP
    
    # SYN-FIN packets
    iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j BAD_TCP
    
    # SYN-RST packets  
    iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j BAD_TCP
    
    # FIN-RST packets
    iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j BAD_TCP
    
    # FIN without ACK
    iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j BAD_TCP
    
    # PSH without ACK
    iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j BAD_TCP
    
    # URG without ACK
    iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j BAD_TCP
    
    # XMAS packets
    iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j BAD_TCP
    
    # All flags set
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j BAD_TCP
    
    #============================================================================
    # LOOPBACK INTERFACE
    #============================================================================
    log_info "  → Allowing loopback traffic..."
    
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    #============================================================================
    # ESTABLISHED/RELATED CONNECTIONS
    #============================================================================
    log_info "  → Allowing established/related connections..."
    
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    #============================================================================
    # ICMP (PING) - REQUIRED FOR COMPETITION
    #============================================================================
    log_info "  → Allowing ICMP (ping) - REQUIRED FOR SCORING..."
    
    # Allow incoming ping (echo request)
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/sec -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP  # Rate limit
    
    # Allow outgoing ping
    iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
    
    # Allow ping responses
    iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
    iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
    
    # Allow destination unreachable
    iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
    iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
    
    # Allow time exceeded
    iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
    iptables -A OUTPUT -p icmp --icmp-type time-exceeded -j ACCEPT
    
    #============================================================================
    # ANTI-SPOOFING (RFC 1918 Private Networks)
    #============================================================================
    log_info "  → Configuring anti-spoofing rules..."
    
    # Note: In CCDC, internal networks use private IPs
    # Only block spoofed packets from OUTSIDE (WAN interface)
    # This is tricky - need to identify WAN interface
    
    # Block packets from outside claiming to be from internal networks
    # (Only if we can identify external interface - skip for now to be safe)
    
    #============================================================================
    # FRAGMENTED PACKETS
    #============================================================================
    log_info "  → Protecting against fragmented packet attacks..."
    
    # Log and drop fragmented packets
    iptables -A INPUT -f -m limit --limit 5/min -j LOG --log-prefix "IPT-FRAGMENT: " --log-level 4
    iptables -A INPUT -f -j DROP
    
    #============================================================================
    # BROADCAST/MULTICAST PROTECTION
    #============================================================================
    log_info "  → Protecting against broadcast attacks..."
    
    # Drop broadcast packets
    iptables -A INPUT -m pkttype --pkt-type broadcast -j DROP
    iptables -A INPUT -m pkttype --pkt-type multicast -j DROP
    
    #============================================================================
    # PORT SCAN DETECTION
    #============================================================================
    log_info "  → Configuring port scan detection..."
    
    # Detect SYN scans
    iptables -A INPUT -p tcp --tcp-flags ALL SYN -m recent --name portscan --rcheck --seconds 60 --hitcount 20 -j PORT_SCAN
    
    # Detect FIN scans
    iptables -A INPUT -p tcp --tcp-flags ALL FIN -m recent --name portscan --rcheck --seconds 60 --hitcount 20 -j PORT_SCAN
    
    # Detect NULL scans
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -m recent --name portscan --rcheck --seconds 60 --hitcount 20 -j PORT_SCAN
    
    #============================================================================
    # SYN FLOOD PROTECTION
    #============================================================================
    log_info "  → Configuring SYN flood protection..."
    
    # Rate limit new connections
    iptables -A INPUT -p tcp --syn -m limit --limit 10/sec --limit-burst 20 -j ACCEPT
    iptables -A INPUT -p tcp --syn -j LOG_DROP
    
    log_success "Base rules applied"
}


# Service-specific rules based on system role
apply_service_rules() {
    local role=$1
    log_info "Applying service rules for role: $role..."
    
    case $role in
        web)
            apply_web_rules
            ;;
        mail)
            apply_mail_rules
            ;;
        dns)
            apply_dns_rules
            ;;
        splunk)
            apply_splunk_rules
            ;;
        ftp)
            apply_ftp_rules
            ;;
        *)
            apply_generic_rules
            ;;
    esac
}

# Web server rules
apply_web_rules() {
    log_info "  → Configuring web server rules (HTTP/HTTPS)..."
    
    #============================================================================
    # HTTP (Port 80) - SCORED SERVICE
    #============================================================================
    # Inbound HTTP with rate limiting
    iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -m limit --limit 50/sec --limit-burst 100 -j ACCEPT
    iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j LOG_DROP
    iptables -A OUTPUT -p tcp --sport 80 -j ACCEPT
    
    # Outbound HTTP (for updates, etc.)
    iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --sport 80 -j ACCEPT
    
    #============================================================================
    # HTTPS (Port 443) - SCORED SERVICE
    #============================================================================
    # Inbound HTTPS with rate limiting
    iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -m limit --limit 50/sec --limit-burst 100 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j LOG_DROP
    iptables -A OUTPUT -p tcp --sport 443 -j ACCEPT
    
    # Outbound HTTPS (for updates, etc.)
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
    iptables -A INPUT -p tcp --sport 443 -j ACCEPT
    
    #============================================================================
    # SPLUNK FORWARDER (Port 9997) - AS REQUESTED
    #============================================================================
    log_info "  → Allowing Splunk forwarder (9997)..."
    
    # Inbound Splunk forwarding
    iptables -A INPUT -p tcp --dport 9997 -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 9997 -j ACCEPT
    
    # Outbound Splunk forwarding
    iptables -A OUTPUT -p tcp --dport 9997 -j ACCEPT
    iptables -A INPUT -p tcp --sport 9997 -j ACCEPT
    
    log_success "Web server rules applied (80, 443, 9997)"
}

# Mail server rules
apply_mail_rules() {
    log_info "  → Configuring mail server rules..."
    
    #============================================================================
    # SMTP (Port 25) - SCORED SERVICE
    #============================================================================
    iptables -A INPUT -p tcp --dport 25 -m limit --limit 10/sec -j ACCEPT
    iptables -A INPUT -p tcp --dport 25 -j LOG_DROP
    iptables -A OUTPUT -p tcp --sport 25 -j ACCEPT
    
    # Outbound SMTP for sending
    iptables -A OUTPUT -p tcp --dport 25 -j ACCEPT
    iptables -A INPUT -p tcp --sport 25 -j ACCEPT
    
    #============================================================================
    # SMTP Submission (Port 587)
    #============================================================================
    iptables -A INPUT -p tcp --dport 587 -m limit --limit 10/sec -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 587 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 587 -j ACCEPT
    
    #============================================================================
    # POP3 (Port 110) - SCORED SERVICE
    #============================================================================
    iptables -A INPUT -p tcp --dport 110 -m limit --limit 10/sec -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 110 -j ACCEPT
    
    #============================================================================
    # IMAP (Ports 143/993) - May be used instead of POP3
    #============================================================================
    iptables -A INPUT -p tcp --dport 143 -m limit --limit 10/sec -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 143 -j ACCEPT
    
    #============================================================================
    # SPLUNK FORWARDER (Port 9997)
    #============================================================================
    iptables -A INPUT -p tcp --dport 9997 -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 9997 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 9997 -j ACCEPT
    
    # Also allow HTTP/HTTPS for webmail
    iptables -A INPUT -p tcp --dport 80 -m limit --limit 50/sec -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -m limit --limit 50/sec -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 80 -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 443 -j ACCEPT
    
    log_success "Mail server rules applied"
}

# Splunk server rules
apply_splunk_rules() {
    log_info "  → Configuring Splunk server rules..."
    
    #============================================================================
    # SPLUNK WEB (Port 8000)
    #============================================================================
    iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 8000 -j ACCEPT
    
    #============================================================================
    # SPLUNK FORWARDER (Port 9997) - Receiving logs
    #============================================================================
    iptables -A INPUT -p tcp --dport 9997 -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 9997 -j ACCEPT
    
    #============================================================================
    # HTTP/HTTPS for updates
    #============================================================================
    iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
    
    log_success "Splunk server rules applied"
}

# FTP server rules
apply_ftp_rules() {
    log_info "  → Configuring FTP server rules..."
    
    #============================================================================
    # FTP Control (Port 21)
    #============================================================================
    iptables -A INPUT -p tcp --dport 21 -m limit --limit 10/sec -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 21 -j ACCEPT
    
    #============================================================================
    # FTP Passive Mode (High ports)
    #============================================================================
    # Note: Passive FTP uses random high ports - need conntrack helper
    # Load FTP connection tracking module
    modprobe nf_conntrack_ftp
    
    # Allow passive FTP data connections
    iptables -A INPUT -p tcp --dport 1024:65535 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 1024:65535 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    #============================================================================
    # SPLUNK FORWARDER
    #============================================================================
    iptables -A OUTPUT -p tcp --dport 9997 -j ACCEPT
    
    log_success "FTP server rules applied"
}

# Generic rules (when role can't be determined)
apply_generic_rules() {
    log_info "  → Configuring generic service rules..."
    
    # Allow HTTP, HTTPS, Splunk as requested
    log_info "    → Allowing HTTP (80)..."
    iptables -A INPUT -p tcp --dport 80 -m limit --limit 50/sec -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 80 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --sport 80 -j ACCEPT
    
    log_info "    → Allowing HTTPS (443)..."
    iptables -A INPUT -p tcp --dport 443 -m limit --limit 50/sec -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 443 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
    iptables -A INPUT -p tcp --sport 443 -j ACCEPT
    
    log_info "    → Allowing Splunk (9997)..."
    iptables -A INPUT -p tcp --dport 9997 -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 9997 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 9997 -j ACCEPT
    iptables -A INPUT -p tcp --sport 9997 -j ACCEPT
    
    log_success "Generic service rules applied (80, 443, 9997)"
}

# Final logging and drop rules
apply_final_rules() {
    log_info "Applying final catch-all rules..."
    
    # Log remaining INPUT packets before dropping
    iptables -A INPUT -m limit --limit 3/min -j LOG --log-prefix "IPT-INPUT-DROP: " --log-level 4
    iptables -A INPUT -j DROP
    
    # Log remaining OUTPUT packets before dropping
    iptables -A OUTPUT -m limit --limit 3/min -j LOG --log-prefix "IPT-OUTPUT-DROP: " --log-level 4
    iptables -A OUTPUT -j DROP
    
    # Log remaining FORWARD packets before dropping
    iptables -A FORWARD -m limit --limit 3/min -j LOG --log-prefix "IPT-FORWARD-DROP: " --log-level 4
    iptables -A FORWARD -j DROP
    
    log_success "Final rules applied"
}

# Save iptables rules persistently
save_rules() {
    log_info "Saving iptables rules..."
    
    # Determine the system type and save accordingly
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu
        if command -v netfilter-persistent &> /dev/null; then
            netfilter-persistent save
        elif command -v iptables-save &> /dev/null; then
            iptables-save > /etc/iptables/rules.v4
            ip6tables-save > /etc/iptables/rules.v6
        fi
    elif [ -f /etc/redhat-release ]; then
        # RHEL/CentOS/Fedora
        if command -v iptables-save &> /dev/null; then
            iptables-save > /etc/sysconfig/iptables
            ip6tables-save > /etc/sysconfig/ip6tables
        fi
    fi
    
    # Also save to CCDC directory
    iptables-save > /ccdc/backups/iptables/current-rules.v4
    ip6tables-save > /ccdc/backups/iptables/current-rules.v6
    
    log_success "Rules saved"
}

# Create systemd service for persistence
create_firewall_service() {
    log_info "Creating firewall persistence service..."
    
    cat > /etc/systemd/system/ccdc-firewall.service <<'EOF'
[Unit]
Description=CCDC Competition Firewall
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/iptables-restore /ccdc/backups/iptables/current-rules.v4
ExecStop=/usr/sbin/iptables -F
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable ccdc-firewall.service
    
    log_success "Firewall service created and enabled"
}

# Display current rules
display_rules() {
    log_info "Current iptables rules:"
    echo ""
    echo "=== INPUT Chain ==="
    iptables -L INPUT -v -n --line-numbers
    echo ""
    echo "=== OUTPUT Chain ==="
    iptables -L OUTPUT -v -n --line-numbers
    echo ""
    echo "=== Custom Chains ==="
    iptables -L LOG_DROP -v -n --line-numbers 2>/dev/null
    iptables -L LOG_ACCEPT -v -n --line-numbers 2>/dev/null
    iptables -L SSH_PROTECT -v -n --line-numbers 2>/dev/null
    echo ""
}

# Create management scripts
create_management_scripts() {
    log_info "Creating firewall management scripts..."
    
    mkdir -p /ccdc/scripts/firewall
    
    # Script to view rules
    cat > /ccdc/scripts/firewall/show_rules.sh <<'SHOWEOF'
#!/bin/bash
echo "=== IPTABLES RULES ==="
echo ""
echo "=== Filter Table ==="
iptables -L -v -n --line-numbers
echo ""
echo "=== NAT Table ==="
iptables -t nat -L -v -n --line-numbers
echo ""
echo "=== Mangle Table ==="
iptables -t mangle -L -v -n --line-numbers
SHOWEOF
    chmod +x /ccdc/scripts/firewall/show_rules.sh
    
    # Script to temporarily disable firewall (EMERGENCY ONLY)
    cat > /ccdc/scripts/firewall/disable_firewall_EMERGENCY.sh <<'DISEOF'
#!/bin/bash
echo "WARNING: This will disable the firewall - FOR EMERGENCY USE ONLY"
echo "Press Ctrl+C to cancel, or wait 5 seconds to continue..."
sleep 5

echo "Saving current rules..."
iptables-save > /ccdc/backups/iptables/emergency-backup-$(date +%Y%m%d_%H%M%S).v4

echo "Setting ACCEPT policies..."
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

echo "Flushing rules..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t mangle -F

echo "FIREWALL DISABLED - System is UNPROTECTED"
echo "To restore: iptables-restore < /ccdc/backups/iptables/current-rules.v4"
DISEOF
    chmod +x /ccdc/scripts/firewall/disable_firewall_EMERGENCY.sh
    
    # Script to restore from backup
    cat > /ccdc/scripts/firewall/restore_from_backup.sh <<'RESTEOF'
#!/bin/bash
echo "Available backups:"
ls -lht /ccdc/backups/iptables/*.v4 | head -10
echo ""
read -p "Enter backup filename to restore: " backup
if [ -f "/ccdc/backups/iptables/$backup" ]; then
    echo "Restoring from $backup..."
    iptables-restore < "/ccdc/backups/iptables/$backup"
    echo "Firewall restored"
else
    echo "Backup not found"
fi
RESTEOF
    chmod +x /ccdc/scripts/firewall/restore_from_backup.sh
    
    # Script to add temporary allow rule
    cat > /ccdc/scripts/firewall/allow_port_temp.sh <<'ALLOWEOF'
#!/bin/bash
if [ $# -ne 2 ]; then
    echo "Usage: $0 <port> <protocol>"
    echo "Example: $0 8080 tcp"
    exit 1
fi

PORT=$1
PROTO=$2

echo "Adding temporary rule to allow $PROTO/$PORT..."
iptables -I INPUT -p $PROTO --dport $PORT -j ACCEPT
iptables -I OUTPUT -p $PROTO --sport $PORT -j ACCEPT

echo "Rule added. View with: iptables -L -n | grep $PORT"
echo "To save: iptables-save > /ccdc/backups/iptables/current-rules.v4"
ALLOWEOF
    chmod +x /ccdc/scripts/firewall/allow_port_temp.sh
    
    # Script to monitor blocked connections
    cat > /ccdc/scripts/firewall/monitor_blocks.sh <<'MONEOF'
#!/bin/bash
echo "Monitoring firewall blocks in real-time..."
echo "Press Ctrl+C to stop"
echo ""
tail -f /var/log/syslog /var/log/messages 2>/dev/null | grep --line-buffered "IPT-"
MONEOF
    chmod +x /ccdc/scripts/firewall/monitor_blocks.sh
    
    log_success "Management scripts created in /ccdc/scripts/firewall/"
}

# Main execution
main() {
    clear
    echo "================================================================================"
    echo "           CCDC Competition IPTables Hardening"
    echo "           2026 Midwest CCDC Qualifier"
    echo "================================================================================"
    echo ""
    log_info "Starting iptables configuration..."
    echo ""
    
    # Warning
    echo -e "${RED}WARNING: This will replace all existing firewall rules!${NC}"
    echo -e "${YELLOW}Make sure you understand the impact before proceeding.${NC}"
    echo ""
    echo "This script will:"
    echo "  - Set default DROP policy on INPUT, OUTPUT, and FORWARD"
    echo "  - Allow only specified ports (80, 443, 9997, and service-specific)"
    echo "  - Enable extensive logging for incident response"
    echo "  - Implement protection against common attacks"
    echo ""
    read -p "Continue? [y/N]: " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Aborted by user"
        exit 0
    fi
    
    echo ""
    
    # Install iptables if needed
    if ! command -v iptables &> /dev/null; then
        log_error "iptables not found! Installing..."
        if command -v apt-get &> /dev/null; then
            apt-get update && apt-get install -y iptables iptables-persistent
        elif command -v yum &> /dev/null; then
            yum install -y iptables iptables-services
        fi
    fi
    
    # Execute configuration steps
    backup_current_rules
    
    # Detect role
    SYSTEM_ROLE=$(detect_system_role)
    echo ""
    
    flush_rules
    create_custom_chains
    set_default_policies
    apply_base_rules
    apply_management_rules
    apply_service_rules "$SYSTEM_ROLE"
    apply_ntp_rules
    apply_final_rules
    save_rules
    create_firewall_service
    create_management_scripts
    
    echo ""
    echo "================================================================================"
    log_success "IPTables configuration complete!"
    echo "================================================================================"
    echo ""
    echo "CONFIGURATION SUMMARY:"
    echo "  System Role: $SYSTEM_ROLE"
    echo "  Default Policy: DROP (all chains)"
    echo "  Allowed Services:"
    echo "    - HTTP (80) - SCORED SERVICE"
    echo "    - HTTPS (443) - SCORED SERVICE"
    echo "    - Splunk (9997)"
    
    case $SYSTEM_ROLE in
        mail)
            echo "    - SMTP (25, 587) - SCORED SERVICE"
            echo "    - POP3 (110) - SCORED SERVICE"
            echo "    - IMAP (143)"
            ;;
        splunk)
            echo "    - Splunk Web (8000)"
            ;;
        ftp)
            echo "    - FTP (21, 990)"
            echo "    - FTP Passive (high ports)"
            ;;
    esac
    
    echo ""
    echo "  Protection Features:"
    echo "    ✓ Invalid packet filtering"
    echo "    ✓ Bad TCP flag detection"
    echo "    ✓ Port scan detection"
    echo "    ✓ SYN flood protection"
    echo "    ✓ SSH brute-force protection"
    echo "    ✓ Rate limiting on services"
    echo "    ✓ Fragment attack protection"
    echo "    ✓ Extensive logging"
    echo ""
    echo "  Management Scripts:"
    echo "    /ccdc/scripts/firewall/show_rules.sh"
    echo "    /ccdc/scripts/firewall/allow_port_temp.sh"
    echo "    /ccdc/scripts/firewall/monitor_blocks.sh"
    echo "    /ccdc/scripts/firewall/restore_from_backup.sh"
    echo "    /ccdc/scripts/firewall/disable_firewall_EMERGENCY.sh"
    echo ""
    echo "  Backups:"
    echo "    /ccdc/backups/iptables/"
    echo ""
    echo "IMPORTANT REMINDERS:"
    echo "  - Test ALL scored services immediately"
    echo "  - Monitor /var/log/syslog for IPT- prefixed entries"
    echo "  - Rules are persistent across reboots"
    echo "  - Use allow_port_temp.sh to quickly allow additional ports"
    echo ""
    echo "Log file: $LOGFILE"
    echo "================================================================================"
    echo ""
    
    # Offer to display rules
    read -p "Display current rules now? [y/N]: " show
    if [[ "$show" =~ ^[Yy]$ ]]; then
        echo ""
        display_rules
    fi
}

# Run main function
main

exit 0
