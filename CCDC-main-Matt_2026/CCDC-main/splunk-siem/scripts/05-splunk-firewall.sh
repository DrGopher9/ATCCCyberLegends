#!/bin/bash
#===============================================================================
# CCDC Splunk SIEM - Firewall Configuration Script
# Target: Splunk Enterprise on Linux
# Run as: root
#===============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

LOGDIR="/opt/splunk-ccdc-logs"
BACKUP_DIR="/opt/splunk-ccdc-backups"
mkdir -p "$LOGDIR" "$BACKUP_DIR"

echo -e "${CYAN}========================================"
echo "  CCDC Splunk Firewall Configuration"
echo -e "========================================${NC}"
echo ""

#-------------------------------------------------------------------------------
echo -e "${YELLOW}=== SPLUNK NETWORK PORTS ===${NC}"
echo ""
echo "Standard Splunk ports:"
echo "  8000  - Splunk Web (HTTPS)"
echo "  8089  - Splunkd REST API / Management"
echo "  9997  - Forwarder receiving (indexer)"
echo "  8088  - HTTP Event Collector (HEC)"
echo "  514   - Syslog receiving (TCP/UDP)"
echo "  9998  - Replication (clustering)"
echo "  8191  - KV Store"
echo ""
echo "Current listening ports:"
ss -tlnp 2>/dev/null | grep -E "(splunk|:80|:8089|:9997|:8088|:514)" || \
netstat -tlnp 2>/dev/null | grep -E "(splunk|:80|:8089|:9997|:8088|:514)"
echo ""

#-------------------------------------------------------------------------------
# Detect firewall type
FIREWALL_TYPE=""
if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    FIREWALL_TYPE="ufw"
elif command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
    FIREWALL_TYPE="firewalld"
else
    FIREWALL_TYPE="iptables"
fi

echo -e "${YELLOW}[*] Detected firewall: $FIREWALL_TYPE${NC}"
echo ""

#===============================================================================
# UFW CONFIGURATION
#===============================================================================
if [ "$FIREWALL_TYPE" = "ufw" ]; then
    echo -e "${CYAN}=== UFW Configuration ===${NC}"
    echo ""

    # Backup current rules
    ufw status verbose > "$BACKUP_DIR/ufw_rules_$(date +%Y%m%d_%H%M%S).bak"

    echo "Current UFW status:"
    ufw status verbose
    echo ""

    read -p "Configure UFW for Splunk? (y/N): " config_ufw
    if [ "$config_ufw" = "y" ]; then
        # Set default policies
        ufw default deny incoming
        ufw default allow outgoing
        echo -e "${GREEN}[+] Default policies set${NC}"

        # SSH (always allow)
        ufw allow 22/tcp comment 'SSH'
        echo -e "${GREEN}[+] SSH (22) allowed${NC}"

        # Splunk Web
        read -p "Allow Splunk Web (8000) from anywhere? (y/N): " allow_web
        if [ "$allow_web" = "y" ]; then
            ufw allow 8000/tcp comment 'Splunk Web'
            echo -e "${GREEN}[+] Splunk Web (8000) allowed${NC}"
        else
            read -p "Allow from specific network? (e.g., 172.20.0.0/16): " web_net
            if [ -n "$web_net" ]; then
                ufw allow from "$web_net" to any port 8000 proto tcp comment 'Splunk Web'
                echo -e "${GREEN}[+] Splunk Web (8000) allowed from $web_net${NC}"
            fi
        fi

        # Splunk Management
        read -p "Allow Splunk Management (8089) from anywhere? (y/N): " allow_mgmt
        if [ "$allow_mgmt" = "y" ]; then
            ufw allow 8089/tcp comment 'Splunk Mgmt'
            echo -e "${GREEN}[+] Splunk Management (8089) allowed${NC}"
        else
            read -p "Allow from specific network?: " mgmt_net
            if [ -n "$mgmt_net" ]; then
                ufw allow from "$mgmt_net" to any port 8089 proto tcp comment 'Splunk Mgmt'
                echo -e "${GREEN}[+] Splunk Management (8089) allowed from $mgmt_net${NC}"
            fi
        fi

        # Forwarder receiving (9997)
        read -p "Allow forwarder receiving (9997)? (y/N): " allow_fwd
        if [ "$allow_fwd" = "y" ]; then
            read -p "Allow from specific network? (e.g., 172.20.0.0/16 or 'any'): " fwd_net
            if [ "$fwd_net" = "any" ]; then
                ufw allow 9997/tcp comment 'Splunk Forwarders'
            else
                ufw allow from "$fwd_net" to any port 9997 proto tcp comment 'Splunk Forwarders'
            fi
            echo -e "${GREEN}[+] Forwarder receiving (9997) allowed${NC}"
        fi

        # HEC (8088)
        read -p "Allow HTTP Event Collector (8088)? (y/N): " allow_hec
        if [ "$allow_hec" = "y" ]; then
            read -p "Allow from specific network? (or 'any'): " hec_net
            if [ "$hec_net" = "any" ]; then
                ufw allow 8088/tcp comment 'Splunk HEC'
            else
                ufw allow from "$hec_net" to any port 8088 proto tcp comment 'Splunk HEC'
            fi
            echo -e "${GREEN}[+] HEC (8088) allowed${NC}"
        fi

        # Syslog (514)
        read -p "Allow Syslog receiving (514)? (y/N): " allow_syslog
        if [ "$allow_syslog" = "y" ]; then
            read -p "Allow from specific network? (or 'any'): " syslog_net
            if [ "$syslog_net" = "any" ]; then
                ufw allow 514/tcp comment 'Syslog TCP'
                ufw allow 514/udp comment 'Syslog UDP'
            else
                ufw allow from "$syslog_net" to any port 514 proto tcp comment 'Syslog TCP'
                ufw allow from "$syslog_net" to any port 514 proto udp comment 'Syslog UDP'
            fi
            echo -e "${GREEN}[+] Syslog (514) allowed${NC}"
        fi

        # Enable firewall
        echo ""
        read -p "Enable UFW now? (y/N): " enable_ufw
        if [ "$enable_ufw" = "y" ]; then
            ufw --force enable
            echo -e "${GREEN}[+] UFW enabled${NC}"
        fi

        echo ""
        echo "Final UFW status:"
        ufw status numbered
    fi

#===============================================================================
# FIREWALLD CONFIGURATION
#===============================================================================
elif [ "$FIREWALL_TYPE" = "firewalld" ]; then
    echo -e "${CYAN}=== Firewalld Configuration ===${NC}"
    echo ""

    # Backup current rules
    firewall-cmd --list-all > "$BACKUP_DIR/firewalld_rules_$(date +%Y%m%d_%H%M%S).bak"

    echo "Current firewalld status:"
    firewall-cmd --list-all
    echo ""

    read -p "Configure firewalld for Splunk? (y/N): " config_fwd
    if [ "$config_fwd" = "y" ]; then
        # Create Splunk service definitions
        echo "[*] Creating Splunk service definitions..."

        # Splunk Web service
        cat > /etc/firewalld/services/splunk-web.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>Splunk Web</short>
  <description>Splunk Web Interface</description>
  <port protocol="tcp" port="8000"/>
</service>
EOF

        # Splunk Management service
        cat > /etc/firewalld/services/splunk-mgmt.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>Splunk Management</short>
  <description>Splunk Management/REST API</description>
  <port protocol="tcp" port="8089"/>
</service>
EOF

        # Splunk Forwarder service
        cat > /etc/firewalld/services/splunk-forwarder.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>Splunk Forwarder</short>
  <description>Splunk Forwarder Receiving</description>
  <port protocol="tcp" port="9997"/>
</service>
EOF

        # Splunk HEC service
        cat > /etc/firewalld/services/splunk-hec.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>Splunk HEC</short>
  <description>Splunk HTTP Event Collector</description>
  <port protocol="tcp" port="8088"/>
</service>
EOF

        firewall-cmd --reload

        # SSH
        firewall-cmd --permanent --add-service=ssh
        echo -e "${GREEN}[+] SSH allowed${NC}"

        # Splunk Web
        read -p "Allow Splunk Web (8000)? (y/N): " allow_web
        if [ "$allow_web" = "y" ]; then
            firewall-cmd --permanent --add-service=splunk-web
            echo -e "${GREEN}[+] Splunk Web (8000) allowed${NC}"
        fi

        # Splunk Management
        read -p "Allow Splunk Management (8089)? (y/N): " allow_mgmt
        if [ "$allow_mgmt" = "y" ]; then
            firewall-cmd --permanent --add-service=splunk-mgmt
            echo -e "${GREEN}[+] Splunk Management (8089) allowed${NC}"
        fi

        # Forwarder receiving
        read -p "Allow forwarder receiving (9997)? (y/N): " allow_fwd
        if [ "$allow_fwd" = "y" ]; then
            firewall-cmd --permanent --add-service=splunk-forwarder
            echo -e "${GREEN}[+] Forwarder receiving (9997) allowed${NC}"
        fi

        # HEC
        read -p "Allow HTTP Event Collector (8088)? (y/N): " allow_hec
        if [ "$allow_hec" = "y" ]; then
            firewall-cmd --permanent --add-service=splunk-hec
            echo -e "${GREEN}[+] HEC (8088) allowed${NC}"
        fi

        # Syslog
        read -p "Allow Syslog receiving (514)? (y/N): " allow_syslog
        if [ "$allow_syslog" = "y" ]; then
            firewall-cmd --permanent --add-port=514/tcp
            firewall-cmd --permanent --add-port=514/udp
            echo -e "${GREEN}[+] Syslog (514) allowed${NC}"
        fi

        # Reload
        firewall-cmd --reload
        echo ""
        echo "Final firewalld status:"
        firewall-cmd --list-all
    fi

#===============================================================================
# IPTABLES CONFIGURATION
#===============================================================================
else
    echo -e "${CYAN}=== iptables Configuration ===${NC}"
    echo ""

    # Backup current rules
    iptables-save > "$BACKUP_DIR/iptables_$(date +%Y%m%d_%H%M%S).bak"

    echo "Current iptables rules:"
    iptables -L -n --line-numbers | head -50
    echo ""

    read -p "Configure iptables for Splunk? (y/N): " config_ipt
    if [ "$config_ipt" = "y" ]; then
        echo -e "${YELLOW}[!] This will flush existing rules. Continue? (y/N): ${NC}"
        read confirm
        if [ "$confirm" = "y" ]; then
            # Flush rules
            iptables -F
            iptables -X

            # Default policies
            iptables -P INPUT DROP
            iptables -P FORWARD DROP
            iptables -P OUTPUT ACCEPT

            # Loopback
            iptables -A INPUT -i lo -j ACCEPT

            # Established connections
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

            # SSH
            iptables -A INPUT -p tcp --dport 22 -j ACCEPT
            echo -e "${GREEN}[+] SSH (22) allowed${NC}"

            # Splunk Web
            read -p "Allow Splunk Web (8000)? (y/N): " allow_web
            if [ "$allow_web" = "y" ]; then
                iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
                echo -e "${GREEN}[+] Splunk Web (8000) allowed${NC}"
            fi

            # Splunk Management
            read -p "Allow Splunk Management (8089)? (y/N): " allow_mgmt
            if [ "$allow_mgmt" = "y" ]; then
                iptables -A INPUT -p tcp --dport 8089 -j ACCEPT
                echo -e "${GREEN}[+] Splunk Management (8089) allowed${NC}"
            fi

            # Forwarder receiving
            read -p "Allow forwarder receiving (9997)? (y/N): " allow_fwd
            if [ "$allow_fwd" = "y" ]; then
                iptables -A INPUT -p tcp --dport 9997 -j ACCEPT
                echo -e "${GREEN}[+] Forwarder receiving (9997) allowed${NC}"
            fi

            # HEC
            read -p "Allow HTTP Event Collector (8088)? (y/N): " allow_hec
            if [ "$allow_hec" = "y" ]; then
                iptables -A INPUT -p tcp --dport 8088 -j ACCEPT
                echo -e "${GREEN}[+] HEC (8088) allowed${NC}"
            fi

            # Syslog
            read -p "Allow Syslog receiving (514)? (y/N): " allow_syslog
            if [ "$allow_syslog" = "y" ]; then
                iptables -A INPUT -p tcp --dport 514 -j ACCEPT
                iptables -A INPUT -p udp --dport 514 -j ACCEPT
                echo -e "${GREEN}[+] Syslog (514) allowed${NC}"
            fi

            # Save rules
            echo ""
            read -p "Save iptables rules? (y/N): " save_rules
            if [ "$save_rules" = "y" ]; then
                if command -v iptables-save &>/dev/null; then
                    iptables-save > /etc/iptables.rules
                    echo -e "${GREEN}[+] Rules saved to /etc/iptables.rules${NC}"

                    # Create restore on boot
                    if [ -d /etc/network/if-pre-up.d ]; then
                        echo '#!/bin/sh' > /etc/network/if-pre-up.d/iptables
                        echo 'iptables-restore < /etc/iptables.rules' >> /etc/network/if-pre-up.d/iptables
                        chmod +x /etc/network/if-pre-up.d/iptables
                    fi
                fi
            fi

            echo ""
            echo "Final iptables rules:"
            iptables -L -n --line-numbers
        fi
    fi
fi

#===============================================================================
# BLOCK MALICIOUS IPS
#===============================================================================

echo ""
echo -e "${YELLOW}[*] Block specific IPs${NC}"
echo ""

read -p "Block any IPs? (enter IP or skip): " block_ip
while [ -n "$block_ip" ]; do
    case "$FIREWALL_TYPE" in
        ufw)
            ufw deny from "$block_ip"
            ;;
        firewalld)
            firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$block_ip' reject"
            firewall-cmd --reload
            ;;
        iptables)
            iptables -I INPUT -s "$block_ip" -j DROP
            ;;
    esac
    echo -e "${GREEN}[+] Blocked: $block_ip${NC}"
    echo "$block_ip" >> "$LOGDIR/blocked_ips.txt"

    read -p "Block another IP? (enter IP or skip): " block_ip
done

#===============================================================================
echo ""
echo -e "${GREEN}========================================"
echo "  Firewall Configuration Complete"
echo -e "========================================${NC}"
echo ""
echo "Backup saved to: $BACKUP_DIR/"
echo ""
echo -e "${YELLOW}SPLUNK PORTS REFERENCE:${NC}"
echo "  8000  - Web Interface"
echo "  8089  - Management/REST API"
echo "  9997  - Forwarder receiving"
echo "  8088  - HTTP Event Collector"
echo "  514   - Syslog"
echo ""
