#!/bin/bash
#===============================================================================
# CCDC Splunk Universal Forwarder - Linux Deployment Script
# Target: Ubuntu, Fedora, CentOS/RHEL Linux servers
# Run as: root
#===============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================"
echo "  Splunk Universal Forwarder Deployment"
echo -e "========================================${NC}"
echo ""

# Configuration - UPDATE THESE
SPLUNK_INDEXER=""        # Will be set interactively
SPLUNK_PORT="9997"
FORWARDER_VERSION="9.1.2"
FORWARDER_ADMIN_PASS=""  # Will be set interactively

#-------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Configuration${NC}"
echo ""

read -p "Enter Splunk Indexer IP/hostname: " SPLUNK_INDEXER
read -p "Enter Splunk receiving port [9997]: " port_input
SPLUNK_PORT=${port_input:-9997}
read -sp "Enter admin password for forwarder: " FORWARDER_ADMIN_PASS
echo ""

if [ -z "$SPLUNK_INDEXER" ] || [ -z "$FORWARDER_ADMIN_PASS" ]; then
    echo -e "${RED}[!] Indexer IP and admin password are required${NC}"
    exit 1
fi

#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[*] Detecting OS...${NC}"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    echo "Detected OS: $OS"
else
    echo -e "${RED}Cannot detect OS${NC}"
    exit 1
fi

#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[*] Checking for existing Splunk installation...${NC}"

SPLUNK_HOME="/opt/splunkforwarder"

if [ -d "$SPLUNK_HOME" ]; then
    echo -e "${YELLOW}[!] Splunk Forwarder already installed at $SPLUNK_HOME${NC}"
    read -p "Reconfigure existing installation? (y/N): " reconfig
    if [ "$reconfig" != "y" ]; then
        exit 0
    fi
else
    #---------------------------------------------------------------------------
    echo ""
    echo -e "${YELLOW}[*] Downloading Splunk Universal Forwarder...${NC}"
    echo ""
    echo "Download from: https://www.splunk.com/en_us/download/universal-forwarder.html"
    echo ""
    echo "Or use wget with your Splunk.com credentials:"
    echo "  wget -O splunkforwarder.tgz 'https://download.splunk.com/products/universalforwarder/releases/$FORWARDER_VERSION/linux/splunkforwarder-$FORWARDER_VERSION-linux-x86_64.tgz'"
    echo ""

    read -p "Path to downloaded forwarder package (or skip to download): " pkg_path

    if [ -z "$pkg_path" ] || [ ! -f "$pkg_path" ]; then
        echo ""
        echo -e "${YELLOW}Attempting to download...${NC}"

        # Try to download (may need credentials)
        cd /tmp
        if command -v wget &>/dev/null; then
            wget -O splunkforwarder.tgz "https://download.splunk.com/products/universalforwarder/releases/$FORWARDER_VERSION/linux/splunkforwarder-$FORWARDER_VERSION-linux-2.1-x86_64.tgz" 2>/dev/null || {
                echo -e "${RED}[!] Download failed. Please download manually.${NC}"
                exit 1
            }
        else
            curl -o splunkforwarder.tgz "https://download.splunk.com/products/universalforwarder/releases/$FORWARDER_VERSION/linux/splunkforwarder-$FORWARDER_VERSION-linux-2.1-x86_64.tgz" 2>/dev/null || {
                echo -e "${RED}[!] Download failed. Please download manually.${NC}"
                exit 1
            }
        fi
        pkg_path="/tmp/splunkforwarder.tgz"
    fi

    #---------------------------------------------------------------------------
    echo ""
    echo -e "${YELLOW}[*] Installing Splunk Universal Forwarder...${NC}"

    tar -xzf "$pkg_path" -C /opt/
    echo -e "${GREEN}    [+] Extracted to /opt/splunkforwarder${NC}"
fi

#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[*] Configuring Splunk Forwarder...${NC}"

# Create user-seed.conf for initial password
mkdir -p "$SPLUNK_HOME/etc/system/local"
cat > "$SPLUNK_HOME/etc/system/local/user-seed.conf" << EOF
[user_info]
USERNAME = admin
PASSWORD = $FORWARDER_ADMIN_PASS
EOF
chmod 600 "$SPLUNK_HOME/etc/system/local/user-seed.conf"
echo -e "${GREEN}    [+] Admin credentials configured${NC}"

# Configure outputs (forward to indexer)
cat > "$SPLUNK_HOME/etc/system/local/outputs.conf" << EOF
[tcpout]
defaultGroup = ccdc-indexers

[tcpout:ccdc-indexers]
server = $SPLUNK_INDEXER:$SPLUNK_PORT

[tcpout-server://$SPLUNK_INDEXER:$SPLUNK_PORT]
EOF
echo -e "${GREEN}    [+] Forwarding configured to $SPLUNK_INDEXER:$SPLUNK_PORT${NC}"

#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[*] Configuring data inputs...${NC}"

cat > "$SPLUNK_HOME/etc/system/local/inputs.conf" << 'EOF'
# CCDC Universal Forwarder Inputs

[default]
host =

# System logs
[monitor:///var/log/syslog]
disabled = false
index = main
sourcetype = syslog

[monitor:///var/log/messages]
disabled = false
index = main
sourcetype = syslog

[monitor:///var/log/auth.log]
disabled = false
index = main
sourcetype = linux_secure

[monitor:///var/log/secure]
disabled = false
index = main
sourcetype = linux_secure

# Audit logs
[monitor:///var/log/audit/audit.log]
disabled = false
index = main
sourcetype = linux_audit

# Apache logs
[monitor:///var/log/apache2/*access*.log]
disabled = false
index = main
sourcetype = access_combined

[monitor:///var/log/apache2/*error*.log]
disabled = false
index = main
sourcetype = apache_error

[monitor:///var/log/httpd/*access*.log]
disabled = false
index = main
sourcetype = access_combined

[monitor:///var/log/httpd/*error*.log]
disabled = false
index = main
sourcetype = apache_error

# Nginx logs
[monitor:///var/log/nginx/*access*.log]
disabled = false
index = main
sourcetype = access_combined

[monitor:///var/log/nginx/*error*.log]
disabled = false
index = main
sourcetype = nginx_error

# MySQL/MariaDB logs
[monitor:///var/log/mysql/*.log]
disabled = false
index = main
sourcetype = mysqld

[monitor:///var/log/mariadb/*.log]
disabled = false
index = main
sourcetype = mysqld

# Mail logs
[monitor:///var/log/mail.log]
disabled = false
index = main
sourcetype = postfix_syslog

[monitor:///var/log/maillog]
disabled = false
index = main
sourcetype = postfix_syslog
EOF

# Set hostname
HOSTNAME=$(hostname)
sed -i "s/^host = $/host = $HOSTNAME/" "$SPLUNK_HOME/etc/system/local/inputs.conf"
echo -e "${GREEN}    [+] Input monitoring configured for common log files${NC}"

#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[*] Setting permissions...${NC}"

# Create splunk user if doesn't exist
if ! id splunk &>/dev/null; then
    useradd -r -m -d "$SPLUNK_HOME" splunk
    echo -e "${GREEN}    [+] Created splunk user${NC}"
fi

chown -R splunk:splunk "$SPLUNK_HOME"
echo -e "${GREEN}    [+] Ownership set to splunk user${NC}"

#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[*] Starting Splunk Forwarder...${NC}"

# Accept license and start
"$SPLUNK_HOME/bin/splunk" start --accept-license --answer-yes --no-prompt

echo ""
echo -e "${YELLOW}[*] Enabling boot start...${NC}"
"$SPLUNK_HOME/bin/splunk" enable boot-start -user splunk

#-------------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}[*] Testing connection to indexer...${NC}"

if timeout 5 bash -c "echo > /dev/tcp/$SPLUNK_INDEXER/$SPLUNK_PORT" 2>/dev/null; then
    echo -e "${GREEN}    [+] Connection to $SPLUNK_INDEXER:$SPLUNK_PORT successful${NC}"
else
    echo -e "${RED}    [-] Cannot connect to $SPLUNK_INDEXER:$SPLUNK_PORT${NC}"
    echo "    Check firewall rules on both forwarder and indexer"
fi

#-------------------------------------------------------------------------------
echo ""
echo -e "${GREEN}========================================"
echo "  Splunk Forwarder Deployment Complete"
echo -e "========================================${NC}"
echo ""
echo "Forwarder Home: $SPLUNK_HOME"
echo "Forwarding to: $SPLUNK_INDEXER:$SPLUNK_PORT"
echo ""
echo -e "${YELLOW}COMMANDS:${NC}"
echo "  $SPLUNK_HOME/bin/splunk status"
echo "  $SPLUNK_HOME/bin/splunk restart"
echo "  $SPLUNK_HOME/bin/splunk list forward-server"
echo ""
echo -e "${CYAN}VERIFY ON INDEXER:${NC}"
echo "  Search: index=* host=$HOSTNAME | head 10"
echo ""
