#!/bin/bash
#===============================================================================
# CCDC Splunk SIEM - Splunk Application Hardening Script
# Target: Splunk Enterprise on Linux
# Run as: root or splunk user
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
echo "  CCDC Splunk Application Hardening"
echo -e "========================================${NC}"
echo ""

# Detect Splunk installation
SPLUNK_HOME=""
for path in /opt/splunk /opt/splunkforwarder /usr/local/splunk; do
    if [ -d "$path" ]; then
        SPLUNK_HOME="$path"
        break
    fi
done

if [ -z "$SPLUNK_HOME" ]; then
    echo -e "${RED}[!] Splunk installation not found${NC}"
    read -p "Enter Splunk installation path: " SPLUNK_HOME
fi

SPLUNK_CMD="$SPLUNK_HOME/bin/splunk"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "Splunk Home: $SPLUNK_HOME"
echo ""

#-------------------------------------------------------------------------------
# Backup configs before changes
echo -e "${YELLOW}[*] Backing up configuration files...${NC}"
tar -czf "$BACKUP_DIR/splunk_etc_preharden_$TIMESTAMP.tar.gz" -C "$SPLUNK_HOME" etc 2>/dev/null
echo -e "${GREEN}    [+] Backup: $BACKUP_DIR/splunk_etc_preharden_$TIMESTAMP.tar.gz${NC}"
echo ""

#===============================================================================
# SSL/TLS CONFIGURATION
#===============================================================================

echo -e "${YELLOW}=== SSL/TLS Configuration ===${NC}"
echo ""

echo "Current SSL settings:"
grep -i "ssl\|enableSplunkWebSSL" "$SPLUNK_HOME/etc/system/local/web.conf" 2>/dev/null || echo "  No local web.conf SSL settings"
echo ""

read -p "Enable HTTPS for Splunk Web? (y/N): " enable_https
if [ "$enable_https" = "y" ]; then
    mkdir -p "$SPLUNK_HOME/etc/system/local"

    # Enable HTTPS in web.conf
    cat >> "$SPLUNK_HOME/etc/system/local/web.conf" << 'EOF'

[settings]
enableSplunkWebSSL = true
httpport = 8000
EOF

    echo -e "${GREEN}    [+] HTTPS enabled for Splunk Web${NC}"
fi

#-------------------------------------------------------------------------------
read -p "Enable SSL for Splunk-to-Splunk communication? (y/N): " enable_s2s_ssl
if [ "$enable_s2s_ssl" = "y" ]; then
    # Configure SSL for receiving
    cat >> "$SPLUNK_HOME/etc/system/local/inputs.conf" << 'EOF'

[splunktcp-ssl:9997]
disabled = false

[SSL]
serverCert = $SPLUNK_HOME/etc/auth/server.pem
sslPassword = password
requireClientCert = false
EOF

    # Configure SSL for sending (if this is also a forwarder)
    cat >> "$SPLUNK_HOME/etc/system/local/outputs.conf" << 'EOF'

[tcpout]
defaultGroup = default-autolb-group
useSSL = true

[tcpout:default-autolb-group]
sslVerifyServerCert = false
EOF

    echo -e "${GREEN}    [+] SSL configured for Splunk-to-Splunk communication${NC}"
    echo -e "${YELLOW}    [!] Update sslPassword and certificate paths as needed${NC}"
fi

#===============================================================================
# WEB INTERFACE HARDENING
#===============================================================================

echo ""
echo -e "${YELLOW}=== Web Interface Hardening ===${NC}"
echo ""

# Disable Splunk Web if not needed
read -p "Is Splunk Web required? (y/N): " need_web
if [ "$need_web" != "y" ]; then
    cat >> "$SPLUNK_HOME/etc/system/local/web.conf" << 'EOF'

[settings]
startwebserver = false
EOF

    echo -e "${GREEN}    [+] Splunk Web disabled (use CLI or REST API)${NC}"
else
    # Configure session timeout
    read -p "Set session timeout (minutes, default 60): " session_timeout
    session_timeout=${session_timeout:-60}

    cat >> "$SPLUNK_HOME/etc/system/local/web.conf" << EOF

[settings]
tools.sessions.timeout = $session_timeout
EOF

    echo -e "${GREEN}    [+] Session timeout: $session_timeout minutes${NC}"

    # Enable secure cookies
    cat >> "$SPLUNK_HOME/etc/system/local/web.conf" << 'EOF'
httponly = true
secure = true
EOF

    echo -e "${GREEN}    [+] Secure cookie flags enabled${NC}"
fi

#===============================================================================
# AUTHENTICATION HARDENING
#===============================================================================

echo ""
echo -e "${YELLOW}=== Authentication Hardening ===${NC}"
echo ""

# Password complexity
read -p "Configure password complexity requirements? (y/N): " config_passwd
if [ "$config_passwd" = "y" ]; then
    mkdir -p "$SPLUNK_HOME/etc/system/local"

    cat >> "$SPLUNK_HOME/etc/system/local/authentication.conf" << 'EOF'

[splunk_auth]
minPasswordLength = 12
minPasswordUppercase = 1
minPasswordLowercase = 1
minPasswordDigit = 1
minPasswordSpecial = 1
EOF

    echo -e "${GREEN}    [+] Password complexity configured${NC}"
    echo "        - Minimum 12 characters"
    echo "        - 1 uppercase, 1 lowercase, 1 digit, 1 special"
fi

# Account lockout
read -p "Configure account lockout? (y/N): " config_lockout
if [ "$config_lockout" = "y" ]; then
    cat >> "$SPLUNK_HOME/etc/system/local/authentication.conf" << 'EOF'

[splunk_auth]
lockoutAttempts = 5
lockoutMins = 30
lockoutThresholdMins = 5
EOF

    echo -e "${GREEN}    [+] Account lockout configured${NC}"
    echo "        - Lockout after 5 failed attempts"
    echo "        - Lockout duration: 30 minutes"
fi

#===============================================================================
# DISABLE UNNECESSARY FEATURES
#===============================================================================

echo ""
echo -e "${YELLOW}=== Disable Unnecessary Features ===${NC}"
echo ""

# Disable sample data inputs
read -p "Disable sample data apps? (y/N): " disable_samples
if [ "$disable_samples" = "y" ]; then
    for sample_app in sample_app introspection_generator_addon; do
        if [ -d "$SPLUNK_HOME/etc/apps/$sample_app" ]; then
            mkdir -p "$SPLUNK_HOME/etc/apps/$sample_app/local"
            echo -e "[install]\nstate = disabled" > "$SPLUNK_HOME/etc/apps/$sample_app/local/app.conf"
            echo -e "${GREEN}    [+] Disabled: $sample_app${NC}"
        fi
    done
fi

# Disable telemetry
read -p "Disable Splunk telemetry? (y/N): " disable_telemetry
if [ "$disable_telemetry" = "y" ]; then
    mkdir -p "$SPLUNK_HOME/etc/apps/splunk_instrumentation/local"
    cat > "$SPLUNK_HOME/etc/apps/splunk_instrumentation/local/telemetry.conf" << 'EOF'
[general]
sendLicenseUsage = false
sendAnonymizedUsage = false
sendSupportUsage = false
EOF

    echo -e "${GREEN}    [+] Telemetry disabled${NC}"
fi

#===============================================================================
# LIMIT REST API ACCESS
#===============================================================================

echo ""
echo -e "${YELLOW}=== REST API Hardening ===${NC}"
echo ""

read -p "Restrict REST API access to specific IPs? (y/N): " restrict_api
if [ "$restrict_api" = "y" ]; then
    read -p "Enter allowed IP/network (e.g., 172.20.0.0/16): " allowed_net

    cat >> "$SPLUNK_HOME/etc/system/local/server.conf" << EOF

[httpServer]
acceptFrom = 127.0.0.1, $allowed_net
EOF

    echo -e "${GREEN}    [+] REST API restricted to: 127.0.0.1, $allowed_net${NC}"
fi

#===============================================================================
# DISABLE REMOTE LOGIN
#===============================================================================

echo ""
echo -e "${YELLOW}=== Remote Login Settings ===${NC}"
echo ""

read -p "Disable Splunk remote login (use SSH only)? (y/N): " disable_remote
if [ "$disable_remote" = "y" ]; then
    cat >> "$SPLUNK_HOME/etc/system/local/server.conf" << 'EOF'

[general]
allowRemoteLogin = never
EOF

    echo -e "${GREEN}    [+] Remote login disabled (use SSH + CLI)${NC}"
fi

#===============================================================================
# INDEX CONFIGURATION
#===============================================================================

echo ""
echo -e "${YELLOW}=== Index Configuration ===${NC}"
echo ""

read -p "Configure index retention settings? (y/N): " config_index
if [ "$config_index" = "y" ]; then
    # Check current index settings
    echo "Current indexes:"
    $SPLUNK_CMD list index 2>/dev/null | head -20

    read -p "Set default frozen time (days, default 90): " frozen_days
    frozen_days=${frozen_days:-90}
    frozen_secs=$((frozen_days * 86400))

    cat >> "$SPLUNK_HOME/etc/system/local/indexes.conf" << EOF

[default]
frozenTimePeriodInSecs = $frozen_secs
maxTotalDataSizeMB = 500000
EOF

    echo -e "${GREEN}    [+] Default retention: $frozen_days days${NC}"
fi

#===============================================================================
# SECURE FILE PERMISSIONS
#===============================================================================

echo ""
echo -e "${YELLOW}=== File Permission Hardening ===${NC}"
echo ""

# Detect Splunk user
SPLUNK_USER=$(stat -c '%U' "$SPLUNK_HOME/bin/splunk" 2>/dev/null)
if [ -z "$SPLUNK_USER" ] || [ "$SPLUNK_USER" = "root" ]; then
    SPLUNK_USER="splunk"
fi

read -p "Secure Splunk file permissions? (y/N): " secure_perms
if [ "$secure_perms" = "y" ]; then
    # Configuration files - restrict access
    chmod 700 "$SPLUNK_HOME/etc"
    chmod 600 "$SPLUNK_HOME/etc/passwd" 2>/dev/null
    chmod 600 "$SPLUNK_HOME/etc/auth/splunk.secret" 2>/dev/null

    # Ensure proper ownership
    if id "$SPLUNK_USER" &>/dev/null; then
        chown -R "$SPLUNK_USER":"$SPLUNK_USER" "$SPLUNK_HOME/etc" 2>/dev/null
        chown -R "$SPLUNK_USER":"$SPLUNK_USER" "$SPLUNK_HOME/var" 2>/dev/null
        echo -e "${GREEN}    [+] Ownership set to: $SPLUNK_USER${NC}"
    fi

    echo -e "${GREEN}    [+] File permissions secured${NC}"
fi

#===============================================================================
# DISABLE DEFAULT/SAMPLE USERS
#===============================================================================

echo ""
echo -e "${YELLOW}=== Audit Default Configurations ===${NC}"
echo ""

# Check for sample/test users
echo "Checking for sample users in passwd..."
if grep -qE "^(test|sample|demo|guest):" "$SPLUNK_HOME/etc/passwd" 2>/dev/null; then
    echo -e "${RED}[!] Sample users found in passwd file${NC}"
    grep -E "^(test|sample|demo|guest):" "$SPLUNK_HOME/etc/passwd"

    read -p "Remove these users? (y/N): " remove_sample
    if [ "$remove_sample" = "y" ]; then
        sed -i '/^test:/d; /^sample:/d; /^demo:/d; /^guest:/d' "$SPLUNK_HOME/etc/passwd"
        echo -e "${GREEN}    [+] Sample users removed${NC}"
    fi
else
    echo -e "${GREEN}    [+] No sample users found${NC}"
fi

#===============================================================================
# CONFIGURE LIMITS
#===============================================================================

echo ""
echo -e "${YELLOW}=== Configure Limits ===${NC}"
echo ""

read -p "Configure search limits? (y/N): " config_limits
if [ "$config_limits" = "y" ]; then
    cat >> "$SPLUNK_HOME/etc/system/local/limits.conf" << 'EOF'

[search]
max_searches_per_cpu = 4
max_rt_search_multiplier = 1
max_mem_usage_mb = 4096

[scheduler]
max_searches_perc = 50
EOF

    echo -e "${GREEN}    [+] Search limits configured${NC}"
fi

#===============================================================================
# RESTART SPLUNK
#===============================================================================

echo ""
echo -e "${YELLOW}[*] Configuration changes require Splunk restart${NC}"
echo ""

read -p "Restart Splunk now? (y/N): " restart_splunk
if [ "$restart_splunk" = "y" ]; then
    echo "[*] Restarting Splunk..."
    $SPLUNK_CMD restart 2>/dev/null

    echo ""
    echo "Checking Splunk status..."
    sleep 10
    $SPLUNK_CMD status
fi

#===============================================================================
echo ""
echo -e "${GREEN}========================================"
echo "  Splunk Hardening Complete"
echo -e "========================================${NC}"
echo ""
echo "Configuration backup: $BACKUP_DIR/splunk_etc_preharden_$TIMESTAMP.tar.gz"
echo ""
echo -e "${YELLOW}Applied Hardening:${NC}"
echo "  - SSL/TLS configuration"
echo "  - Web interface security"
echo "  - Authentication hardening"
echo "  - Disabled unnecessary features"
echo "  - File permissions secured"
echo ""
echo -e "${CYAN}VERIFICATION:${NC}"
echo "  $SPLUNK_CMD btool server list --debug"
echo "  $SPLUNK_CMD btool web list --debug"
echo "  $SPLUNK_CMD btool authentication list --debug"
echo ""
