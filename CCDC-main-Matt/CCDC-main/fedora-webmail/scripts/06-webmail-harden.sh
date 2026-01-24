#!/bin/bash
#===============================================================================
# CCDC Fedora Webmail/Apps - Web Application Hardening Script
# Target: Fedora Server with Apache/Nginx, PHP, Roundcube
# Run as: root
#===============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

BACKUP_DIR="/opt/ccdc-backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p "$BACKUP_DIR"

echo -e "${CYAN}========================================"
echo "  CCDC Fedora Web Application Hardening"
echo -e "========================================${NC}"
echo ""

#===============================================================================
echo -e "${YELLOW}=== Apache Hardening ===${NC}"
echo ""

if [ -d /etc/httpd ]; then
    echo "[*] Apache (httpd) detected"

    # Backup
    cp -r /etc/httpd "$BACKUP_DIR/httpd_$TIMESTAMP"
    echo -e "${GREEN}    [+] Configuration backed up${NC}"

    # Main config hardening
    HTTPD_CONF="/etc/httpd/conf/httpd.conf"

    read -p "Apply Apache hardening? (y/N): " harden_apache
    if [ "$harden_apache" = "y" ]; then
        # Disable server signature
        if grep -q "ServerSignature" "$HTTPD_CONF"; then
            sed -i 's/ServerSignature.*/ServerSignature Off/' "$HTTPD_CONF"
        else
            echo "ServerSignature Off" >> "$HTTPD_CONF"
        fi
        echo -e "${GREEN}    [+] Server signature disabled${NC}"

        # Disable server tokens
        if grep -q "ServerTokens" "$HTTPD_CONF"; then
            sed -i 's/ServerTokens.*/ServerTokens Prod/' "$HTTPD_CONF"
        else
            echo "ServerTokens Prod" >> "$HTTPD_CONF"
        fi
        echo -e "${GREEN}    [+] Server tokens minimized${NC}"

        # Disable directory listing
        sed -i 's/Options Indexes/Options -Indexes/g' "$HTTPD_CONF"
        echo -e "${GREEN}    [+] Directory listing disabled${NC}"

        # Disable TRACE method
        if ! grep -q "TraceEnable" "$HTTPD_CONF"; then
            echo "TraceEnable Off" >> "$HTTPD_CONF"
        fi
        echo -e "${GREEN}    [+] TRACE method disabled${NC}"

        # Security headers
        cat > /etc/httpd/conf.d/security.conf << 'EOF'
# CCDC Security Headers
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>

# Disable ETag (information disclosure)
FileETag None

# Timeout settings
Timeout 60
KeepAliveTimeout 5
EOF
        echo -e "${GREEN}    [+] Security headers configured${NC}"
    fi
fi

#===============================================================================
echo ""
echo -e "${YELLOW}=== PHP Hardening ===${NC}"
echo ""

PHP_INI=""
for path in /etc/php.ini /etc/php/*/apache2/php.ini /etc/php/*/fpm/php.ini; do
    if [ -f "$path" ]; then
        PHP_INI="$path"
        break
    fi
done

if [ -n "$PHP_INI" ]; then
    echo "PHP config found: $PHP_INI"

    # Backup
    cp "$PHP_INI" "$BACKUP_DIR/php.ini.$TIMESTAMP"

    read -p "Apply PHP hardening? (y/N): " harden_php
    if [ "$harden_php" = "y" ]; then
        # Disable dangerous functions
        DISABLE_FUNCS="exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source"

        if grep -q "^disable_functions" "$PHP_INI"; then
            sed -i "s/^disable_functions.*/disable_functions = $DISABLE_FUNCS/" "$PHP_INI"
        else
            echo "disable_functions = $DISABLE_FUNCS" >> "$PHP_INI"
        fi
        echo -e "${GREEN}    [+] Dangerous functions disabled${NC}"

        # Hide PHP version
        sed -i 's/expose_php.*/expose_php = Off/' "$PHP_INI"
        echo -e "${GREEN}    [+] PHP version hidden${NC}"

        # Disable remote file inclusion
        sed -i 's/allow_url_fopen.*/allow_url_fopen = Off/' "$PHP_INI"
        sed -i 's/allow_url_include.*/allow_url_include = Off/' "$PHP_INI"
        echo -e "${GREEN}    [+] Remote file inclusion disabled${NC}"

        # Error handling (don't display in production)
        sed -i 's/display_errors.*/display_errors = Off/' "$PHP_INI"
        sed -i 's/display_startup_errors.*/display_startup_errors = Off/' "$PHP_INI"
        sed -i 's/log_errors.*/log_errors = On/' "$PHP_INI"
        echo -e "${GREEN}    [+] Error display disabled (logging enabled)${NC}"

        # Session security
        sed -i 's/session.cookie_httponly.*/session.cookie_httponly = 1/' "$PHP_INI"
        sed -i 's/session.cookie_secure.*/session.cookie_secure = 1/' "$PHP_INI"
        sed -i 's/session.use_strict_mode.*/session.use_strict_mode = 1/' "$PHP_INI"
        echo -e "${GREEN}    [+] Session security hardened${NC}"

        # File upload limits
        sed -i 's/upload_max_filesize.*/upload_max_filesize = 10M/' "$PHP_INI"
        sed -i 's/post_max_size.*/post_max_size = 10M/' "$PHP_INI"
        echo -e "${GREEN}    [+] Upload limits set${NC}"
    fi
else
    echo "PHP configuration not found"
fi

#===============================================================================
echo ""
echo -e "${YELLOW}=== Roundcube Hardening ===${NC}"
echo ""

# Find Roundcube
ROUNDCUBE_PATH=""
for path in /var/www/html/roundcube /var/www/roundcube /usr/share/roundcubemail /var/www/html/roundcubemail; do
    if [ -d "$path" ]; then
        ROUNDCUBE_PATH="$path"
        break
    fi
done

if [ -n "$ROUNDCUBE_PATH" ]; then
    echo "Roundcube found: $ROUNDCUBE_PATH"

    # Backup config
    cp "$ROUNDCUBE_PATH/config/config.inc.php" "$BACKUP_DIR/roundcube_config.$TIMESTAMP" 2>/dev/null

    read -p "Apply Roundcube hardening? (y/N): " harden_rc
    if [ "$harden_rc" = "y" ]; then
        RC_CONFIG="$ROUNDCUBE_PATH/config/config.inc.php"

        # Remove installer directory
        if [ -d "$ROUNDCUBE_PATH/installer" ]; then
            rm -rf "$ROUNDCUBE_PATH/installer"
            echo -e "${GREEN}    [+] Installer directory removed${NC}"
        fi

        # Set proper permissions
        chown -R apache:apache "$ROUNDCUBE_PATH"
        find "$ROUNDCUBE_PATH" -type d -exec chmod 755 {} \;
        find "$ROUNDCUBE_PATH" -type f -exec chmod 644 {} \;
        chmod 640 "$RC_CONFIG" 2>/dev/null
        echo -e "${GREEN}    [+] File permissions secured${NC}"

        # Secure temp and logs directories
        chmod 700 "$ROUNDCUBE_PATH/temp" 2>/dev/null
        chmod 700 "$ROUNDCUBE_PATH/logs" 2>/dev/null
        echo -e "${GREEN}    [+] Temp/logs directories secured${NC}"

        # Disable installer check in config
        if grep -q "enable_installer" "$RC_CONFIG" 2>/dev/null; then
            sed -i "s/\$config\['enable_installer'\].*/\$config['enable_installer'] = false;/" "$RC_CONFIG"
        fi
        echo -e "${GREEN}    [+] Installer disabled in config${NC}"

        # Block access to sensitive files via Apache
        cat > /etc/httpd/conf.d/roundcube-security.conf << EOF
# Roundcube Security
<Directory "$ROUNDCUBE_PATH">
    <FilesMatch "\.(inc|log|sql|dist|sh)$">
        Require all denied
    </FilesMatch>
</Directory>

<Directory "$ROUNDCUBE_PATH/config">
    Require all denied
</Directory>

<Directory "$ROUNDCUBE_PATH/temp">
    Require all denied
</Directory>

<Directory "$ROUNDCUBE_PATH/logs">
    Require all denied
</Directory>
EOF
        echo -e "${GREEN}    [+] Apache access restrictions configured${NC}"
    fi
else
    echo "Roundcube not found"
fi

#===============================================================================
echo ""
echo -e "${YELLOW}=== SELinux Configuration ===${NC}"
echo ""

if command -v getenforce &>/dev/null; then
    SELINUX_STATUS=$(getenforce)
    echo "SELinux status: $SELINUX_STATUS"

    if [ "$SELINUX_STATUS" = "Enforcing" ]; then
        echo -e "${GREEN}    [+] SELinux is enforcing${NC}"

        # Set appropriate booleans for webmail
        read -p "Configure SELinux for webmail? (y/N): " config_selinux
        if [ "$config_selinux" = "y" ]; then
            # Allow httpd to connect to network (for IMAP/SMTP)
            setsebool -P httpd_can_network_connect 1
            echo -e "${GREEN}    [+] httpd_can_network_connect enabled${NC}"

            # Allow httpd to send mail
            setsebool -P httpd_can_sendmail 1
            echo -e "${GREEN}    [+] httpd_can_sendmail enabled${NC}"

            # Restore contexts
            restorecon -Rv /var/www/html 2>/dev/null
            echo -e "${GREEN}    [+] SELinux contexts restored${NC}"
        fi
    elif [ "$SELINUX_STATUS" = "Permissive" ]; then
        echo -e "${YELLOW}    [!] SELinux is permissive - consider enabling${NC}"
    else
        echo -e "${RED}    [!] SELinux is disabled${NC}"
    fi
fi

#===============================================================================
echo ""
echo -e "${YELLOW}=== SSL/TLS Configuration ===${NC}"
echo ""

if [ -f /etc/httpd/conf.d/ssl.conf ]; then
    read -p "Harden SSL/TLS configuration? (y/N): " harden_ssl
    if [ "$harden_ssl" = "y" ]; then
        cp /etc/httpd/conf.d/ssl.conf "$BACKUP_DIR/ssl.conf.$TIMESTAMP"

        # Modern SSL settings
        cat > /etc/httpd/conf.d/ssl-hardening.conf << 'EOF'
# SSL Hardening
SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder on
SSLCompression off
SSLSessionTickets off

# HSTS (uncomment if HTTPS-only)
# Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
EOF
        echo -e "${GREEN}    [+] SSL/TLS hardened${NC}"
    fi
fi

#===============================================================================
echo ""
echo -e "${YELLOW}[*] Restarting web services...${NC}"

read -p "Restart Apache/Nginx now? (y/N): " restart_web
if [ "$restart_web" = "y" ]; then
    # Test config first
    if httpd -t 2>/dev/null; then
        systemctl restart httpd
        echo -e "${GREEN}    [+] Apache restarted${NC}"
    else
        echo -e "${RED}    [-] Apache config test failed - not restarting${NC}"
    fi

    # Restart PHP-FPM if used
    systemctl restart php-fpm 2>/dev/null && echo -e "${GREEN}    [+] PHP-FPM restarted${NC}"
fi

echo ""
echo -e "${GREEN}========================================"
echo "  Web Application Hardening Complete"
echo -e "========================================${NC}"
echo ""
echo "Backups saved to: $BACKUP_DIR/"
echo ""
echo -e "${YELLOW}VERIFY:${NC}"
echo "  - Web application loads correctly"
echo "  - Login functionality works"
echo "  - Email sending/receiving works"
echo ""
