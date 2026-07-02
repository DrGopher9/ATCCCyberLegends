#!/bin/bash
###############################################################################
# 07-prestashop-harden.sh - PrestaShop Web Application Hardening
# Target: Ubuntu 24 E-Commerce Server
# Purpose: Secure PrestaShop installation and web server
###############################################################################

set -euo pipefail

LOGFILE="/root/ccdc-logs/prestashop_harden_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$(dirname "$LOGFILE")"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOGFILE"
}

log "Starting PrestaShop hardening..."

# Find PrestaShop installation
echo ""
echo "============================================"
echo "LOCATING PRESTASHOP INSTALLATION"
echo "============================================"

PS_ROOT=""
PS_CONFIG=""

# Search for PrestaShop
for dir in /var/www/html /var/www/prestashop /var/www/*; do
    if [ -f "$dir/app/config/parameters.php" ] || [ -f "$dir/config/settings.inc.php" ]; then
        PS_ROOT="$dir"
        break
    fi
done

if [ -z "$PS_ROOT" ]; then
    log "PrestaShop installation not found in standard locations."
    read -p "Enter PrestaShop root directory: " PS_ROOT
fi

if [ ! -d "$PS_ROOT" ]; then
    log "ERROR: Directory $PS_ROOT does not exist"
    exit 1
fi

log "PrestaShop root: $PS_ROOT"

# Detect version (1.6 vs 1.7+)
if [ -f "$PS_ROOT/app/config/parameters.php" ]; then
    log "Detected PrestaShop 1.7+ (Symfony-based)"
    PS_VERSION="1.7"
    PS_CONFIG="$PS_ROOT/app/config/parameters.php"
elif [ -f "$PS_ROOT/config/settings.inc.php" ]; then
    log "Detected PrestaShop 1.6 or earlier"
    PS_VERSION="1.6"
    PS_CONFIG="$PS_ROOT/config/settings.inc.php"
else
    log "WARNING: Could not detect PrestaShop version"
    PS_VERSION="unknown"
fi

# Detect web server
if systemctl is-active --quiet apache2; then
    WEBSERVER="apache2"
elif systemctl is-active --quiet nginx; then
    WEBSERVER="nginx"
else
    WEBSERVER="unknown"
fi
log "Web server: $WEBSERVER"

echo ""
echo "============================================"
echo "PRESTASHOP SECURITY AUDIT"
echo "============================================"

# Check for common security issues
echo ""
echo "--- Checking for dangerous files ---"

# Install directory (should be removed after installation)
if [ -d "$PS_ROOT/install" ]; then
    echo "[CRITICAL] /install directory exists - should be removed!"
    log "CRITICAL: install directory found"
fi

# Check for phpinfo files
PHPINFO_FILES=$(find "$PS_ROOT" -name "phpinfo.php" -o -name "info.php" -o -name "test.php" 2>/dev/null || true)
if [ -n "$PHPINFO_FILES" ]; then
    echo "[WARNING] PHP info files found:"
    echo "$PHPINFO_FILES"
fi

# Check admin directory name
ADMIN_DIR=$(find "$PS_ROOT" -maxdepth 1 -type d -name "admin*" 2>/dev/null | head -1)
if [ -n "$ADMIN_DIR" ]; then
    ADMIN_NAME=$(basename "$ADMIN_DIR")
    echo "Admin directory: $ADMIN_NAME"
    if [ "$ADMIN_NAME" = "admin" ]; then
        echo "[WARNING] Admin directory is 'admin' - should be renamed!"
    fi
fi

# Check file permissions
echo ""
echo "--- File permissions check ---"
WORLD_WRITABLE=$(find "$PS_ROOT" -type f -perm -002 2>/dev/null | head -10)
if [ -n "$WORLD_WRITABLE" ]; then
    echo "[WARNING] World-writable files found:"
    echo "$WORLD_WRITABLE"
fi

echo ""
echo "============================================"
echo "PRESTASHOP HARDENING OPTIONS"
echo "============================================"

# 1. Remove install directory
if [ -d "$PS_ROOT/install" ]; then
    read -p "Remove install directory? (RECOMMENDED) (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        mv "$PS_ROOT/install" "$PS_ROOT/install.removed.$(date +%Y%m%d_%H%M%S)"
        log "Install directory removed (moved to .removed)"
    fi
fi

# 2. Rename admin directory
if [ -n "$ADMIN_DIR" ] && [ "$(basename "$ADMIN_DIR")" = "admin" ]; then
    NEW_ADMIN="admin$(openssl rand -hex 4)"
    read -p "Rename admin directory to '$NEW_ADMIN'? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        mv "$ADMIN_DIR" "$PS_ROOT/$NEW_ADMIN"
        log "Admin directory renamed to: $NEW_ADMIN"
        echo "NEW ADMIN URL: http://yoursite/$NEW_ADMIN"
    fi
fi

# 3. Remove dangerous files
if [ -n "$PHPINFO_FILES" ]; then
    read -p "Remove phpinfo/test files? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "$PHPINFO_FILES" | while read -r file; do
            rm -f "$file" 2>/dev/null && log "Removed: $file"
        done
    fi
fi

# 4. Fix file permissions
echo ""
read -p "Fix file permissions (644 files, 755 dirs)? (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log "Fixing permissions..."
    # Files
    find "$PS_ROOT" -type f -exec chmod 644 {} \; 2>/dev/null
    # Directories
    find "$PS_ROOT" -type d -exec chmod 755 {} \; 2>/dev/null
    # Cache/logs need to be writable
    if [ -d "$PS_ROOT/var/cache" ]; then
        chmod -R 775 "$PS_ROOT/var/cache" 2>/dev/null || true
        chmod -R 775 "$PS_ROOT/var/logs" 2>/dev/null || true
    fi
    if [ -d "$PS_ROOT/cache" ]; then
        chmod -R 775 "$PS_ROOT/cache" 2>/dev/null || true
    fi
    if [ -d "$PS_ROOT/img" ]; then
        chmod -R 775 "$PS_ROOT/img" 2>/dev/null || true
    fi
    if [ -d "$PS_ROOT/upload" ]; then
        chmod -R 775 "$PS_ROOT/upload" 2>/dev/null || true
    fi
    if [ -d "$PS_ROOT/download" ]; then
        chmod -R 775 "$PS_ROOT/download" 2>/dev/null || true
    fi
    log "Permissions fixed"
fi

# 5. Set proper ownership
echo ""
read -p "Set ownership to www-data? (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    chown -R www-data:www-data "$PS_ROOT" 2>/dev/null
    log "Ownership set to www-data"
fi

# 6. Disable debug mode
echo ""
echo "--- Checking debug mode ---"
if [ -f "$PS_ROOT/config/defines.inc.php" ]; then
    if grep -q "_PS_MODE_DEV_.*true" "$PS_ROOT/config/defines.inc.php"; then
        echo "[WARNING] Debug mode is ENABLED"
        read -p "Disable debug mode? (y/N): " -r REPLY
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sed -i "s/define('_PS_MODE_DEV_', true)/define('_PS_MODE_DEV_', false)/" "$PS_ROOT/config/defines.inc.php"
            log "Debug mode disabled"
        fi
    else
        echo "Debug mode is disabled (good)"
    fi
fi

# 7. Apache/Nginx hardening
echo ""
echo "============================================"
echo "WEB SERVER HARDENING"
echo "============================================"

if [ "$WEBSERVER" = "apache2" ]; then
    log "Configuring Apache security..."

    # Enable security modules
    a2enmod headers 2>/dev/null || true
    a2enmod rewrite 2>/dev/null || true

    # Check .htaccess
    if [ -f "$PS_ROOT/.htaccess" ]; then
        echo ".htaccess exists"
    else
        echo "[WARNING] No .htaccess file found"
    fi

    # Create security headers config
    read -p "Add security headers to Apache? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cat > /etc/apache2/conf-available/security-headers.conf << 'EOF'
# Security Headers for CCDC
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>

# Hide Apache version
ServerTokens Prod
ServerSignature Off
EOF
        a2enconf security-headers 2>/dev/null || true
        log "Security headers configured"
    fi

    # Disable directory listing
    read -p "Disable directory listing? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ -f "/etc/apache2/apache2.conf" ]; then
            sed -i 's/Options Indexes/Options -Indexes/g' /etc/apache2/apache2.conf 2>/dev/null || true
            log "Directory listing disabled"
        fi
    fi

    read -p "Restart Apache to apply changes? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        systemctl restart apache2
        log "Apache restarted"
    fi

elif [ "$WEBSERVER" = "nginx" ]; then
    log "Configuring Nginx security..."

    # Create security config snippet
    read -p "Add security headers to Nginx? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cat > /etc/nginx/snippets/security-headers.conf << 'EOF'
# Security Headers for CCDC
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Hide Nginx version
server_tokens off;
EOF
        log "Security headers config created at /etc/nginx/snippets/security-headers.conf"
        echo "Add to your server block: include snippets/security-headers.conf;"
    fi

    read -p "Restart Nginx to apply changes? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        nginx -t && systemctl restart nginx
        log "Nginx restarted"
    fi
fi

# 8. PHP hardening
echo ""
echo "============================================"
echo "PHP HARDENING"
echo "============================================"

PHP_INI=$(php -r "echo php_ini_loaded_file();" 2>/dev/null || echo "")
if [ -n "$PHP_INI" ] && [ -f "$PHP_INI" ]; then
    echo "PHP config: $PHP_INI"

    read -p "Apply PHP security settings? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cp "$PHP_INI" "$PHP_INI.bak.$(date +%Y%m%d_%H%M%S)"

        # Disable dangerous functions
        CURRENT_DISABLE=$(grep "^disable_functions" "$PHP_INI" || echo "")
        DANGEROUS_FUNCS="exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source"

        if [ -z "$CURRENT_DISABLE" ]; then
            echo "disable_functions = $DANGEROUS_FUNCS" >> "$PHP_INI"
        fi

        # Other security settings
        sed -i 's/^expose_php.*/expose_php = Off/' "$PHP_INI" 2>/dev/null || true
        sed -i 's/^display_errors.*/display_errors = Off/' "$PHP_INI" 2>/dev/null || true
        sed -i 's/^log_errors.*/log_errors = On/' "$PHP_INI" 2>/dev/null || true

        log "PHP security settings applied"
        echo "NOTE: Some functions may need to be re-enabled for PrestaShop to work"
        echo "If issues occur, edit: $PHP_INI"
    fi
fi

echo ""
echo "============================================"
echo "PRESTASHOP HARDENING COMPLETE"
echo "============================================"
echo ""
echo "Applied changes:"
echo "  - Install directory removed (if existed)"
echo "  - Admin directory renamed (if selected)"
echo "  - File permissions fixed (if selected)"
echo "  - Debug mode disabled (if selected)"
echo "  - Web server hardened (if selected)"
echo "  - PHP hardened (if selected)"
echo ""
echo "VERIFICATION:"
echo "  1. Test the storefront: http://yoursite/"
echo "  2. Test admin panel: http://yoursite/[admin-folder]/"
echo "  3. Test checkout flow"
echo "  4. Check error logs: tail -f /var/log/apache2/error.log"
echo ""
log "PrestaShop hardening complete"
