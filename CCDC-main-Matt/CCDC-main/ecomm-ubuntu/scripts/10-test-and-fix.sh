#!/bin/bash
#===============================================================================
# CCDC E-Commerce Server - Test & Fix Script
# Target: Ubuntu 24 with PrestaShop + MySQL
#
# Run this to diagnose issues and apply fixes
#===============================================================================

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

LOGFILE="/var/log/ccdc-ecomm-test-$(date +%Y%m%d-%H%M%S).log"

# Detect web root and PrestaShop location
WEB_ROOT="/var/www/html"
PRESTASHOP_ROOT=""

# Try to find PrestaShop
for dir in /var/www/html /var/www/html/prestashop /var/www/prestashop /var/www/shop; do
    if [ -f "$dir/config/settings.inc.php" ] || [ -f "$dir/app/config/parameters.php" ]; then
        PRESTASHOP_ROOT="$dir"
        break
    fi
done

log() {
    echo -e "$1" | tee -a "$LOGFILE"
}

pass() {
    log "  ${GREEN}[PASS]${NC} $1"
}

fail() {
    log "  ${RED}[FAIL]${NC} $1"
}

warn() {
    log "  ${YELLOW}[WARN]${NC} $1"
}

info() {
    log "  ${CYAN}[INFO]${NC} $1"
}

header() {
    log ""
    log "${CYAN}========================================"
    log "  $1"
    log "========================================${NC}"
    log ""
}

#===============================================================================
header "E-COMMERCE SERVER DIAGNOSTIC TEST"
#===============================================================================

log "Time: $(date)"
log "Host: $(hostname)"
log "Log: $LOGFILE"
log ""

if [ -n "$PRESTASHOP_ROOT" ]; then
    log "PrestaShop detected at: $PRESTASHOP_ROOT"
else
    warn "PrestaShop location not auto-detected"
    read -p "Enter PrestaShop path [/var/www/html]: " PRESTASHOP_ROOT
    PRESTASHOP_ROOT=${PRESTASHOP_ROOT:-/var/www/html}
fi
log ""

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_WARNED=0

#===============================================================================
header "TEST 1: Service Status"
#===============================================================================

# Apache
log "Checking Apache/Nginx..."
if systemctl is-active --quiet apache2; then
    pass "Apache2 is running"
    WEB_SERVER="apache2"
    ((TESTS_PASSED++))
elif systemctl is-active --quiet httpd; then
    pass "HTTPD is running"
    WEB_SERVER="httpd"
    ((TESTS_PASSED++))
elif systemctl is-active --quiet nginx; then
    pass "Nginx is running"
    WEB_SERVER="nginx"
    ((TESTS_PASSED++))
else
    fail "No web server running!"
    ((TESTS_FAILED++))
    WEB_SERVER=""
fi

# MySQL/MariaDB
log "Checking MySQL/MariaDB..."
if systemctl is-active --quiet mysql; then
    pass "MySQL is running"
    DB_SERVICE="mysql"
    ((TESTS_PASSED++))
elif systemctl is-active --quiet mariadb; then
    pass "MariaDB is running"
    DB_SERVICE="mariadb"
    ((TESTS_PASSED++))
else
    fail "No database server running!"
    ((TESTS_FAILED++))
    DB_SERVICE=""
fi

# PHP-FPM (if used)
log "Checking PHP-FPM..."
if systemctl is-active --quiet php*-fpm 2>/dev/null; then
    PHP_FPM=$(systemctl list-units --type=service --state=running | grep php | grep fpm | awk '{print $1}' | head -1)
    pass "PHP-FPM is running ($PHP_FPM)"
    ((TESTS_PASSED++))
elif systemctl is-active --quiet php-fpm; then
    pass "PHP-FPM is running"
    ((TESTS_PASSED++))
else
    info "PHP-FPM not running (may be using mod_php)"
fi

#===============================================================================
header "TEST 2: Port Listeners"
#===============================================================================

log "Checking listening ports..."

check_port() {
    local port=$1
    local name=$2
    if ss -tlnp | grep -q ":$port "; then
        pass "Port $port ($name) is listening"
        ((TESTS_PASSED++))
        return 0
    else
        fail "Port $port ($name) is NOT listening"
        ((TESTS_FAILED++))
        return 1
    fi
}

check_port 80 "HTTP"
check_port 443 "HTTPS"
check_port 3306 "MySQL"

#===============================================================================
header "TEST 3: HTTP/HTTPS Response"
#===============================================================================

log "Testing HTTP response..."

# Test HTTP
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 http://localhost/ 2>/dev/null)
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; then
    pass "HTTP returns $HTTP_CODE"
    ((TESTS_PASSED++))
else
    fail "HTTP returns $HTTP_CODE (expected 200/301/302)"
    ((TESTS_FAILED++))
fi

# Test HTTPS
HTTPS_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 https://localhost/ 2>/dev/null)
if [ "$HTTPS_CODE" = "200" ] || [ "$HTTPS_CODE" = "301" ] || [ "$HTTPS_CODE" = "302" ]; then
    pass "HTTPS returns $HTTPS_CODE"
    ((TESTS_PASSED++))
else
    warn "HTTPS returns $HTTPS_CODE (may need SSL setup)"
    ((TESTS_WARNED++))
fi

#===============================================================================
header "TEST 4: PHP Configuration"
#===============================================================================

log "Testing PHP..."

# Check PHP CLI
if command -v php &>/dev/null; then
    PHP_VERSION=$(php -v | head -1)
    pass "PHP CLI available: $PHP_VERSION"
    ((TESTS_PASSED++))
else
    fail "PHP CLI not found"
    ((TESTS_FAILED++))
fi

# Test PHP in web server
echo "<?php echo 'PHP_TEST_OK'; ?>" > /tmp/phptest.php
cp /tmp/phptest.php "$PRESTASHOP_ROOT/phptest.php" 2>/dev/null

PHP_WEB=$(curl -s --max-time 5 http://localhost/phptest.php 2>/dev/null)
if [ "$PHP_WEB" = "PHP_TEST_OK" ]; then
    pass "PHP is working in web server"
    ((TESTS_PASSED++))
else
    fail "PHP not processing in web server"
    ((TESTS_FAILED++))
fi
rm -f "$PRESTASHOP_ROOT/phptest.php" /tmp/phptest.php 2>/dev/null

# Check required PHP extensions
log "Checking PHP extensions..."
REQUIRED_EXTENSIONS="pdo pdo_mysql mysqli gd curl json mbstring xml zip intl"

for ext in $REQUIRED_EXTENSIONS; do
    if php -m 2>/dev/null | grep -qi "^$ext$"; then
        pass "PHP extension: $ext"
    else
        warn "PHP extension missing: $ext"
        ((TESTS_WARNED++))
    fi
done

#===============================================================================
header "TEST 5: MySQL Connectivity"
#===============================================================================

log "Testing MySQL connectivity..."

# Try to extract credentials from PrestaShop config
DB_HOST="localhost"
DB_NAME=""
DB_USER=""
DB_PASS=""

# PrestaShop 1.7+ config
if [ -f "$PRESTASHOP_ROOT/app/config/parameters.php" ]; then
    info "Found PrestaShop 1.7+ config"
    DB_HOST=$(grep -oP "database_host.*?'\K[^']*" "$PRESTASHOP_ROOT/app/config/parameters.php" 2>/dev/null | head -1)
    DB_NAME=$(grep -oP "database_name.*?'\K[^']*" "$PRESTASHOP_ROOT/app/config/parameters.php" 2>/dev/null | head -1)
    DB_USER=$(grep -oP "database_user.*?'\K[^']*" "$PRESTASHOP_ROOT/app/config/parameters.php" 2>/dev/null | head -1)
    DB_PASS=$(grep -oP "database_password.*?'\K[^']*" "$PRESTASHOP_ROOT/app/config/parameters.php" 2>/dev/null | head -1)
fi

# PrestaShop 1.6 config
if [ -f "$PRESTASHOP_ROOT/config/settings.inc.php" ]; then
    info "Found PrestaShop 1.6 config"
    DB_HOST=$(grep "_DB_SERVER_" "$PRESTASHOP_ROOT/config/settings.inc.php" | grep -oP "'[^']*'" | tail -1 | tr -d "'")
    DB_NAME=$(grep "_DB_NAME_" "$PRESTASHOP_ROOT/config/settings.inc.php" | grep -oP "'[^']*'" | tail -1 | tr -d "'")
    DB_USER=$(grep "_DB_USER_" "$PRESTASHOP_ROOT/config/settings.inc.php" | grep -oP "'[^']*'" | tail -1 | tr -d "'")
    DB_PASS=$(grep "_DB_PASSWD_" "$PRESTASHOP_ROOT/config/settings.inc.php" | grep -oP "'[^']*'" | tail -1 | tr -d "'")
fi

if [ -n "$DB_NAME" ] && [ -n "$DB_USER" ]; then
    log "  Database: $DB_NAME"
    log "  User: $DB_USER"
    log "  Host: $DB_HOST"

    # Test connection
    if mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" -e "USE $DB_NAME; SELECT 1;" &>/dev/null; then
        pass "MySQL connection successful"
        ((TESTS_PASSED++))

        # Count tables
        TABLE_COUNT=$(mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" -N -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='$DB_NAME';" 2>/dev/null)
        info "Database has $TABLE_COUNT tables"
    else
        fail "MySQL connection FAILED"
        ((TESTS_FAILED++))
    fi
else
    warn "Could not extract database credentials from config"
    ((TESTS_WARNED++))

    read -p "  Enter MySQL username [prestashop]: " DB_USER
    DB_USER=${DB_USER:-prestashop}
    read -sp "  Enter MySQL password: " DB_PASS
    echo ""
    read -p "  Enter database name [prestashop]: " DB_NAME
    DB_NAME=${DB_NAME:-prestashop}

    if mysql -u "$DB_USER" -p"$DB_PASS" -e "USE $DB_NAME; SELECT 1;" &>/dev/null; then
        pass "MySQL connection successful"
        ((TESTS_PASSED++))
    else
        fail "MySQL connection FAILED"
        ((TESTS_FAILED++))
    fi
fi

#===============================================================================
header "TEST 6: PrestaShop Status"
#===============================================================================

log "Testing PrestaShop..."

# Check if store is accessible
STORE_RESPONSE=$(curl -s --max-time 15 http://localhost/ 2>/dev/null)

if echo "$STORE_RESPONSE" | grep -qi "prestashop\|cart\|product\|shop"; then
    pass "PrestaShop appears to be responding"
    ((TESTS_PASSED++))
elif echo "$STORE_RESPONSE" | grep -qi "error\|exception\|fatal"; then
    fail "PrestaShop showing errors"
    ((TESTS_FAILED++))
    log "  Error preview:"
    echo "$STORE_RESPONSE" | grep -i "error\|exception" | head -3 | sed 's/^/    /'
else
    warn "Could not determine PrestaShop status"
    ((TESTS_WARNED++))
fi

# Check cache/logs directories
log "Checking PrestaShop directories..."

WRITABLE_DIRS="var/cache var/logs img upload download"
for dir in $WRITABLE_DIRS; do
    if [ -d "$PRESTASHOP_ROOT/$dir" ]; then
        if [ -w "$PRESTASHOP_ROOT/$dir" ]; then
            pass "Directory writable: $dir"
        else
            warn "Directory not writable: $dir"
            ((TESTS_WARNED++))
        fi
    fi
done

# Check maintenance mode
if [ -f "$PRESTASHOP_ROOT/.maintenance" ]; then
    warn "PrestaShop is in MAINTENANCE MODE"
    ((TESTS_WARNED++))
fi

#===============================================================================
header "TEST 7: File Permissions"
#===============================================================================

log "Checking file ownership..."

# Get web server user
WEB_USER=$(ps aux | grep -E "(apache|httpd|nginx|www-data)" | grep -v grep | head -1 | awk '{print $1}')
WEB_USER=${WEB_USER:-www-data}
info "Web server user: $WEB_USER"

# Check ownership
OWNER=$(stat -c '%U' "$PRESTASHOP_ROOT" 2>/dev/null)
if [ "$OWNER" = "$WEB_USER" ] || [ "$OWNER" = "root" ]; then
    pass "Web root ownership: $OWNER"
    ((TESTS_PASSED++))
else
    warn "Web root owned by: $OWNER (expected $WEB_USER or root)"
    ((TESTS_WARNED++))
fi

#===============================================================================
header "TEST 8: SSL Certificate"
#===============================================================================

log "Checking SSL certificate..."

CERT_INFO=$(echo | openssl s_client -connect localhost:443 -servername localhost 2>/dev/null | openssl x509 -noout -dates 2>/dev/null)

if [ -n "$CERT_INFO" ]; then
    EXPIRY=$(echo "$CERT_INFO" | grep "notAfter" | cut -d= -f2)
    pass "SSL certificate found"
    info "Expires: $EXPIRY"
    ((TESTS_PASSED++))

    # Check if expired
    EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null)
    NOW_EPOCH=$(date +%s)
    if [ -n "$EXPIRY_EPOCH" ] && [ "$EXPIRY_EPOCH" -lt "$NOW_EPOCH" ]; then
        fail "SSL certificate is EXPIRED!"
        ((TESTS_FAILED++))
    fi
else
    warn "No SSL certificate found or SSL not configured"
    ((TESTS_WARNED++))
fi

#===============================================================================
header "TEST 9: Error Logs"
#===============================================================================

log "Checking for recent errors..."

# Apache error log
for logfile in /var/log/apache2/error.log /var/log/httpd/error_log /var/log/nginx/error.log; do
    if [ -f "$logfile" ]; then
        ERROR_COUNT=$(tail -100 "$logfile" 2>/dev/null | grep -ci "error\|fatal\|critical" || echo 0)
        if [ "$ERROR_COUNT" -gt 10 ]; then
            warn "Found $ERROR_COUNT errors in $logfile (last 100 lines)"
            ((TESTS_WARNED++))
            log "  Recent errors:"
            tail -5 "$logfile" | grep -i "error\|fatal" | sed 's/^/    /' | head -3
        else
            pass "Web server log: $ERROR_COUNT errors in last 100 lines"
        fi
        break
    fi
done

# MySQL error log
for logfile in /var/log/mysql/error.log /var/log/mariadb/mariadb.log; do
    if [ -f "$logfile" ]; then
        ERROR_COUNT=$(tail -50 "$logfile" 2>/dev/null | grep -ci "error\|fatal" || echo 0)
        if [ "$ERROR_COUNT" -gt 5 ]; then
            warn "Found $ERROR_COUNT errors in MySQL log"
            ((TESTS_WARNED++))
        else
            pass "MySQL log: $ERROR_COUNT errors in last 50 lines"
        fi
        break
    fi
done

#===============================================================================
header "TEST 10: Disk Space"
#===============================================================================

log "Checking disk space..."

DISK_USAGE=$(df -h / | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$DISK_USAGE" -lt 80 ]; then
    pass "Disk usage: ${DISK_USAGE}%"
    ((TESTS_PASSED++))
elif [ "$DISK_USAGE" -lt 90 ]; then
    warn "Disk usage: ${DISK_USAGE}% (getting full)"
    ((TESTS_WARNED++))
else
    fail "Disk usage: ${DISK_USAGE}% (CRITICAL!)"
    ((TESTS_FAILED++))
fi

#===============================================================================
header "TEST SUMMARY"
#===============================================================================

log ""
log "  ${GREEN}Passed:${NC}  $TESTS_PASSED"
log "  ${YELLOW}Warnings:${NC} $TESTS_WARNED"
log "  ${RED}Failed:${NC}  $TESTS_FAILED"
log ""

if [ "$TESTS_FAILED" -gt 0 ]; then
    log "${RED}Some tests failed! See fixes below.${NC}"
else
    log "${GREEN}All critical tests passed!${NC}"
fi

#===============================================================================
header "COMMON FIXES"
#===============================================================================

if [ "$TESTS_FAILED" -gt 0 ] || [ "$TESTS_WARNED" -gt 0 ]; then
    log "Would you like to apply automatic fixes?"
    read -p "Apply fixes? (y/n): " APPLY_FIXES

    if [ "$APPLY_FIXES" = "y" ]; then
        log ""
        log "Applying fixes..."
        log ""

        # Fix 1: Restart services
        log "Restarting services..."
        [ -n "$WEB_SERVER" ] && systemctl restart "$WEB_SERVER" && log "  Restarted $WEB_SERVER"
        [ -n "$DB_SERVICE" ] && systemctl restart "$DB_SERVICE" && log "  Restarted $DB_SERVICE"

        # Fix 2: Fix permissions
        log "Fixing permissions..."
        if [ -d "$PRESTASHOP_ROOT" ]; then
            chown -R "$WEB_USER":"$WEB_USER" "$PRESTASHOP_ROOT"
            find "$PRESTASHOP_ROOT" -type d -exec chmod 755 {} \;
            find "$PRESTASHOP_ROOT" -type f -exec chmod 644 {} \;

            # Make cache/upload writable
            for dir in var/cache var/logs img upload download app/cache app/logs cache log; do
                [ -d "$PRESTASHOP_ROOT/$dir" ] && chmod -R 775 "$PRESTASHOP_ROOT/$dir"
            done
            log "  Fixed file permissions"
        fi

        # Fix 3: Clear PrestaShop cache
        log "Clearing PrestaShop cache..."
        rm -rf "$PRESTASHOP_ROOT/var/cache/"* 2>/dev/null
        rm -rf "$PRESTASHOP_ROOT/app/cache/"* 2>/dev/null
        rm -rf "$PRESTASHOP_ROOT/cache/smarty/compile/"* 2>/dev/null
        rm -rf "$PRESTASHOP_ROOT/cache/smarty/cache/"* 2>/dev/null
        log "  Cleared cache"

        # Fix 4: Disable maintenance mode
        if [ -f "$PRESTASHOP_ROOT/.maintenance" ]; then
            rm -f "$PRESTASHOP_ROOT/.maintenance"
            log "  Disabled maintenance mode"
        fi

        # Fix 5: Generate self-signed SSL if needed
        if [ ! -f /etc/ssl/certs/prestashop.crt ]; then
            log "Generating self-signed SSL certificate..."
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout /etc/ssl/private/prestashop.key \
                -out /etc/ssl/certs/prestashop.crt \
                -subj "/CN=$(hostname)" 2>/dev/null
            log "  Generated SSL certificate"
        fi

        log ""
        log "${GREEN}Fixes applied. Re-run this script to verify.${NC}"
    fi
fi

#===============================================================================
header "QUICK COMMANDS REFERENCE"
#===============================================================================

cat << 'EOF'
# Restart services
systemctl restart apache2 mysql

# Check logs
tail -50 /var/log/apache2/error.log
tail -50 /var/log/mysql/error.log

# Fix permissions
chown -R www-data:www-data /var/www/html
find /var/www/html -type d -exec chmod 755 {} \;
find /var/www/html -type f -exec chmod 644 {} \;

# Clear PrestaShop cache
rm -rf /var/www/html/var/cache/*
rm -rf /var/www/html/app/cache/*

# Test MySQL
mysql -u root -p -e "SHOW DATABASES;"

# Test PHP
php -v
php -m | grep -i mysql

# Disable maintenance mode
rm /var/www/html/.maintenance

# Enable Apache modules
a2enmod rewrite ssl
systemctl restart apache2

# Check Apache config
apachectl configtest
EOF

log ""
log "Full log saved to: $LOGFILE"
