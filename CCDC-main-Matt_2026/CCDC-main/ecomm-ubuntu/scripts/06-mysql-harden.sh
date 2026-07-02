#!/bin/bash
###############################################################################
# 06-mysql-harden.sh - MySQL Hardening Script
# Target: Ubuntu 24 E-Commerce Server (PrestaShop backend)
# Purpose: Secure MySQL/MariaDB database
###############################################################################

set -euo pipefail

LOGFILE="/root/ccdc-logs/mysql_harden_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$(dirname "$LOGFILE")"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOGFILE"
}

log "Starting MySQL hardening..."

# Detect MySQL or MariaDB
if systemctl is-active --quiet mysql 2>/dev/null; then
    SERVICE="mysql"
elif systemctl is-active --quiet mariadb 2>/dev/null; then
    SERVICE="mariadb"
else
    log "ERROR: MySQL/MariaDB service not found or not running"
    exit 1
fi

log "Detected database service: $SERVICE"

echo ""
echo "============================================"
echo "MYSQL SECURITY AUDIT"
echo "============================================"

# Try to connect
read -sp "Enter MySQL root password (or Enter for socket auth): " MYSQL_PASS
echo ""

if [ -z "$MYSQL_PASS" ]; then
    MYSQL_CMD="mysql"
else
    MYSQL_CMD="mysql -uroot -p${MYSQL_PASS}"
fi

# Test connection
if ! $MYSQL_CMD -e "SELECT 1;" &>/dev/null; then
    log "ERROR: Cannot connect to MySQL. Check credentials."
    exit 1
fi

log "MySQL connection successful"

# Audit current state
echo ""
echo "--- Current MySQL Users ---"
$MYSQL_CMD -e "SELECT User,Host,plugin FROM mysql.user;" 2>/dev/null | tee -a "$LOGFILE"

echo ""
echo "--- Users with % (any host) access ---"
$MYSQL_CMD -e "SELECT User,Host FROM mysql.user WHERE Host='%';" 2>/dev/null | tee -a "$LOGFILE"

echo ""
echo "--- Databases ---"
$MYSQL_CMD -e "SHOW DATABASES;" 2>/dev/null | tee -a "$LOGFILE"

echo ""
echo "============================================"
echo "MYSQL HARDENING OPTIONS"
echo "============================================"

# 1. Remove anonymous users
echo ""
read -p "Remove anonymous MySQL users? (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log "Removing anonymous users..."
    $MYSQL_CMD -e "DELETE FROM mysql.user WHERE User='';" 2>/dev/null
    log "Anonymous users removed"
fi

# 2. Remove remote root access
echo ""
read -p "Remove remote root login (keep localhost only)? (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log "Removing remote root access..."
    $MYSQL_CMD -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" 2>/dev/null
    log "Remote root access removed"
fi

# 3. Remove test database
echo ""
read -p "Remove test database? (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log "Removing test database..."
    $MYSQL_CMD -e "DROP DATABASE IF EXISTS test;" 2>/dev/null
    $MYSQL_CMD -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" 2>/dev/null
    log "Test database removed"
fi

# 4. Check for wildcard host users
echo ""
echo "Users with wildcard (%) host access:"
WILDCARD_USERS=$($MYSQL_CMD -N -e "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE Host='%';" 2>/dev/null || echo "")
if [ -n "$WILDCARD_USERS" ]; then
    echo "$WILDCARD_USERS"
    echo ""
    read -p "Restrict these users to localhost only? (y/N): " -r REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        for userhost in $WILDCARD_USERS; do
            user=$(echo "$userhost" | cut -d@ -f1)
            log "Restricting $user to localhost..."
            $MYSQL_CMD -e "UPDATE mysql.user SET Host='localhost' WHERE User='$user' AND Host='%';" 2>/dev/null || true
        done
        log "Wildcard users restricted"
    fi
fi

# Flush privileges
log "Flushing privileges..."
$MYSQL_CMD -e "FLUSH PRIVILEGES;" 2>/dev/null

# 5. Configure bind-address
echo ""
echo "============================================"
echo "MYSQL BIND ADDRESS CONFIGURATION"
echo "============================================"
echo ""
echo "Current MySQL is bound to:"
grep -r "bind-address" /etc/mysql/ 2>/dev/null || echo "bind-address not explicitly set"

echo ""
read -p "Ensure MySQL binds to localhost only? (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Find the config file
    MYSQL_CONF=""
    if [ -f "/etc/mysql/mysql.conf.d/mysqld.cnf" ]; then
        MYSQL_CONF="/etc/mysql/mysql.conf.d/mysqld.cnf"
    elif [ -f "/etc/mysql/mariadb.conf.d/50-server.cnf" ]; then
        MYSQL_CONF="/etc/mysql/mariadb.conf.d/50-server.cnf"
    elif [ -f "/etc/mysql/my.cnf" ]; then
        MYSQL_CONF="/etc/mysql/my.cnf"
    fi

    if [ -n "$MYSQL_CONF" ]; then
        log "Configuring bind-address in $MYSQL_CONF"
        # Backup
        cp "$MYSQL_CONF" "$MYSQL_CONF.bak.$(date +%Y%m%d_%H%M%S)"

        # Check if bind-address exists and update, or add it
        if grep -q "^bind-address" "$MYSQL_CONF"; then
            sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' "$MYSQL_CONF"
        elif grep -q "^\[mysqld\]" "$MYSQL_CONF"; then
            sed -i '/^\[mysqld\]/a bind-address = 127.0.0.1' "$MYSQL_CONF"
        fi

        log "bind-address set to 127.0.0.1"
        echo ""
        read -p "Restart MySQL to apply bind-address change? (y/N): " -r REPLY
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            systemctl restart $SERVICE
            log "MySQL restarted"
        else
            log "MySQL restart skipped. Run 'systemctl restart $SERVICE' to apply."
        fi
    else
        log "Could not find MySQL config file"
    fi
fi

# 6. Enable logging
echo ""
echo "============================================"
echo "MYSQL LOGGING"
echo "============================================"
read -p "Enable MySQL general query log? (useful for IR) (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    $MYSQL_CMD -e "SET GLOBAL general_log = 'ON';" 2>/dev/null || true
    $MYSQL_CMD -e "SET GLOBAL general_log_file = '/var/log/mysql/general.log';" 2>/dev/null || true
    log "General query log enabled"
    echo "Log file: /var/log/mysql/general.log"
    echo "NOTE: This generates a lot of data. Disable after investigation:"
    echo "  mysql -e \"SET GLOBAL general_log = 'OFF';\""
fi

echo ""
echo "============================================"
echo "PRESTASHOP DATABASE CHECK"
echo "============================================"
PS_DB=$($MYSQL_CMD -N -e "SHOW DATABASES LIKE '%prestashop%';" 2>/dev/null || echo "")
if [ -z "$PS_DB" ]; then
    PS_DB=$($MYSQL_CMD -N -e "SHOW DATABASES LIKE '%presta%';" 2>/dev/null || echo "")
fi

if [ -n "$PS_DB" ]; then
    echo "Found PrestaShop database: $PS_DB"
    echo ""
    echo "PrestaShop database users:"
    $MYSQL_CMD -e "SELECT User,Host FROM mysql.db WHERE Db='$PS_DB';" 2>/dev/null || true
else
    echo "PrestaShop database not found by name pattern."
    echo "Listing all databases:"
    $MYSQL_CMD -e "SHOW DATABASES;" 2>/dev/null
fi

echo ""
echo "============================================"
echo "MYSQL HARDENING COMPLETE"
echo "============================================"
echo ""
echo "Applied changes:"
echo "  - Removed anonymous users (if selected)"
echo "  - Removed remote root access (if selected)"
echo "  - Removed test database (if selected)"
echo "  - Restricted wildcard users (if selected)"
echo "  - Configured bind-address (if selected)"
echo ""
echo "Final user list:"
$MYSQL_CMD -e "SELECT User,Host,plugin FROM mysql.user;" 2>/dev/null

echo ""
echo "IMPORTANT: Update PrestaShop config if you changed database credentials!"
echo "Config file: /var/www/[prestashop]/app/config/parameters.php"
echo ""
log "MySQL hardening complete"
