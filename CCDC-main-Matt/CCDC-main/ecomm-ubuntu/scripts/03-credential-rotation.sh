#!/bin/bash
###############################################################################
# 03-credential-rotation.sh - Credential Rotation Script
# Target: Ubuntu 24 E-Commerce Server (PrestaShop + MySQL)
# Purpose: Change all critical passwords systematically
###############################################################################

set -euo pipefail

LOGFILE="/root/ccdc-logs/cred_rotation_$(date +%Y%m%d_%H%M%S).log"
CRED_FILE="/root/ccdc-logs/NEW_CREDENTIALS_$(date +%Y%m%d_%H%M%S).txt"
mkdir -p "$(dirname "$LOGFILE")"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$LOGFILE"
}

generate_password() {
    # Generate a competition-friendly password (no special chars that break scripts)
    openssl rand -base64 12 | tr -dc 'A-Za-z0-9' | head -c 16
}

log "Starting credential rotation..."

# Initialize credentials file
cat > "$CRED_FILE" << EOF
============================================
CCDC CREDENTIAL ROTATION - $(date)
Host: $(hostname)
============================================
KEEP THIS FILE SECURE - DELETE AFTER RECORDING

EOF

echo ""
echo "============================================"
echo "LINUX SYSTEM USERS"
echo "============================================"

# Get list of users with login shells
USERS=$(grep -E '/bin/(bash|sh|zsh)$' /etc/passwd | cut -d: -f1)

for user in $USERS; do
    echo ""
    read -p "Change password for '$user'? (y/N/skip-all): " -r REPLY

    if [[ $REPLY =~ ^[Ss] ]]; then
        log "Skipping remaining users"
        break
    fi

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        NEW_PASS=$(generate_password)
        echo "$user:$NEW_PASS" | chpasswd
        if [ $? -eq 0 ]; then
            log "Password changed for: $user"
            echo "LINUX USER: $user" >> "$CRED_FILE"
            echo "PASSWORD:   $NEW_PASS" >> "$CRED_FILE"
            echo "" >> "$CRED_FILE"
        else
            log "FAILED to change password for: $user"
        fi
    fi
done

echo ""
echo "============================================"
echo "MYSQL USERS"
echo "============================================"

read -p "Rotate MySQL passwords? (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    read -sp "Enter current MySQL root password (or press Enter for socket auth): " MYSQL_ROOT_PASS
    echo ""

    if [ -z "$MYSQL_ROOT_PASS" ]; then
        MYSQL_CMD="mysql"
    else
        MYSQL_CMD="mysql -uroot -p${MYSQL_ROOT_PASS}"
    fi

    # Get MySQL users
    MYSQL_USERS=$($MYSQL_CMD -N -e "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE User NOT IN ('mysql.sys','mysql.session','mysql.infoschema','debian-sys-maint');" 2>/dev/null || echo "")

    if [ -z "$MYSQL_USERS" ]; then
        log "Could not retrieve MySQL users. Check credentials."
    else
        echo "MySQL users found:"
        echo "$MYSQL_USERS"
        echo ""

        for userhost in $MYSQL_USERS; do
            user=$(echo "$userhost" | cut -d@ -f1)
            host=$(echo "$userhost" | cut -d@ -f2)

            read -p "Change password for MySQL '$user'@'$host'? (y/N): " -r REPLY
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                NEW_PASS=$(generate_password)
                $MYSQL_CMD -e "ALTER USER '$user'@'$host' IDENTIFIED BY '$NEW_PASS';" 2>/dev/null
                if [ $? -eq 0 ]; then
                    log "MySQL password changed for: $user@$host"
                    echo "MYSQL USER: $user@$host" >> "$CRED_FILE"
                    echo "PASSWORD:   $NEW_PASS" >> "$CRED_FILE"
                    echo "" >> "$CRED_FILE"
                else
                    log "FAILED to change MySQL password for: $user@$host"
                fi
            fi
        done

        $MYSQL_CMD -e "FLUSH PRIVILEGES;" 2>/dev/null || true
    fi
fi

echo ""
echo "============================================"
echo "PRESTASHOP ADMIN"
echo "============================================"

read -p "Reset PrestaShop admin password? (y/N): " -r REPLY
if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Find PrestaShop database configuration
    PS_CONFIG=$(find /var/www -name "parameters.php" -path "*/app/config/*" 2>/dev/null | head -1)

    if [ -z "$PS_CONFIG" ]; then
        PS_CONFIG=$(find /var/www -name "settings.inc.php" 2>/dev/null | head -1)
    fi

    if [ -n "$PS_CONFIG" ]; then
        log "Found PrestaShop config: $PS_CONFIG"

        # Extract database info
        DB_NAME=$(grep -oP "(?<='database_name' => ')[^']*" "$PS_CONFIG" 2>/dev/null || grep -oP "(?<=_DB_NAME', ')[^']*" "$PS_CONFIG" 2>/dev/null || echo "")
        DB_PREFIX=$(grep -oP "(?<='database_prefix' => ')[^']*" "$PS_CONFIG" 2>/dev/null || grep -oP "(?<=_DB_PREFIX', ')[^']*" "$PS_CONFIG" 2>/dev/null || echo "ps_")
        COOKIE_KEY=$(grep -oP "(?<='cookie_key' => ')[^']*" "$PS_CONFIG" 2>/dev/null || grep -oP "(?<=_COOKIE_KEY', ')[^']*" "$PS_CONFIG" 2>/dev/null || echo "")

        if [ -n "$DB_NAME" ]; then
            echo "Database: $DB_NAME"
            echo "Prefix: $DB_PREFIX"

            # List admin users
            echo "PrestaShop admin users:"
            $MYSQL_CMD "$DB_NAME" -e "SELECT id_employee, email, lastname, firstname FROM ${DB_PREFIX}employee;" 2>/dev/null || echo "Could not query employees"

            read -p "Enter admin email to reset: " ADMIN_EMAIL
            NEW_PASS=$(generate_password)

            # PrestaShop uses MD5(COOKIE_KEY + password) for older versions
            # Newer versions use bcrypt
            # We'll use MD5 format which works for most versions
            if [ -n "$COOKIE_KEY" ]; then
                HASH=$(echo -n "${COOKIE_KEY}${NEW_PASS}" | md5sum | cut -d' ' -f1)
            else
                HASH=$(echo -n "$NEW_PASS" | md5sum | cut -d' ' -f1)
            fi

            $MYSQL_CMD "$DB_NAME" -e "UPDATE ${DB_PREFIX}employee SET passwd='$HASH' WHERE email='$ADMIN_EMAIL';" 2>/dev/null
            if [ $? -eq 0 ]; then
                log "PrestaShop admin password changed for: $ADMIN_EMAIL"
                echo "PRESTASHOP ADMIN: $ADMIN_EMAIL" >> "$CRED_FILE"
                echo "PASSWORD:         $NEW_PASS" >> "$CRED_FILE"
                echo "NOTE: If login fails, password hash format may differ" >> "$CRED_FILE"
                echo "" >> "$CRED_FILE"
            else
                log "FAILED to change PrestaShop admin password"
            fi
        fi
    else
        log "PrestaShop configuration not found"
    fi
fi

echo ""
echo "============================================"
echo "CREDENTIAL ROTATION COMPLETE"
echo "============================================"
echo ""
echo "New credentials saved to: $CRED_FILE"
echo ""
echo "IMPORTANT:"
echo "1. Record these credentials securely"
echo "2. Update PrestaShop database connection in parameters.php if MySQL creds changed"
echo "3. Test all services after rotation"
echo "4. Delete $CRED_FILE after recording"
echo ""
chmod 600 "$CRED_FILE"
log "Credential rotation complete"
