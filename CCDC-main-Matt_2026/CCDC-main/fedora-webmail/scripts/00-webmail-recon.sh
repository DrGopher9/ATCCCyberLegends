#!/bin/bash
#===============================================================================
# CCDC Fedora Webmail/Apps - Reconnaissance Script
# Target: Fedora Server with Webmail (Roundcube/SquirrelMail) and Web Apps
# Run as: root
#===============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

LOGDIR="/opt/ccdc-logs"
mkdir -p "$LOGDIR"
RECON_FILE="$LOGDIR/webmail_recon_$(date +%Y%m%d_%H%M%S).txt"

echo -e "${CYAN}========================================"
echo "  CCDC Fedora Webmail Reconnaissance"
echo -e "========================================${NC}"
echo ""

{
    echo "CCDC Fedora Webmail Reconnaissance - $(date)"
    echo "=============================================="
    echo ""

    #---------------------------------------------------------------------------
    echo "=== SYSTEM INFORMATION ==="
    echo ""
    echo "Hostname: $(hostname)"
    echo "OS: $(cat /etc/fedora-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null)"
    echo "Kernel: $(uname -r)"
    echo "Uptime: $(uptime)"
    echo ""
    echo "IP Addresses:"
    ip -4 addr show | grep inet | awk '{print "  " $2}'
    echo ""

    #---------------------------------------------------------------------------
    echo "=== USER ACCOUNTS ==="
    echo ""
    echo "Users with login shells:"
    grep -v "nologin\|false" /etc/passwd | grep -v "^#"
    echo ""

    echo "Users with UID >= 1000:"
    awk -F: '$3 >= 1000 && $3 < 65534 {print "  " $1 " (UID: " $3 ")"}' /etc/passwd
    echo ""

    echo "Root SSH authorized keys:"
    cat /root/.ssh/authorized_keys 2>/dev/null || echo "  No authorized_keys"
    echo ""

    echo "Sudoers:"
    grep -v "^#" /etc/sudoers 2>/dev/null | grep -v "^$" | head -20
    echo ""

    #---------------------------------------------------------------------------
    echo "=== WEB SERVER ==="
    echo ""

    # Check for Apache
    if systemctl is-active httpd &>/dev/null; then
        echo "Apache (httpd): RUNNING"
        echo "  Version: $(httpd -v 2>/dev/null | head -1)"
        echo "  Config test: $(httpd -t 2>&1)"
        echo ""
        echo "  Virtual Hosts:"
        httpd -S 2>/dev/null | head -20
        echo ""
        echo "  Loaded Modules:"
        httpd -M 2>/dev/null | grep -E "(php|ssl|rewrite|proxy)" | head -10
    elif systemctl is-active nginx &>/dev/null; then
        echo "Nginx: RUNNING"
        echo "  Version: $(nginx -v 2>&1)"
        echo ""
        echo "  Config:"
        nginx -T 2>/dev/null | grep -E "server_name|listen|root" | head -20
    else
        echo "No web server detected running"
    fi
    echo ""

    #---------------------------------------------------------------------------
    echo "=== PHP CONFIGURATION ==="
    echo ""
    if command -v php &>/dev/null; then
        echo "PHP Version: $(php -v | head -1)"
        echo ""
        echo "Key PHP Settings:"
        php -i 2>/dev/null | grep -E "^(display_errors|expose_php|allow_url_fopen|open_basedir|disable_functions)" | head -10
        echo ""
        echo "PHP Modules:"
        php -m 2>/dev/null | head -20
    else
        echo "PHP not installed"
    fi
    echo ""

    #---------------------------------------------------------------------------
    echo "=== WEBMAIL APPLICATIONS ==="
    echo ""

    # Check for Roundcube
    ROUNDCUBE_PATHS="/var/www/html/roundcube /var/www/roundcube /usr/share/roundcubemail /var/www/html/roundcubemail"
    for path in $ROUNDCUBE_PATHS; do
        if [ -d "$path" ]; then
            echo "Roundcube found: $path"
            if [ -f "$path/index.php" ]; then
                grep -i "version" "$path/index.php" 2>/dev/null | head -3
            fi
            if [ -f "$path/config/config.inc.php" ]; then
                echo "  Config file exists"
                grep -E "^\\\$config\['(db_dsnw|default_host|smtp_server)" "$path/config/config.inc.php" 2>/dev/null
            fi
        fi
    done

    # Check for SquirrelMail
    SQUIRREL_PATHS="/var/www/html/squirrelmail /usr/share/squirrelmail /var/www/html/webmail"
    for path in $SQUIRREL_PATHS; do
        if [ -d "$path" ]; then
            echo "SquirrelMail found: $path"
        fi
    done

    # Check for Horde
    if [ -d "/usr/share/horde" ] || [ -d "/var/www/html/horde" ]; then
        echo "Horde Webmail found"
    fi

    # Check for other web apps
    echo ""
    echo "Web document roots content:"
    for webroot in /var/www/html /var/www /srv/http; do
        if [ -d "$webroot" ]; then
            echo "  $webroot:"
            ls -la "$webroot" 2>/dev/null | head -15
        fi
    done
    echo ""

    #---------------------------------------------------------------------------
    echo "=== DATABASE ==="
    echo ""
    if systemctl is-active mariadb &>/dev/null || systemctl is-active mysql &>/dev/null; then
        echo "MariaDB/MySQL: RUNNING"
        echo "  Databases:"
        mysql -e "SHOW DATABASES;" 2>/dev/null || echo "  (Need credentials to list)"
    fi

    if systemctl is-active postgresql &>/dev/null; then
        echo "PostgreSQL: RUNNING"
    fi

    if systemctl is-active sqlite &>/dev/null || [ -f "/var/lib/roundcube/roundcube.db" ]; then
        echo "SQLite databases found:"
        find /var -name "*.db" -o -name "*.sqlite" 2>/dev/null | head -10
    fi
    echo ""

    #---------------------------------------------------------------------------
    echo "=== MAIL SERVICES ==="
    echo ""
    for svc in postfix dovecot sendmail; do
        if systemctl is-active $svc &>/dev/null; then
            echo "$svc: RUNNING"
        fi
    done
    echo ""

    echo "Mail configuration:"
    if [ -f /etc/postfix/main.cf ]; then
        echo "  Postfix main.cf exists"
        grep -E "^(myhostname|mydomain|mynetworks|inet_interfaces)" /etc/postfix/main.cf 2>/dev/null
    fi
    echo ""

    #---------------------------------------------------------------------------
    echo "=== SSL/TLS CERTIFICATES ==="
    echo ""
    echo "Certificate files:"
    find /etc/pki/tls/certs /etc/ssl/certs /etc/letsencrypt -name "*.pem" -o -name "*.crt" 2>/dev/null | head -10
    echo ""

    if [ -f /etc/httpd/conf.d/ssl.conf ]; then
        echo "Apache SSL config:"
        grep -E "SSLCertificate|SSLProtocol" /etc/httpd/conf.d/ssl.conf 2>/dev/null | head -10
    fi
    echo ""

    #---------------------------------------------------------------------------
    echo "=== NETWORK SERVICES ==="
    echo ""
    echo "Listening Ports:"
    ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
    echo ""

    echo "Established Connections:"
    ss -tnp state established 2>/dev/null | head -20
    echo ""

    #---------------------------------------------------------------------------
    echo "=== FIREWALL (firewalld) ==="
    echo ""
    if systemctl is-active firewalld &>/dev/null; then
        echo "Firewalld: ACTIVE"
        firewall-cmd --list-all 2>/dev/null
    else
        echo "Firewalld: INACTIVE"
        echo ""
        echo "iptables rules:"
        iptables -L -n 2>/dev/null | head -30
    fi
    echo ""

    #---------------------------------------------------------------------------
    echo "=== SELINUX STATUS ==="
    echo ""
    getenforce 2>/dev/null || echo "SELinux not available"
    echo ""
    if command -v getsebool &>/dev/null; then
        echo "HTTP-related SELinux booleans:"
        getsebool -a 2>/dev/null | grep -i http | head -10
    fi
    echo ""

    #---------------------------------------------------------------------------
    echo "=== SCHEDULED TASKS ==="
    echo ""
    echo "Root crontab:"
    crontab -l 2>/dev/null || echo "  No root crontab"
    echo ""

    echo "System cron jobs:"
    ls -la /etc/cron.d/ 2>/dev/null
    echo ""

    #---------------------------------------------------------------------------
    echo "=== RUNNING SERVICES ==="
    echo ""
    systemctl list-units --type=service --state=running | head -30
    echo ""

    #---------------------------------------------------------------------------
    echo "=== SUSPICIOUS PROCESSES ==="
    echo ""
    ps aux | grep -iE "(nc|ncat|netcat|python.*-c|perl.*-e|bash.*-i|/tmp/)" | grep -v grep
    echo ""

    #---------------------------------------------------------------------------
    echo "=== RECENT LOGINS ==="
    echo ""
    last -10 2>/dev/null
    echo ""

    echo "Failed logins:"
    grep "Failed password" /var/log/secure 2>/dev/null | tail -10
    echo ""

} | tee "$RECON_FILE"

echo ""
echo -e "${GREEN}========================================"
echo "  Reconnaissance Complete"
echo -e "========================================${NC}"
echo ""
echo -e "${YELLOW}Output saved to: $RECON_FILE${NC}"
echo ""
echo -e "${CYAN}Key Items to Review:${NC}"
echo "  - Web application locations and versions"
echo "  - Database credentials"
echo "  - User accounts with shell access"
echo "  - Firewall/SELinux status"
echo "  - SSL certificate configuration"
echo ""
