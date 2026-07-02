# E-Commerce Server Troubleshooting Guide

## Quick Diagnostic
```bash
./scripts/10-test-and-fix.sh
```

---

## Common Issues & Fixes

### 1. Website Shows Blank Page

**Diagnose:**
```bash
tail -50 /var/log/apache2/error.log
php -v   # Check PHP is working
```

**Fix:**
```bash
# Enable error display temporarily
echo "display_errors = On" >> /etc/php/*/apache2/php.ini
systemctl restart apache2

# Clear cache
rm -rf /var/www/html/var/cache/*
rm -rf /var/www/html/app/cache/*

# Check PHP memory
echo "memory_limit = 256M" >> /etc/php/*/apache2/php.ini
systemctl restart apache2
```

---

### 2. Database Connection Error

**Diagnose:**
```bash
# Check MySQL is running
systemctl status mysql

# Test connection manually
mysql -u prestashop -p
```

**Fix:**
```bash
# Restart MySQL
systemctl restart mysql

# If password wrong, reset it:
mysql -u root -p
> ALTER USER 'prestashop'@'localhost' IDENTIFIED BY 'newpassword';
> FLUSH PRIVILEGES;

# Update PrestaShop config (1.7+):
nano /var/www/html/app/config/parameters.php
# Change: 'database_password' => 'newpassword'

# Update PrestaShop config (1.6):
nano /var/www/html/config/settings.inc.php
# Change: define('_DB_PASSWD_', 'newpassword');

# Clear cache after config change
rm -rf /var/www/html/var/cache/*
```

---

### 3. 500 Internal Server Error

**Diagnose:**
```bash
tail -100 /var/log/apache2/error.log | grep -i error
```

**Fix - Permissions:**
```bash
chown -R www-data:www-data /var/www/html
find /var/www/html -type d -exec chmod 755 {} \;
find /var/www/html -type f -exec chmod 644 {} \;
chmod -R 775 /var/www/html/var
chmod -R 775 /var/www/html/app/cache
chmod -R 775 /var/www/html/app/logs
```

**Fix - .htaccess:**
```bash
# Check if mod_rewrite is enabled
a2enmod rewrite
systemctl restart apache2

# Check Apache config allows .htaccess
nano /etc/apache2/sites-enabled/000-default.conf
# Add inside <VirtualHost>:
#   <Directory /var/www/html>
#       AllowOverride All
#   </Directory>

systemctl restart apache2
```

---

### 4. CSS/Images Not Loading

**Diagnose:**
```bash
# Check browser console (F12) for 404 errors
curl -I http://localhost/themes/
```

**Fix:**
```bash
# Enable mod_rewrite
a2enmod rewrite
systemctl restart apache2

# Check .htaccess exists
ls -la /var/www/html/.htaccess

# Fix base URL in database
mysql -u prestashop -p prestashop
> SELECT * FROM ps_shop_url;
> UPDATE ps_shop_url SET domain='YOUR_IP', domain_ssl='YOUR_IP';

# Clear cache
rm -rf /var/www/html/var/cache/*
```

---

### 5. Admin Panel Inaccessible

**Diagnose:**
```bash
# Find admin folder (it's renamed for security)
ls /var/www/html | grep admin
# Example: admin1234abc
```

**Fix:**
```bash
# Access via: http://YOUR_IP/admin1234abc

# If locked out, reset admin password:
mysql -u prestashop -p prestashop
> UPDATE ps_employee SET passwd=MD5('cookie_key_from_settings' || 'newpassword') WHERE id_employee=1;

# Or simpler - get cookie key first:
grep COOKIE_KEY /var/www/html/app/config/parameters.php
# Then:
> UPDATE ps_employee SET passwd=MD5('COOKIE_KEY_VALUE' || 'newpassword') WHERE id_employee=1;
```

---

### 6. Maintenance Mode Stuck

**Fix:**
```bash
rm /var/www/html/.maintenance

# Or via database:
mysql -u prestashop -p prestashop
> UPDATE ps_configuration SET value='0' WHERE name='PS_SHOP_ENABLE';
```

---

### 7. SSL/HTTPS Not Working

**Diagnose:**
```bash
# Check if SSL module enabled
apache2ctl -M | grep ssl

# Check certificate
openssl s_client -connect localhost:443 -servername localhost
```

**Fix:**
```bash
# Enable SSL
a2enmod ssl
a2ensite default-ssl
systemctl restart apache2

# Generate self-signed cert if needed
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/prestashop.key \
    -out /etc/ssl/certs/prestashop.crt \
    -subj "/CN=$(hostname)"

# Update Apache SSL config
nano /etc/apache2/sites-enabled/default-ssl.conf
# Set:
#   SSLCertificateFile /etc/ssl/certs/prestashop.crt
#   SSLCertificateKeyFile /etc/ssl/private/prestashop.key

systemctl restart apache2
```

---

### 8. Slow Performance

**Fix:**
```bash
# Enable PHP opcache
echo "opcache.enable=1" >> /etc/php/*/apache2/php.ini
echo "opcache.memory_consumption=256" >> /etc/php/*/apache2/php.ini
systemctl restart apache2

# Enable Apache caching
a2enmod expires headers
systemctl restart apache2

# Check MySQL slow queries
tail -50 /var/log/mysql/slow.log
```

---

### 9. "Class Not Found" Errors

**Fix:**
```bash
# Regenerate class index
rm /var/www/html/var/cache/*/class_index.php

# Or run PrestaShop console
cd /var/www/html
php bin/console cache:clear
```

---

### 10. File Upload Errors

**Fix:**
```bash
# Increase PHP limits
nano /etc/php/*/apache2/php.ini
# Set:
#   upload_max_filesize = 64M
#   post_max_size = 64M
#   max_execution_time = 300

# Fix permissions
chmod 775 /var/www/html/img
chmod 775 /var/www/html/upload
chown -R www-data:www-data /var/www/html/img /var/www/html/upload

systemctl restart apache2
```

---

## Emergency Recovery

### Complete Service Restart
```bash
systemctl restart apache2 mysql php*-fpm
```

### Restore from Backup
```bash
# Restore database
mysql -u root -p prestashop < /opt/ccdc-backups/mysql_prestashop_*.sql

# Restore files
cp -r /opt/ccdc-backups/prestashop_*/* /var/www/html/

# Fix permissions
chown -R www-data:www-data /var/www/html
```

### Emergency Debug Mode
```bash
# Enable PrestaShop debug (1.7+)
nano /var/www/html/config/defines.inc.php
# Change: define('_PS_MODE_DEV_', true);

# Check output
curl http://localhost/ 2>&1 | head -50
```

---

## Service Check Commands

```bash
# All-in-one status
systemctl status apache2 mysql --no-pager

# Test HTTP
curl -I http://localhost

# Test MySQL
mysql -u root -p -e "SELECT 1"

# Test PHP
php -r "echo 'PHP OK';"

# Check ports
ss -tlnp | grep -E "80|443|3306"
```

---

## PrestaShop Config Locations

| Version | Config File |
|---------|-------------|
| 1.7+ | `/var/www/html/app/config/parameters.php` |
| 1.6 | `/var/www/html/config/settings.inc.php` |

## Important Database Tables

| Table | Purpose |
|-------|---------|
| ps_employee | Admin users |
| ps_configuration | Shop settings |
| ps_shop_url | Domain settings |
| ps_customer | Customer accounts |
