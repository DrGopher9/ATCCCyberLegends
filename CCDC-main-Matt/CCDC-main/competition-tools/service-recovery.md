# CCDC Service Recovery Guide

## CRITICAL: Uptime = Points

Every minute a scored service is down costs you points. This guide helps you get services back FAST.

---

## Quick Recovery Commands

### Linux Services

```bash
# Check service status
systemctl status SERVICE_NAME

# Restart service
systemctl restart SERVICE_NAME

# If restart fails, check logs
journalctl -u SERVICE_NAME -n 50

# Check if process is running
ps aux | grep SERVICE_NAME

# Check if port is listening
ss -tlnp | grep PORT

# Force kill and restart
pkill -9 SERVICE_NAME
systemctl start SERVICE_NAME
```

### Windows Services

```powershell
# Check service status
Get-Service SERVICE_NAME

# Restart service
Restart-Service SERVICE_NAME -Force

# If fails, check event log
Get-WinEvent -LogName System -MaxEvents 50 | Where-Object {$_.Message -like "*SERVICE*"}

# Check if port is listening
Get-NetTCPConnection -LocalPort PORT

# Force restart
Stop-Process -Name PROCESS_NAME -Force
Start-Service SERVICE_NAME
```

---

## Service-Specific Recovery

### Apache/Nginx (HTTP/HTTPS)

**Quick Check:**
```bash
curl -I http://localhost
curl -Ik https://localhost
```

**Common Issues:**

| Problem | Fix |
|---------|-----|
| Config syntax error | `apachectl configtest` or `nginx -t` |
| Port already in use | `ss -tlnp \| grep :80` then kill process |
| SSL certificate issue | Check cert paths in config |
| Permission denied | `chown -R apache:apache /var/www/html` |
| Module not loaded | Check `/etc/httpd/conf.modules.d/` |

**Recovery:**
```bash
# Test config
apachectl configtest  # or nginx -t

# If config error, restore from backup
cp /opt/ccdc-backups/httpd_*/conf/httpd.conf /etc/httpd/conf/

# Restart
systemctl restart httpd  # or nginx

# If still fails, check SELinux
setenforce 0  # Temporarily disable
systemctl restart httpd
# Then fix SELinux properly:
restorecon -Rv /var/www/html
setsebool -P httpd_can_network_connect 1
setenforce 1
```

---

### MySQL/MariaDB

**Quick Check:**
```bash
mysql -u root -p -e "SELECT 1"
```

**Common Issues:**

| Problem | Fix |
|---------|-----|
| Can't connect to socket | Check if running, check socket path |
| Access denied | Reset root password |
| Corrupted tables | `mysqlcheck --repair --all-databases` |
| Disk full | Clear logs, temp files |
| Config error | Check `/etc/my.cnf` syntax |

**Recovery:**
```bash
# Check status
systemctl status mariadb

# If not starting, check error log
tail -50 /var/log/mysql/error.log
tail -50 /var/log/mariadb/mariadb.log

# Reset root password if locked out:
systemctl stop mariadb
mysqld_safe --skip-grant-tables &
mysql -u root
  > FLUSH PRIVILEGES;
  > ALTER USER 'root'@'localhost' IDENTIFIED BY 'newpassword';
  > quit
pkill mysqld
systemctl start mariadb

# Restore from backup if corrupted
mysql -u root -p < /opt/ccdc-backups/database/all_databases.sql
```

---

### Postfix (SMTP)

**Quick Check:**
```bash
telnet localhost 25
# Should see: 220 hostname ESMTP Postfix
```

**Common Issues:**

| Problem | Fix |
|---------|-----|
| Not accepting connections | Check `inet_interfaces` in main.cf |
| Relay denied | Check `mynetworks` setting |
| Queue stuck | `postqueue -f` to flush |
| Config error | `postfix check` |

**Recovery:**
```bash
# Test config
postfix check

# If config error, restore
cp /opt/ccdc-backups/mail/postfix/main.cf /etc/postfix/

# Restart
systemctl restart postfix

# Check queue
postqueue -p
# Flush queue
postqueue -f

# If relay issues
postconf -e 'mynetworks = 127.0.0.0/8 [::1]/128 172.20.0.0/16'
systemctl restart postfix
```

---

### Dovecot (IMAP/POP3)

**Quick Check:**
```bash
telnet localhost 143
# Should see: * OK Dovecot ready
```

**Recovery:**
```bash
# Test config
doveconf -n

# Restart
systemctl restart dovecot

# Check logs
tail -50 /var/log/dovecot.log
journalctl -u dovecot -n 50

# SSL issues - regenerate self-signed
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/pki/dovecot/private/dovecot.pem \
  -out /etc/pki/dovecot/certs/dovecot.pem \
  -subj "/CN=$(hostname)"
systemctl restart dovecot
```

---

### DNS (Windows AD)

**Quick Check:**
```powershell
Resolve-DnsName google.com -Server localhost
nslookup domain.local localhost
```

**Common Issues:**

| Problem | Fix |
|---------|-----|
| Not resolving | Check DNS service, forwarders |
| Zone missing | Restore zone from backup |
| Forwarders not working | Update forwarder IPs |

**Recovery:**
```powershell
# Restart DNS service
Restart-Service DNS

# Check DNS service
Get-Service DNS

# Clear DNS cache
Clear-DnsServerCache

# Check zones
Get-DnsServerZone

# Fix forwarders
Set-DnsServerForwarder -IPAddress 8.8.8.8, 1.1.1.1

# If zone is missing, restore from backup
# or recreate the zone
```

---

### DHCP (Windows AD)

**Quick Check:**
```powershell
Get-DhcpServerv4Scope
```

**Recovery:**
```powershell
# Restart DHCP
Restart-Service DHCPServer

# Check scopes
Get-DhcpServerv4Scope

# If scope missing, restore
netsh dhcp server import "C:\ccdc-backups\dhcp-export.txt"

# Verify leases
Get-DhcpServerv4Lease -ScopeId 172.20.242.0
```

---

### Active Directory

**Quick Check:**
```powershell
Get-ADDomainController
Get-ADDomain
```

**Recovery:**
```powershell
# Check AD services
Get-Service NTDS, Netlogon, DNS, KDC

# Restart Netlogon
Restart-Service Netlogon

# Force replication (if multiple DCs)
repadmin /syncall /AdeP

# Check for replication errors
repadmin /showrepl

# DCDIAG for health check
dcdiag /v
```

---

### Splunk

**Quick Check:**
```bash
curl -k https://localhost:8000
/opt/splunk/bin/splunk status
```

**Recovery:**
```bash
# Restart Splunk
/opt/splunk/bin/splunk restart

# Check logs
tail -50 /opt/splunk/var/log/splunk/splunkd.log

# If license error
/opt/splunk/bin/splunk list licenser-pools

# If web not starting
/opt/splunk/bin/splunk enable webserver
/opt/splunk/bin/splunk restart

# If corrupt, restore config
cp -r /opt/ccdc-backups/splunk_etc/etc/* /opt/splunk/etc/
chown -R splunk:splunk /opt/splunk/etc
/opt/splunk/bin/splunk restart
```

---

## Emergency Procedures

### Service Won't Start - Unknown Reason

1. Check logs first:
```bash
journalctl -u SERVICE -n 100
tail -100 /var/log/SERVICE.log
```

2. Check disk space:
```bash
df -h
```

3. Check memory:
```bash
free -m
```

4. Check file permissions:
```bash
ls -la /etc/SERVICE/
ls -la /var/lib/SERVICE/
```

5. Restore from backup if all else fails

### Complete System Unresponsive

1. Try SSH from another system
2. If no SSH, use console access
3. Check if system is up (ping)
4. Force reboot only as last resort
5. After reboot, check all services

### Database Corrupted

1. Stop the service
2. Check logs for corruption details
3. Try repair:
```bash
# MySQL
mysqlcheck --repair --all-databases

# PostgreSQL
pg_resetwal -f /var/lib/pgsql/data
```
4. If repair fails, restore from backup

### Web Application Broken

1. Check web server logs
2. Check application logs
3. Restore from backup
4. Clear cache/temp files
5. Check database connectivity

---

## Pre-Competition: Know Your Recovery

Before competition, document for each system:

- [ ] Service names and commands
- [ ] Config file locations
- [ ] Log file locations
- [ ] Backup locations
- [ ] Dependencies
- [ ] Default ports
- [ ] Test commands

This saves precious minutes during recovery!
