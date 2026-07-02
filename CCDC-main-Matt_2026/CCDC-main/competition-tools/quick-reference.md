# CCDC Quick Reference Card

## First 15 Minutes Checklist

### ALL SYSTEMS:
- [ ] Change default/admin passwords
- [ ] Remove unknown users
- [ ] Check for unauthorized SSH keys
- [ ] Enable firewall
- [ ] Start logging

### Windows AD:
- [ ] Change Administrator password
- [ ] Audit Domain Admins group
- [ ] Check scheduled tasks
- [ ] Enable Windows Firewall
- [ ] Check Group Policy

### Linux Systems:
- [ ] Change root password
- [ ] Check /etc/passwd for suspicious users
- [ ] Check sudoers
- [ ] Review crontabs
- [ ] Check running processes

### Firewall:
- [ ] Change admin password
- [ ] Review security policies
- [ ] Check NAT rules
- [ ] Enable logging
- [ ] Backup configuration

### Splunk:
- [ ] Change admin password
- [ ] Verify forwarders connected
- [ ] Check for alerts
- [ ] Review dashboards

---

## Critical Ports

| Service | Port | Protocol |
|---------|------|----------|
| SSH | 22 | TCP |
| DNS | 53 | TCP/UDP |
| HTTP | 80 | TCP |
| HTTPS | 443 | TCP |
| SMTP | 25 | TCP |
| SMTP-SUB | 587 | TCP |
| IMAP | 143 | TCP |
| IMAPS | 993 | TCP |
| POP3 | 110 | TCP |
| POP3S | 995 | TCP |
| LDAP | 389 | TCP |
| LDAPS | 636 | TCP |
| Kerberos | 88 | TCP/UDP |
| SMB | 445 | TCP |
| RDP | 3389 | TCP |
| MySQL | 3306 | TCP |
| Splunk Web | 8000 | TCP |
| Splunk Mgmt | 8089 | TCP |
| Splunk Fwd | 9997 | TCP |

---

## Quick Commands

### Linux

```bash
# Change password
passwd username

# Lock user
usermod -L username

# Find files modified in last day
find / -mtime -1 -type f 2>/dev/null

# Check connections
ss -tnp

# Check listening ports
ss -tlnp

# Check processes
ps auxf

# Check crontabs
crontab -l
cat /etc/crontab
ls /etc/cron.d/

# Block IP (iptables)
iptables -I INPUT -s IP -j DROP

# Block IP (UFW)
ufw deny from IP

# Block IP (firewalld)
firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=IP reject'
firewall-cmd --reload

# Check last logins
last -20

# Check failed logins
grep "Failed password" /var/log/auth.log
grep "Failed password" /var/log/secure

# Check for web shells
grep -r "eval\|base64_decode\|shell_exec" /var/www/

# Generate password
< /dev/urandom tr -dc 'A-Za-z0-9!@#$%' | head -c 20; echo
```

### Windows PowerShell

```powershell
# Change password
Set-ADAccountPassword -Identity user -Reset

# Disable user
Disable-ADAccount -Identity user

# Check Domain Admins
Get-ADGroupMember -Identity "Domain Admins"

# Check logged on users
query user

# Check connections
Get-NetTCPConnection -State Established

# Check services
Get-Service | Where-Object {$_.Status -eq 'Running'}

# Check scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'}

# Block IP
New-NetFirewallRule -DisplayName "Block-IP" -Direction Inbound -Action Block -RemoteAddress IP

# Check event log
Get-WinEvent -LogName Security -MaxEvents 50

# Generate password
-join ((65..90) + (97..122) + (48..57) | Get-Random -Count 16 | ForEach-Object {[char]$_})

# Force GPO update
gpupdate /force
```

### Palo Alto Firewall

```
# Show system info
show system info

# Show admins
show admins all

# Show security policies
show running security-policy

# Show active sessions
show session all

# Block IP
set address block-IP ip-netmask IP/32
set security policies rules block-IP from any to any source block-IP action deny

# Commit changes
commit
```

---

## Incident Response Quick Actions

### User Compromise:
1. Disable the account
2. Change password
3. Kill active sessions
4. Review recent activity
5. Check for persistence

### Web Shell Found:
1. Remove/quarantine the file
2. Check web server access logs
3. Block source IP
4. Check for other shells
5. Review upload directories

### Brute Force Attack:
1. Block attacker IP
2. Check for successful logins
3. Change compromised passwords
4. Enable fail2ban/account lockout
5. Review all auth logs

### Suspected Backdoor:
1. Capture system state
2. Check running processes
3. Check network connections
4. Review scheduled tasks/cron
5. Check startup items
6. Look for unusual services

---

## Log Locations

### Linux
- Auth: `/var/log/auth.log` or `/var/log/secure`
- System: `/var/log/syslog` or `/var/log/messages`
- Apache: `/var/log/apache2/` or `/var/log/httpd/`
- Nginx: `/var/log/nginx/`
- Mail: `/var/log/mail.log` or `/var/log/maillog`
- Audit: `/var/log/audit/audit.log`

### Windows
- Security: Event Viewer > Windows Logs > Security
- System: Event Viewer > Windows Logs > System
- Application: Event Viewer > Windows Logs > Application
- PowerShell: Event Viewer > Applications and Services > PowerShell

### Splunk
- Audit: `/opt/splunk/var/log/splunk/audit.log`
- Main: `/opt/splunk/var/log/splunk/splunkd.log`

---

## Splunk Searches

```
# Failed logins
index=* sourcetype=linux_secure "Failed password" | stats count by src_ip

# Successful logins
index=* sourcetype=linux_secure "Accepted" | stats count by user

# Windows failed logins
index=* EventCode=4625 | stats count by Account_Name, Source_Network_Address

# New user created
index=* EventCode=4720 | table _time, TargetUserName, SubjectUserName

# Admin activity
index=_audit | stats count by action, user

# Process execution
index=* sourcetype=sysmon EventCode=1 | table _time, User, Image, CommandLine
```

---

## Communication Template

When reporting to team:
```
ISSUE: [Brief description]
SYSTEM: [hostname/IP]
STATUS: [Investigating/Contained/Resolved]
ACTION NEEDED: [Yes/No - what's needed]
```

---

## Emergency Contacts

| Role | Name | Location |
|------|------|----------|
| Team Captain | | |
| Windows Admin | | |
| Linux Admin | | |
| Network Admin | | |
| White Team Table | | |
