# CCDC Red Team Playbook

## Know Your Enemy

Red teams typically have **full access** to your network before competition starts. Assume:
- They have your passwords
- They have backdoors installed
- They know your network topology
- They have persistence mechanisms

---

## Common Attack Timeline

### First 30 Minutes
- **Credential stuffing** with default/known passwords
- **Accessing backdoors** already installed
- **Reconnaissance** of your changes

### First 2 Hours
- **Privilege escalation** if you missed something
- **Lateral movement** between systems
- **Installing new persistence**
- **Data exfiltration** for points

### Mid-Competition
- **Targeted attacks** on services you're protecting
- **Social engineering** attempts
- **Destroying evidence** of their access

### Final Hours
- **All-out assault** - they have nothing to lose
- **Service disruption** attempts
- **Distraction attacks** while hitting real targets

---

## Common Attack Vectors

### 1. Credential Attacks

**What they do:**
- Use passwords from pre-competition access
- Brute force SSH/RDP
- Spray common passwords
- Kerberoasting (AD)

**How to detect:**
```
# Splunk
index=* "Failed password" | stats count by src_ip | where count > 10

# Linux
grep "Failed password" /var/log/secure | tail -50

# Windows
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 50
```

**How to defend:**
- Change ALL passwords immediately
- Enable account lockout
- Use fail2ban
- Monitor for brute force

---

### 2. Web Shells

**What they do:**
- Upload PHP/ASPX shells via file upload
- Plant shells in writable directories
- Use encoded/obfuscated shells

**Common locations:**
```
/var/www/html/uploads/
/var/www/html/images/
/var/www/html/tmp/
/var/www/html/cache/
C:\inetpub\wwwroot\uploads\
```

**How to detect:**
```bash
# Find PHP files in upload directories
find /var/www -path "*upload*" -name "*.php"

# Find recently modified PHP files
find /var/www -name "*.php" -mtime -1

# Find files with suspicious content
grep -r "eval\|base64_decode\|shell_exec\|system\|passthru" /var/www/
```

**How to defend:**
- Remove write permissions from web directories
- Block PHP execution in upload directories
- Monitor for new PHP files

---

### 3. Persistence Mechanisms

**Where they hide:**

| System | Location |
|--------|----------|
| Linux | Crontabs, systemd services, .bashrc, authorized_keys |
| Windows | Scheduled tasks, services, Run keys, startup folder |
| Web | Web shells, modified application files |
| Database | Stored procedures, triggers, rogue users |

**How to detect:**
```bash
# Linux
crontab -l
cat /etc/crontab
ls /etc/cron.d/
systemctl list-unit-files --type=service
cat ~/.bashrc
cat ~/.ssh/authorized_keys

# Windows PowerShell
Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'}
Get-Service | Where-Object {$_.Status -eq 'Running'}
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

**How to defend:**
- Audit all cron jobs and scheduled tasks
- Remove unknown SSH keys
- Check startup items
- Monitor for new services

---

### 4. Backdoor Accounts

**What they do:**
- Create hidden user accounts
- Add themselves to admin groups
- Create service accounts with high privileges

**How to detect:**
```bash
# Linux - users with UID >= 1000
awk -F: '$3 >= 1000 {print $1, $3}' /etc/passwd

# Linux - users in sudo/wheel group
getent group sudo wheel

# Windows - Domain Admins
Get-ADGroupMember -Identity "Domain Admins"

# Windows - Local Admins
Get-LocalGroupMember -Group "Administrators"
```

**How to defend:**
- Audit all user accounts
- Remove unknown users
- Check group memberships
- Monitor for user creation events

---

### 5. Network-Based Attacks

**What they do:**
- ARP spoofing / MITM
- DNS poisoning
- Rogue DHCP
- Port scanning
- Sniffing credentials

**How to detect:**
```bash
# Check ARP table for duplicates
arp -a | sort | uniq -d

# Check for rogue DHCP
# Multiple DHCP servers responding

# Network connections
ss -tnp
netstat -tnp
```

**How to defend:**
- Enable ARP inspection (if available)
- Static ARP entries for critical systems
- Encrypt everything (HTTPS, SSH)
- Monitor network traffic

---

### 6. Service Disruption

**What they do:**
- Stop critical services
- Corrupt configuration files
- Fill disk space
- Fork bombs / resource exhaustion
- Delete critical files

**How to detect:**
- Service monitoring scripts
- Disk space alerts
- Process monitoring

**How to defend:**
- Backup configurations
- Monitor service status
- Set up auto-restart for critical services
- Monitor disk usage

---

## Red Team Tools to Watch For

| Tool | Purpose | Detection |
|------|---------|-----------|
| Mimikatz | Credential dumping | Process name, LSASS access |
| PSExec | Remote execution | Event 7045, network shares |
| Cobalt Strike | C2 framework | Beaconing, named pipes |
| Metasploit | Exploitation | Known exploits, meterpreter |
| Nmap | Scanning | SYN floods, port probes |
| Hydra/Medusa | Brute force | Rapid auth failures |
| Responder | LLMNR/NBT-NS poisoning | Rogue responses |
| BloodHound | AD recon | LDAP queries |
| CrackMapExec | AD attacks | SMB/WinRM activity |

**Detection searches:**
```
# Splunk - Known bad process names
index=* (mimikatz OR psexec OR meterpreter OR beacon)

# Splunk - Suspicious PowerShell
index=* sourcetype="WinEventLog:*PowerShell*"
| where match(ScriptBlockText, "(?i)invoke-mimikatz|invoke-psexec|downloadstring")
```

---

## Incident Response Quick Actions

### Confirmed Compromise

1. **DON'T PANIC** - Think before acting
2. **Document** - Screenshot, note time
3. **Isolate if needed** - But don't break scoring
4. **Identify scope** - What did they access?
5. **Remove access** - Disable accounts, block IPs
6. **Remove persistence** - Cron, tasks, services
7. **Change credentials** - Assume they have all passwords
8. **Monitor** - They will try to get back in

### Active Attack in Progress

1. **Block the source IP** immediately
2. **Kill malicious processes**
3. **Preserve evidence** (screenshot, logs)
4. **Notify team captain**
5. **Check for lateral movement**

---

## Hunting Queries

### Splunk Threat Hunting

```spl
# Unusual outbound connections
index=* dest_port!=80 dest_port!=443 dest_port!=22 dest_port!=53
| stats count by src_ip, dest_ip, dest_port
| where count < 10

# Commands with encoded content
index=* ("powershell" OR "bash" OR "sh") ("base64" OR "-enc" OR "-e ")

# Large data transfers
index=* | stats sum(bytes_out) as total by src_ip, dest_ip
| where total > 10000000

# Processes spawned by web server
index=* parent_process_name IN ("httpd", "apache2", "nginx", "w3wp.exe")
| stats count by process_name, cmdline

# Lateral movement indicators
index=* (EventCode=4648 OR EventCode=4624 Logon_Type=3)
| stats count by src_ip, dest_ip, user
```

---

## Remember

1. **They already have access** - Your job is to find and remove it
2. **Speed matters** - The faster you harden, the less time they have
3. **Assume breach** - Verify everything
4. **Defense in depth** - Multiple layers of protection
5. **Monitor constantly** - Someone should always be watching
6. **Stay calm** - Mistakes happen when you panic
