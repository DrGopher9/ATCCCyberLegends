# CRITICAL: Triage (First 15 Mins)

**Assumptions:** You are in a Netlab Console. Copy/Paste might be broken. Internet might be down.

## 1. STOP THE BLEEDING (The "Golden 4")
*Execute these immediately. Do not wait for permission.*

### Linux (Any Distro)
1. **Change Root Pass:**
   `passwd`
2. **Find Nasty Users (UID 0):**
   `grep :0: /etc/passwd`
   *(If you see anything other than `root`, kill it)*
3. **Block Inbound Traffic (Save SSH):**
   `iptables -P INPUT DROP`
   `iptables -A INPUT -p tcp --dport 22 -j ACCEPT`
   `iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`
4. **Spot Beacons:**
   `ss -tulpn`
   *(Look for weird high ports like 4444, 6666, 1337)*

### Windows (PowerShell)
1. **Change Admin Pass:**
   `net user Administrator "Sup3rH@rdP@ss!99"`
2. **Enable Firewall:**
   `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True`
3. **Check Current Admins:**
   `Get-LocalGroupMember -Group "Administrators"`
4. **See Running Connections:**
   `netstat -ano | findstr ESTABLISHED`

---

## 2. PERSISTENCE HUNTING
*Red Team usually hides here.*

### Linux Locations
* `crontab -l` (Check current user tasks)
* `cat /etc/crontab` (Check system tasks)
* `ls -al /var/www/html` (Web shells often look like `shell.php`)
* `ls -lt /tmp/` (Look for recent files dropped in temp)

### Windows Locations
* **Startup Folder:** `shell:startup` (Type this in Run box `Win+R`)
* **Scheduled Tasks:** `Get-ScheduledTask | Where State -eq 'Ready'`
* **Registry Run Keys:**
    `Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run`

---

## 3. "OH SNAP" RECOVERY
*If you lock yourself out, type this to reset.*

* **Linux Firewall Flush:**
    `iptables -F`
    `iptables -P INPUT ACCEPT`
* **Windows Firewall Off:**
    `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False`