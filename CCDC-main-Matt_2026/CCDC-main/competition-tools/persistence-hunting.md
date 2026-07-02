# CCDC Persistence Hunting Checklist

## Use This Checklist on EVERY System

Red team has pre-planted backdoors. Find them before they use them.

---

## Linux Persistence Checklist

### 1. User Accounts
```bash
# List all users with shells
grep -v "nologin\|false" /etc/passwd

# Users with UID 0 (root equivalents)
awk -F: '$3 == 0 {print $1}' /etc/passwd

# Recently created users
ls -lt /home/

# Check for hidden users (UID in normal range but hidden)
awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $3}' /etc/passwd
```

**Look for:** Unknown users, users with UID 0 that aren't root

### 2. SSH Authorized Keys
```bash
# Check all users
for user in $(cut -d: -f1 /etc/passwd); do
  keyfile=$(eval echo ~$user)/.ssh/authorized_keys
  if [ -f "$keyfile" ]; then
    echo "=== $user ==="
    cat "$keyfile"
  fi
done

# Also check root
cat /root/.ssh/authorized_keys
```

**Look for:** Unknown keys, keys with suspicious comments

### 3. Sudo Configuration
```bash
# Main sudoers
cat /etc/sudoers | grep -v "^#" | grep -v "^$"

# Sudoers.d files
ls -la /etc/sudoers.d/
cat /etc/sudoers.d/*
```

**Look for:** Unknown users with NOPASSWD, suspicious commands allowed

### 4. Cron Jobs
```bash
# System crontabs
cat /etc/crontab
ls -la /etc/cron.d/
cat /etc/cron.d/*

# User crontabs
for user in $(cut -d: -f1 /etc/passwd); do
  crontab -u $user -l 2>/dev/null | grep -v "^#" | grep -v "^$" && echo "^^^ $user ^^^"
done

# Cron directories
ls -la /etc/cron.hourly/
ls -la /etc/cron.daily/
ls -la /var/spool/cron/
```

**Look for:** Reverse shells, wget/curl commands, encoded commands

### 5. Systemd Services
```bash
# List all enabled services
systemctl list-unit-files --type=service --state=enabled

# List running services
systemctl list-units --type=service --state=running

# Check for custom services
ls -la /etc/systemd/system/
ls -la /usr/lib/systemd/system/*.service | xargs grep -l "ExecStart"

# Find recently modified service files
find /etc/systemd /usr/lib/systemd -name "*.service" -mtime -7
```

**Look for:** Services with suspicious ExecStart commands, unknown services

### 6. Init Scripts
```bash
ls -la /etc/init.d/
ls -la /etc/rc.local
cat /etc/rc.local
```

### 7. Shell Profiles (Backdoor on Login)
```bash
# System-wide
cat /etc/profile
cat /etc/bash.bashrc
ls -la /etc/profile.d/

# User-specific
for home in /home/* /root; do
  for file in .bashrc .bash_profile .profile; do
    if [ -f "$home/$file" ]; then
      echo "=== $home/$file ==="
      cat "$home/$file" | grep -v "^#" | grep -v "^$"
    fi
  done
done
```

**Look for:** Reverse shell commands, suspicious aliases, curl/wget

### 8. Web Shells
```bash
# Find PHP files in web root
find /var/www -name "*.php" -type f

# Recently modified PHP files
find /var/www -name "*.php" -mtime -7

# Files with suspicious functions
grep -rl "eval\|base64_decode\|shell_exec\|system\|passthru\|exec(" /var/www/

# Files in upload directories
find /var/www -path "*upload*" -name "*.php"
find /var/www -path "*tmp*" -name "*.php"

# Hidden files
find /var/www -name ".*" -type f
```

### 9. SUID/SGID Binaries
```bash
# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find SGID binaries
find / -perm -2000 -type f 2>/dev/null
```

**Look for:** Unusual SUID binaries in /tmp, /home, or web directories

### 10. Network Backdoors
```bash
# Listening ports
ss -tlnp

# Established connections
ss -tnp state established

# Check for netcat listeners
ps aux | grep -E "nc|ncat|netcat"

# Check iptables for port redirects
iptables -L -n -t nat
```

---

## Windows Persistence Checklist

### 1. User Accounts
```powershell
# All local users
Get-LocalUser

# Users in Administrators group
Get-LocalGroupMember -Group "Administrators"

# Domain Admins (if DC)
Get-ADGroupMember -Identity "Domain Admins"

# Recently created users
Get-LocalUser | Where-Object {$_.Enabled -eq $true} | Select Name, LastLogon
```

### 2. Scheduled Tasks
```powershell
# All scheduled tasks (non-Microsoft)
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"} |
  Select TaskName, TaskPath, State

# Task details
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"} |
  ForEach-Object { $_ | Get-ScheduledTaskInfo }

# Check specific task
Get-ScheduledTask -TaskName "TASKNAME" | Select *
(Get-ScheduledTask -TaskName "TASKNAME").Actions
```

### 3. Services
```powershell
# Running services (non-standard)
Get-Service | Where-Object {
  $_.Status -eq 'Running' -and
  $_.DisplayName -notlike "Windows*" -and
  $_.DisplayName -notlike "Microsoft*"
}

# Service binary paths
Get-WmiObject win32_service | Select Name, PathName, StartMode, State |
  Where-Object {$_.StartMode -eq "Auto"}
```

### 4. Run Keys (Auto-Start)
```powershell
# HKLM Run keys
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

# HKCU Run keys
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

# Wow6432Node (32-bit on 64-bit)
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
```

### 5. Startup Folder
```powershell
# System startup
Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

# User startup
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
```

### 6. WMI Subscriptions
```powershell
# Event Filters
Get-WMIObject -Namespace root\Subscription -Class __EventFilter

# Event Consumers
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer

# Filter-to-Consumer Bindings
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
```

### 7. PowerShell Profiles
```powershell
# Check all profile locations
$PROFILE | Select *
Test-Path $PROFILE.AllUsersAllHosts
Test-Path $PROFILE.AllUsersCurrentHost
Test-Path $PROFILE.CurrentUserAllHosts
Test-Path $PROFILE.CurrentUserCurrentHost

# Read profiles if they exist
Get-Content $PROFILE.AllUsersAllHosts -ErrorAction SilentlyContinue
Get-Content $PROFILE.CurrentUserAllHosts -ErrorAction SilentlyContinue
```

### 8. DLL Hijacking
```powershell
# Check common hijack locations
Get-ChildItem "C:\Windows\System32\*.dll" -ErrorAction SilentlyContinue |
  Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)}

# Check PATH directories for rogue DLLs
$env:PATH -split ";" | ForEach-Object {
  Get-ChildItem "$_\*.dll" -ErrorAction SilentlyContinue
}
```

### 9. Group Policy
```powershell
# Startup scripts
Get-ChildItem "C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup"
Get-ChildItem "C:\Windows\System32\GroupPolicy\User\Scripts\Logon"
```

### 10. Network Backdoors
```powershell
# Listening ports
Get-NetTCPConnection -State Listen | Select LocalPort, OwningProcess |
  ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{Port=$_.LocalPort; Process=$proc.Name; PID=$_.OwningProcess}
  }

# Established connections
Get-NetTCPConnection -State Established | Where-Object {$_.RemoteAddress -notmatch "^(127\.|10\.|172\.|192\.168)"}
```

---

## Quick Sweep Script (Linux)

```bash
#!/bin/bash
echo "=== PERSISTENCE HUNT ==="
echo ""
echo "=== Users with shells ==="
grep -v "nologin\|false" /etc/passwd
echo ""
echo "=== UID 0 accounts ==="
awk -F: '$3 == 0 {print}' /etc/passwd
echo ""
echo "=== SSH Keys ==="
cat /root/.ssh/authorized_keys 2>/dev/null
for d in /home/*; do cat "$d/.ssh/authorized_keys" 2>/dev/null && echo "^^^ $d ^^^"; done
echo ""
echo "=== Cron Jobs ==="
cat /etc/crontab | grep -v "^#"
ls /etc/cron.d/
for u in $(cut -d: -f1 /etc/passwd); do crontab -u $u -l 2>/dev/null; done
echo ""
echo "=== Listening Ports ==="
ss -tlnp
echo ""
echo "=== Recent PHP files ==="
find /var/www -name "*.php" -mtime -2 2>/dev/null
echo ""
echo "=== Suspicious processes ==="
ps aux | grep -E "nc |ncat|netcat|python.*-c|perl.*-e"
```

---

## Priority Order

1. **SSH Keys** - Instant access
2. **User Accounts** - Easy to miss
3. **Cron Jobs** - Time-delayed backdoors
4. **Web Shells** - Common in web servers
5. **Scheduled Tasks** - Windows equivalent of cron
6. **Services** - Persistent and hidden
7. **Run Keys** - Auto-start on login
8. **Everything Else** - As time permits

---

## When You Find Something

1. **Document it** - Screenshot, note location
2. **Remove it** - Delete/disable
3. **Log it** - Record in change log
4. **Check for more** - Rarely just one backdoor
5. **Change credentials** - Assume they were used
6. **Monitor** - They may try to re-establish
