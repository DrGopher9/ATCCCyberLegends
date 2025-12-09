# Linux Hardening (Ubuntu & Red Hat)

**Goal:** Secure the box without breaking scoring services.

## 1. Quick Distro Check
*Not sure what OS you are on? Run this:*
`cat /etc/os-release`

---

## 2. Universal Hardening (All Distros)
*These commands work on Ubuntu, Fedora, and Oracle.*

### User Management
* **Lock Root:** `sudo passwd -l root`
* **Lock Suspicious User:** `sudo passwd -l [username]`
* **Find Empty Passwords:** `awk -F: '($2 == "") {print}' /etc/shadow`

### SSH Config (`/etc/ssh/sshd_config`)
* **Disable Root Login:** Change to `PermitRootLogin no`
* **Disable Empty Passwords:** Change to `PermitEmptyPasswords no`
* **Restart SSH:** `sudo systemctl restart sshd`

### Audit Persistence
* **Check Cron:** `crontab -l` and `cat /etc/crontab`
* **Check Sudoers:** `visudo` (Look for `NOPASSWD` lines!)

---

## 3. The "Red Hat" Family (Fedora, Oracle 9, CentOS)
*Used for: Webmail, Splunk*

### Package Manager: DNF / YUM
* **Update System:** `sudo dnf update --security`
* **Install Tools:** `sudo dnf install nmap tmux`
* **Remove Tools:** `sudo dnf remove netcat nc`

### Firewall: FirewallD (Crucial!)
*Red Hat does NOT use UFW. It uses FirewallD.*
* **Check Status:** `systemctl status firewalld`
* **Allow Service (Temporary):** `firewall-cmd --add-service=http`
* **Allow Port (Permanent):** `firewall-cmd --permanent --add-port=80/tcp`
* **Block IP:** `firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='1.2.3.4' reject"`
* **Apply Changes:** `firewall-cmd --reload`
* **Panic Mode (Stop Firewall):** `systemctl stop firewalld`

### SELinux (The "Shield")
* **Check Status:** `sestatus` (Should say "Enforcing")
* **Turn On:** `setenforce 1`
* *Note: If services break, check logs: `tail -f /var/log/audit/audit.log`*

---

## 4. The "Debian" Family (Ubuntu 24)
*Used for: Ecom, Workstations*

### Package Manager: APT
* **Update System:** `sudo apt update && sudo apt upgrade`
* **Install Tools:** `sudo apt install nmap`

### Firewall: UFW (Uncomplicated Firewall)
* **Status:** `sudo ufw status verbose`
* **Allow SSH:** `sudo ufw allow ssh` (DO THIS FIRST)
* **Allow Web:** `sudo ufw allow 80/tcp`
* **Block IP:** `sudo ufw deny from 1.2.3.4`
* **Enable:** `sudo ufw enable`

---

## 5. Service Control (Systemd)
*Works on ALL your Linux machines.*

* **List Running Services:**
    `systemctl list-units --type=service --state=running`
* **Stop a Service:**
    `sudo systemctl stop [service_name]`
* **Disable (Prevent Start):**
    `sudo systemctl disable [service_name]`