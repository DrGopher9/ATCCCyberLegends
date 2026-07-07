# Week 12 — Lab Exercises: Own Your Box (Baseline)

Everyone does the **Common** part, then only **your track's** section. Output: a one-page baseline you'll
compare against when the red team attacks next week. Back up your config before you finish.

**Prereqs:** your assigned box + creds ([`../07-competition-reference.md`](../07-competition-reference.md));
Phase 0/1 skills.

---

## Common (every track)
Document your box's normal state:
```bash
# Linux boxes:
hostnamectl; ip a                     # who/where am I
ss -tlnp                              # every listener (memorize these — normal = this list)
ps aux --sort=-%cpu | head -20        # normal processes
awk -F: '$3>=1000 {print $1}' /etc/passwd   # normal users
systemctl list-units --type=service --state=running
```
```powershell
# Windows boxes:
Get-NetTCPConnection -State Listen | Sort LocalPort
Get-Service | ? Status -eq Running
Get-LocalUser; Get-LocalGroupMember Administrators
```
Write down: **what listens, what runs, who logs in — when everything is healthy.** Then **back up**
(configs, firewall state, or a service config export). Know where the backup is.

---

## Track: AD/DNS (Server 2019 `172.20.240.102`)
```powershell
Get-ADDomain; Get-ADGroupMember "Domain Admins"        # baseline the crown jewels
Get-ADUser -Filter * | Measure-Object                   # account count (these back POP3 auth)
Get-DnsServerZone; Get-DnsServerResourceRecord -ZoneName <zone> | Select -First 20   # DNS baseline
Get-GPO -All | Select DisplayName                       # GPO baseline
```
Break/recover: stop and start the **DNS** service; confirm `nslookup` works after. Note: never break AD
auth — mail depends on it.

## Track: Web/FTP (IIS `.101`, FTP `.104`)
```powershell
Get-Website; Get-WebBinding                             # IIS sites/bindings (HTTP 80 / HTTPS 443)
Get-ChildItem C:\inetpub\wwwroot                        # web root — know what SHOULD be here
Get-Service W3SVC, FTPSVC                                # web + FTP services
```
Break/recover: `Restart-Service W3SVC`, verify with `curl -I http://<.101>/`. Baseline the FTP config +
allowed users. Note the web root file list — an extra file next week = web shell.

## Track: E-Comm (Ubuntu `172.20.242.30`)
```bash
systemctl status apache2 2>/dev/null || systemctl status nginx    # web server
ls -la /var/www/html                                     # web root baseline
sudo ss -tlnp | grep -E ':80|:443|:3306'                 # web + DB listeners
mysql -e "show databases;" 2>/dev/null || sudo -u postgres psql -l   # DB baseline
```
Break/recover: restart the web server; verify with `curl -I http://<.30>/`. Note the web root contents
and the DB name/users — the app's normal footprint.

## Track: Email/Webmail (Fedora `172.20.242.40`)
```bash
systemctl status postfix dovecot 2>/dev/null            # SMTP + POP3/IMAP daemons
sudo ss -tlnp | grep -E ':25|:110|:143|:993|:995'        # mail listeners
sudo postconf -n | head -30                              # postfix config baseline
ls -la /var/mail 2>/dev/null; sudo doveadm user '*' 2>/dev/null   # mailboxes/users
```
Break/recover: restart postfix/dovecot; verify SMTP banner on 25 and a POP3 login on 110. Remember POP3
auth uses **AD** usernames — coordinate with the AD owner.

## Track: Network (Palo Alto, Cisco FTD, VyOS)
```
# Palo Alto (GUI https://172.20.242.150 or CLI): show the security policy, zones, interfaces
show running security-policy
# Cisco FTD (GUI https://172.20.240.200): baseline access control policy
# VyOS: show configuration
```
Back up **all three** configs now (export/commit-save). Baseline: which zones, which allow rules, where
the scoring traffic flows. Note the ICMP posture (must stay up except the PA core port).

## Track: Splunk (Oracle Linux / Splunk `172.20.242.20`)
```bash
sudo /opt/splunk/bin/splunk status                       # is Splunk up?
| metadata type=hosts index=*                            # (in UI) which hosts report — the baseline
sudo /opt/splunk/bin/splunk list forward-server 2>/dev/null
```
Baseline: which hosts SHOULD be reporting (all of them), the dashboards present, and the Splunk admin
accounts. A host dropping off next week = a blinded box.

---

## Done?
You've hit the objective if you produced a one-page baseline of your box (listeners, processes, users,
config, scored components), can break+recover each scored service, and have a config backup. Refine it
solo for [`homework.md`](homework.md) — you'll need it the moment the red team arrives.
