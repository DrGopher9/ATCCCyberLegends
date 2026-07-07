# Week 9 — Lab Exercises: Hardening & Host Firewalls

The rule of the week: **Manual → Script → Verify → Rollback.** Back up before you change anything. After
every change, prove the scored service still works. Keep a second session open. There is no revert in
competition, so your rollback is whatever *you* can do by hand.

**Prereqs:** a lab box you may harden/restore; know its scored service + port (from
[`../07-competition-reference.md`](../07-competition-reference.md)).

---

## Exercise 1 — Back up FIRST
```bash
# Linux: snapshot the config you're about to touch
sudo mkdir -p /root/backup_$(date +%H%M)
sudo cp -a /etc/ssh/sshd_config /root/backup_*/ 2>/dev/null
sudo iptables-save | sudo tee /root/backup_*/iptables.rules >/dev/null
```
```powershell
# Windows: export current firewall rules
netsh advfirewall export "C:\backup_fw.wfw"
```
You can't roll back what you didn't save.

## Exercise 2 — Write a host firewall rule BY HAND (`T2-C4`)
Allow the box's scored service, keep ICMP, deny the rest. Example for a web box (port 80/443):
```bash
# Linux (ufw):
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp                 # keep your own admin access!
# ICMP stays up (ufw allows it by default; do NOT add a blanket icmp drop)
sudo ufw --force enable
sudo ufw status verbose
```
```powershell
# Windows (DNS box example, port 53):
New-NetFirewallRule -DisplayName "Allow DNS" -Direction Inbound -Protocol UDP -LocalPort 53 -Action Allow
New-NetFirewallRule -DisplayName "Allow DNS TCP" -Direction Inbound -Protocol TCP -LocalPort 53 -Action Allow
# Keep RDP for your own access; keep ICMP echo:
New-NetFirewallRule -DisplayName "Allow ICMPv4" -Protocol ICMPv4 -IcmpType 8 -Action Allow
```
> **Two traps:** (1) don't lock out your own admin port (22/3389); (2) don't blanket-drop ICMP — the
> scoring engine needs it (except the PA core port).

## Exercise 3 — VERIFY the service still works (`T2-C6`)
Immediately after the rule:
```bash
ss -tlnp | grep <port>                # still listening?
curl -I http://localhost/              # web: real response?
ping -c2 <another-host>                # ICMP still flowing?
```
Mail box: log in via the webmail / test POP3. DNS box: `nslookup google.com <dns-ip>`. If the service
dropped, your rule is wrong — fix it now.

## Exercise 4 — Run a repo hardening script, and EXPLAIN it (`T2-C5`)
Read the script's header first, then run it:
```bash
# e.g. Ubuntu:
less CCDC_2026/Linux/Ubuntu/Harden.sh      # what does it change? does it use set -e?
sudo bash CCDC_2026/Linux/Ubuntu/Harden.sh # run it (you backed up in Ex.1)
```
```powershell
# e.g. Windows firewall:
Get-Content CCDC_2026\Windows\Firewall.ps1 | more
.\CCDC_2026\Windows\Firewall.ps1
```
Then, out loud or in writing, **explain three things the script changed.** If you can't, you shouldn't
have run it. Note where it wrote its log/backup.

## Exercise 5 — VERIFY again, then ROLL BACK one change (`T2-C5`)
- Re-verify the scored service (Exercise 3). Still up? Good.
- Now **undo one specific change** the script made — by hand:
```bash
# Example: restore sshd_config from your backup and restart
sudo cp /root/backup_*/sshd_config /etc/ssh/sshd_config
sudo systemctl restart ssh
```
```powershell
# Example: re-import the firewall you exported
netsh advfirewall import "C:\backup_fw.wfw"
```
Confirm the rollback took effect and the service still works.

## Exercise 6 — The self-own drill (do this once, on purpose)
Write a rule that **blocks** the scored service (e.g. deny 80/443, or drop all ICMP). Run your verify
checks and watch them fail. Then fix it. Now you know what a self-inflicted outage *feels* like — so
you catch it in three seconds during a real round.

## Done?
You've hit the objectives if you: backed up, wrote a hand firewall rule that kept the service + ICMP
up, ran a repo script and explained it, rolled back a change, and **verified the service after every
step**. Repeat Exercises 2–5 solo for [`homework.md`](homework.md).
