# Week 8 — Lab Exercises: The Credential Sweep

You'll change real credentials this week. **Before you start: open a SECOND session to the box and keep
it logged in** — that's your safety net if you lock yourself out (there is no revert in competition).
Log every change in the change-log and password-tracker as you go.

**Prereqs:** access to a lab Linux box and a lab Windows box; the default creds from
[`../07-competition-reference.md`](../07-competition-reference.md).

---

## Part 1 — Linux credential sweep (`T2-C1`, `T2-C3`)

Default Linux creds are `sysadmin:changeme` (Ubuntu/Fedora) and `root:changemenow` / `admin:changeme`
(Splunk) — the Red Team has these.

### 1a. See who exists
```bash
# Humans and anyone with a login shell:
awk -F: '$3>=1000 && $3<65534 {print $1, $3}' /etc/passwd
grep -vE 'nologin|false' /etc/passwd
# UID 0 accounts (should be ONLY root):
awk -F: '$3==0 {print $1}' /etc/passwd
```
Flag anything you don't recognize — especially a second UID-0 account.

### 1b. Rotate passwords (keep your second session open!)
```bash
sudo passwd root                     # root — not scored, change freely
sudo passwd sysadmin                 # the known default account
# For each legitimate human account, rotate too:
sudo passwd <user>
```
Record each new password in the [password-tracker](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/password-tracker.md).

### 1c. Disable/remove unknown accounts
```bash
sudo usermod -L unknownuser          # LOCK first (safer than delete — keep for the IR report)
sudo usermod -s /usr/sbin/nologin unknownuser
# Only delete once you're sure it's hostile:
sudo userdel -r unknownuser
```

### 1d. Audit sudo
```bash
sudo grep -vE '^#|^$' /etc/sudoers
sudo ls -la /etc/sudoers.d/ && sudo cat /etc/sudoers.d/* 2>/dev/null
```
Look for unknown users with `NOPASSWD` or `ALL`.

### 1e. SSH keys (`T2-C3`) — a classic backdoor
```bash
for u in $(cut -d: -f1 /etc/passwd); do
  f=$(eval echo ~$u)/.ssh/authorized_keys
  [ -f "$f" ] && echo "=== $u ===" && cat "$f"
done
sudo cat /root/.ssh/authorized_keys 2>/dev/null
```
Remove any key you can't account for (comment out or delete the line). An attacker's key = passwordless
entry that rotating passwords does **not** stop.

---

## Part 2 — Windows credential sweep (`T2-C2`)

Default Windows creds are `administrator:!Password123` (all servers) and `UserOne:ChangeMe123` (Win11).
Elevated PowerShell.

### 2a. See who exists / who's admin
```powershell
Get-LocalUser | Select Name, Enabled
Get-LocalGroupMember "Administrators"        # local admins
# On the AD box (READ first — don't disable AD users; POP3/mail rides on them):
Get-ADGroupMember "Domain Admins" | Select Name, SamAccountName
```

### 2b. Rotate the admin password (keep a second session!)
```powershell
# Local Administrator (not scored — change freely):
$p = Read-Host -AsSecureString "New admin password"
Get-LocalUser Administrator | Set-LocalUser -Password $p
```
Record it in the password-tracker.

### 2c. Disable unknown accounts
```powershell
Disable-LocalUser -Name "sketchyacct"        # disable, don't delete (keep for IR)
```
> **Do NOT bulk-disable AD user accounts** — POP3/mail authenticates against them. Rotate *admin* and
> *service* credentials; leave scored-service user accounts intact and **verify mail still works** if
> you touch any.

### 2d. Scheduled tasks (persistence preview)
```powershell
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select TaskName, TaskPath
```
Note anything unfamiliar — you'll hunt these for real in Phase 2.

---

## Verify + log
- **Verify scored services still work** after the sweep: mail login (Webmail), web (`curl -I`), DNS
  lookup. A sweep that breaks a scored service cost you points.
- Confirm your **change-log** and **password-tracker** are complete.

## Done?
You've hit the objectives if you swept a Linux box (passwords, unknown accounts, sudo, SSH keys) and a
Windows box (admin password, admin audit, unknown accounts), caught the planted account + key, kept a
clean log, and **didn't break a scored service or lock yourself out**. Repeat both sweeps timed for
[`homework.md`](homework.md).
