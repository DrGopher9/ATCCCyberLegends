# Week 3 — Lab Exercises: Services, systemd, Logs, Packages

Work on a lab **Linux** box you're allowed to break and fix (Ubuntu Ecom `172.20.242.30` has a real
web service). You'll intentionally stop and restart services — that's expected here. Most commands need
`sudo`.

**Prereqs:** shell on a lab Linux box; know the service name you're targeting (ask the facilitator —
often `apache2`/`nginx` on Ecom, or `ssh`).

---

## Exercise 1 — Inspect a service
```bash
systemctl status ssh              # is it running? enabled at boot?
systemctl is-active ssh           # active / inactive
systemctl is-enabled ssh          # enabled / disabled
systemctl list-units --type=service --state=running | head   # what's running
```
Read the `status` output: **Active:** line, main **PID**, and the recent log lines at the bottom.

## Exercise 2 — Stop, start, restart
Pick a *safe* service the facilitator names (e.g. the web server on Ecom):
```bash
sudo systemctl stop  <service>
systemctl is-active <service>     # inactive
sudo systemctl start <service>
systemctl is-active <service>     # active
sudo systemctl restart <service>
```
> In competition, `restart` is your fastest fix when a scored service hiccups. But always follow up by
> **verifying it actually serves** (Exercise 5), not just that it's "active."

## Exercise 3 — Read the logs
```bash
journalctl -u <service> -n 50 --no-pager    # last 50 lines for this service
journalctl -xe --no-pager | tail -40         # recent errors, explained
sudo tail -n 30 /var/log/syslog 2>/dev/null || sudo tail -n 30 /var/log/messages
sudo tail -n 30 /var/log/auth.log 2>/dev/null || sudo tail -n 30 /var/log/secure
```
`auth.log`/`secure` is where failed logins show up — you'll live in that file during competition.

## Exercise 4 — Break it, then recover it (the important one)
Have the facilitator break the service (or do it yourself in a way you can undo). Then, **without
guessing**, diagnose from logs and recover:
```bash
systemctl status <service>        # what does it say?
journalctl -u <service> -n 40 --no-pager   # WHY did it fail? read here first
# ...fix the cause it points to (config typo, wrong port, missing dependency)...
sudo systemctl restart <service>
systemctl is-active <service>     # back to active?
```
Recovering a service by *reading its log* — not by trial and error — is the skill.

## Exercise 5 — Verify it actually works
```bash
ss -tlnp | grep <port>            # is it listening on the right port?
curl -I http://localhost/          # for a web service: real response?
```
"Active" is not the same as "serving." Always confirm the second.

## Exercise 6 — Patch
```bash
# Ubuntu/Debian:
sudo apt update && sudo apt -y upgrade
# Fedora/Oracle (dnf):  sudo dnf -y update
```
Then re-run Exercise 5 to confirm the service still serves after patching. That "patch → verify" habit
is what keeps you from dropping a scored service in competition.

## Done?
You've hit the objectives if you can: check/stop/start/restart a service, read its logs, **recover a
broken service from its log**, verify it serves, and patch. Repeat Exercise 4 solo for
[`homework.md`](homework.md) until recovery is quick.
