# Week 15 — Lab Exercises: Persistence Hunting

The red team pre-planted backdoors on your box. Find and evict **all** of them — then prove nothing
respawns. Work the checklist systematically (every class, in order); that's what catches the boring
backdoor. Verify the scored service after eviction. Full reference:
[`persistence-hunting.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/persistence-hunting.md).

---

## Common — the persistence checklist (Linux)
```bash
# 1. Accounts (backdoor users / extra UID 0)
awk -F: '$3==0 {print $1}' /etc/passwd
awk -F: '$3>=1000 {print $1,$3}' /etc/passwd            # vs. your baseline
# 2. SSH keys (all users + root)
for u in $(cut -d: -f1 /etc/passwd); do f=$(eval echo ~$u)/.ssh/authorized_keys; [ -f "$f" ] && echo "== $u ==" && cat "$f"; done
sudo cat /root/.ssh/authorized_keys 2>/dev/null
# 3. Cron (all users + system)
sudo cat /etc/crontab; sudo ls -la /etc/cron.*; for u in $(cut -d: -f1 /etc/passwd); do sudo crontab -l -u $u 2>/dev/null | sed "s/^/$u: /"; done
# 4. Services + startup
systemctl list-unit-files --state=enabled | grep -vi '@'   # unexpected enabled units?
ls -la /etc/systemd/system/ /etc/rc.local 2>/dev/null
# 5. Odd listeners / processes vs. baseline
sudo ss -tlnp; ps aux --sort=-%cpu | head
```

## Common — the persistence checklist (Windows)
```powershell
Get-LocalGroupMember Administrators                       # backdoor admin?
Get-ScheduledTask | ? State -ne Disabled | Select TaskName,TaskPath   # scheduled-task persistence
Get-CimInstance Win32_StartupCommand | Select Name,Command,Location    # run keys / startup
Get-Service | ? {$_.StartType -eq 'Automatic'}           # rogue auto service?
Get-CimInstance Win32_Service | Select Name,PathName | ? PathName -match 'temp|users|\.ps1|\.bat'
```

> **Eviction rule:** remove the mechanism, not just the symptom. Kill the process AND the cron/task that
> restarts it. After removing, **re-run the checklist** — did anything come back?

---

## Track add-ons (hunt these too)

- **AD/DNS:** new Domain Admin / delegation, malicious GPO (login script / scheduled task via GPO),
  AdminSDHolder abuse, rogue DNS records. `Get-ADGroupMember`, `Get-GPO -All`, GPO scheduled-task XML.
- **Web/FTP:** web shell in `wwwroot`, rogue IIS handler/module, backdoor FTP user, an auto-start task
  re-dropping the shell. Diff `wwwroot` vs. baseline; `Get-WebManagedModule`.
- **E-Comm:** web/reverse shell, cron respawner, malicious systemd unit, DB trigger/user backdoor,
  `.htaccess` shells. Diff `/var/www/html`; check DB users.
- **Email/Webmail:** backdoor alias/`.forward`, rogue transport rule, webmail plugin backdoor,
  cron/service respawner. Diff aliases + `postconf -n` vs. baseline.
- **Network:** rogue admin account on a device, an allow-rule that re-appears, a config-restore job,
  scheduled commit of a bad config. Diff each config vs. your backup.
- **Splunk:** a scripted input running attacker code, a rogue user/role, a forwarder pointed elsewhere,
  a startup script. Check `inputs.conf` scripted inputs, Splunk users/roles.

---

## Prove it's clean (all tracks)
1. Re-run the full checklist — nothing unexpected remains.
2. Wait/re-check — nothing respawns (no cron/task/service brings a backdoor back).
3. Your Week-14 detection is quiet (no active attacker).
4. The scored service still works.
5. Write the incident report for what you found (source/impact/remediation) — practice for Phase 3.

## Done?
You've hit the objective if you found and evicted every planted persistence mechanism on your box, it
stays clean on re-check, and the service still scores. Drill the full checklist solo for
[`homework.md`](homework.md) before the gate.
