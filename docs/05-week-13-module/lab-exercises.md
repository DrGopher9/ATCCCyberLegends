# Week 13 — Lab Exercises: Detect the Attack on Your Box

**Observe and detect only — do NOT evict this week.** Capture the evidence (source IP, timeline, what
happened) as if you'll write the incident report, then leave it for Week 14. The red team runs the
attacks; you find them by comparing against your Week-12 baseline.

Each section lists: the **attack** the red team runs, **where to look**, and the **evidence to
capture**.

---

## Common — the detection reflex (every track)
```spl
# Splunk: is something deviating? start broad, then narrow to your host
index=* host=<yourbox> | timechart count by sourcetype
index=* ("Failed password" OR EventCode=4625) host=<yourbox> | stats count by src_ip
```
Then compare live state to your baseline: new listener? new user? new file? new process?

---

## Track: AD/DNS
- **Attack:** password spray / many failed logons, then a suspicious logon; maybe a new Domain Admin or
  a scheduled task.
- **Look:** Security log 4625 (spray) then 4624 (success); `Get-ADGroupMember "Domain Admins"` vs.
  baseline; `Get-ScheduledTask` vs. baseline. Splunk: `EventCode=4625 | stats count by src_ip`.
- **Capture:** source IP, spray window, the account that succeeded, any new privileged member.

## Track: Web/FTP
- **Attack:** a **web shell** dropped in the web root, or an FTP upload / anonymous access.
- **Look:** `Get-ChildItem C:\inetpub\wwwroot` vs. baseline (new `.aspx`/`.php`?); IIS logs
  (`C:\inetpub\logs\LogFiles`) for POSTs to odd files; FTP logs for uploads. Splunk: web access spikes,
  requests to files not in your baseline.
- **Capture:** the dropped file path + timestamp, the source IP, the requests that hit it.

## Track: E-Comm
- **Attack:** web shell / reverse shell (e.g. a new listener on an odd port like 4444), or SQLi against
  the app.
- **Look:** `ss -tlnp` vs. baseline (new listener?); `ls -la /var/www/html` vs. baseline; Apache/Nginx
  access log for suspicious requests; `ps aux` for a shell process. Splunk: web log anomalies.
- **Capture:** the new file/listener, the source IP, the request that planted it.

## Track: Email/Webmail
- **Attack:** auth attack against SMTP/POP3, a mail-relay abuse attempt, or a tampered mailbox/alias.
- **Look:** `/var/log/maillog` for auth failures / relay attempts; `postconf -n` and aliases vs.
  baseline; dovecot auth logs. Splunk: mail auth failure spikes.
- **Capture:** source IP, the accounts targeted, any config/alias change.

## Track: Network
- **Attack:** a rogue allow-rule added, an admin login from an odd source, or a config change on a
  firewall/router.
- **Look:** Palo Alto / Cisco FTD admin + traffic logs; config vs. your Week-12 backup (diff it);
  login events on the devices. Watch that ICMP/scoring flows aren't being tampered with.
- **Capture:** what rule/config changed, when, from where.

## Track: Splunk
- **Attack:** a **forwarder killed** on a host (blinding the team), or a Splunk admin login / config
  poke.
- **Look:** `| metadata type=hosts index=*` — which host went silent and when? Splunk `_audit` /
  `_internal` for admin activity. Compare reporting hosts to your Week-12 baseline.
- **Capture:** which host stopped reporting + timestamp, any admin action.

---

## After you detect (all tracks) — capture, don't evict
Write down, for your box's attack:
- **Source IP**, **timeline** (first seen → last seen), **what the attacker did / was after**, and
  **what was affected**.
This is the raw material for the incident report you'll write for real in Week 14 / Phase 3. Leave the
foothold in place for now.

## Done?
You've hit the objective if you detected your box's attack from your baseline + Splunk, named the
technique, and captured source IP + timeline — **without evicting.** Practice the detection searches
solo for [`homework.md`](homework.md).
