# Week 11 — Lab Exercises: The IR Cycle + Incident Reports

You'll run a full incident response cycle on a planted intrusion, then write the report that scores.
Golden rule: **note the evidence before you evict it** (no revert in competition), and **contain
without breaking a scored service.**

**Prereqs:** Weeks 8–10 skills; a box the facilitator has "compromised"; the report format in
[`inject-templates.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/inject-templates.md).

---

## Exercise 1 — DETECT
Find the intrusion using what you built in Weeks 8–10:
```spl
# Splunk: failed-login spike / odd source
index=* ("Failed password" OR EventCode=4625) | stats count by src_ip, host | sort -count
```
```bash
# On the box: odd processes, listeners, new accounts, recent files
ps aux --sort=-%cpu | head
sudo ss -tlnp
awk -F: '$3>=1000 {print $1,$3}' /etc/passwd
sudo find / -newermt "-2 hours" -type f 2>/dev/null | grep -vE '/proc|/sys' | head
```
Write down what you see: **source IP, what's wrong, when, which box.** This is your evidence — capture
it now.

## Exercise 2 — CONTAIN (without self-owning)
Stop the bleeding, keep scored services up:
```bash
# Block the hostile source (NOT a range that could include the scoring engine):
sudo ufw deny from <attacker_ip>
# Kill the active hostile session/process:
sudo pkill -u <baduser>
sudo kill -9 <pid>
# Disable (don't delete yet) the account:
sudo usermod -L <baduser>
```
Then **verify the scored service still works** (Week 9 reflex). Containment that drops the service is a
self-own.

## Exercise 3 — EVICT
Remove the foothold for good:
```bash
# Remove the planted account + its home, the SSH key, the cron/task, the dropped file:
sudo userdel -r <baduser>
sudo crontab -l -u <baduser> 2>/dev/null   # check before removing
# remove unauthorized authorized_keys line, malicious file, etc.
```
Windows equivalents: `Remove-LocalUser`, remove the scheduled task, delete the dropped binary. Re-scan
(Exercise 1) to confirm it's gone.

## Exercise 4 — DOCUMENT: change-log (`T2-I2`)
Log every action you just took in the [change-log](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/change-log.md):
time, system, what you changed, who did it, result. If it's not logged, it didn't happen (and you
can't undo or explain it).

## Exercise 5 — DOCUMENT: incident report (`T2-I3`) — the scored part
Write a report with **exactly** the packet's required contents:
- **Source & destination IPs**
- **Timeline** of the activity
- **Passwords cracked** (if any)
- **What was affected**
- **Remediation plan** (what you did / will do)

Rules: focus on the **exploitation event, not misconfiguration**; be clear, thorough, accurate; **one
report per real event — don't pad.** Save it as a PDF (that's the real submission format).

> A good report is ~1 page, specific, and reads like a professional wrote it. Compare yours to the
> template; cut anything frivolous.

## Exercise 6 — Verify you're clean
- Re-run the detection searches — is the foothold gone?
- Confirm all scored services on the box still work.
- Confirm the change-log and report are complete.

## Done?
You've hit the objectives if you ran the full cycle (detect → contain → evict → document), kept a clean
change-log, and wrote a spec-compliant, non-padded incident report — **without breaking a scored
service.** Practice writing one more report solo for [`homework.md`](homework.md).
