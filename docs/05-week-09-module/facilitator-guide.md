# Week 9 — Facilitator Guide: Hardening & Host Firewalls (Manual → Script → Verify → Rollback)

> **Phase 1, Week 9.** Built from [`../templates/module-template.md`](../templates/module-template.md).

**Rubric targets:** `T2-C4` (write a host firewall rule by hand without breaking the service), `T2-C5`
(run a repo hardening script and explain + roll it back), `T2-C6` (verify a scored service after any
change). See [`../02-readiness-rubric.md`](../02-readiness-rubric.md).

**Council lens:** the Blue Teamer owns this week, with the phase's hardest rule: **manual first, then
the script; always verify the scored service survived; always know the rollback.** No member runs a
hardening script they can't explain and can't reverse. A too-aggressive rule that blocks the scoring
engine is a self-inflicted outage — the Red Team doesn't even have to show up.

**You need:** lab Linux + Windows boxes you can harden and restore, the repo hardening scripts (paths
below), and the scored-service list from [`../07-competition-reference.md`](../07-competition-reference.md).

---

## Learning objectives
By end of the weeknight session, every member can:
1. Write a host firewall rule **by hand** that allows a scored service and denies the rest — without
   breaking the service or ICMP.
2. Back up a box's config, run a repo hardening script, and **explain what it changed**.
3. **Roll back** a specific hardening change.
4. **Verify** the scored service still works after every change (the reflex that prevents self-owns).

By the weekend lab, every member hardens a box end-to-end and restores it, with the service still
scoring throughout.

## The rule of the week (say it every session)
> **Manual → Script → Verify → Rollback.** Understand the change by hand first. Back up before you run
> anything. After every change, prove the scored service still works. Know how to undo it *before* you
> do it.

## Weeknight session plan (2–3 hr)
- **0:00–0:15 — Warm-up:** Week 8 credential sweep, one box, timed (keeps `T2-C1/C2` warm).
- **0:15–0:45 — Concept + demo (manual firewall):** on Linux, `ufw`/`iptables` — allow the box's scored
  ports, keep **ICMP up (except the PA core port)**, deny the rest. On Windows, `New-NetFirewallRule`.
  Demo writing one rule and testing it. Show the repo [`iptables.sh`](../../CCDC_2026/Linux/iptables.sh)
  and [`Firewall.ps1`](../../CCDC_2026/Windows/Firewall.ps1) as the "understood accelerator," not magic.
- **0:45–1:05 — Concept + demo (backup + rollback):** back up before hardening (configs, firewall
  state); how to reverse one change. Point at the repo hardening scripts and their logs/backups.
- **1:05–2:15 — Guided lab:** run [`lab-exercises.md`](lab-exercises.md) — manual rule → verify →
  script → verify → rollback.
- **2:15–2:30 — Debrief + assign [`homework.md`](homework.md); preview Week 10 (Splunk).**

## Weekend lab plan (3–5 hr)
- **Warm-up (20m):** the rule of the week recited; one credential sweep.
- **Harden-and-survive (100m):** each member hardens their assigned box (manual firewall + one repo
  script), **verifying the scored service after every step**. Facilitator spot-checks that the service
  never dropped. Then each member rolls back one change on demand.
- **The self-own drill (20m):** facilitator has members deliberately write a rule that blocks the
  service/scoring, watch it fail the verify check, and fix it — so they *feel* the failure mode safely.
- **Assessment (30m):** run [`assessment.md`](assessment.md).
- **AAR (15m).**

## Facilitator notes & common snags
- **ICMP.** Reinforce: keep ICMP up everywhere except the Palo Alto core port (packet rule) — the
  scoring engine uses it. A firewall that drops all ICMP silently tanks your score.
- **Backups before scripts.** The repo scripts (e.g. [`Ubuntu/Harden.sh`](../../CCDC_2026/Linux/Ubuntu/Harden.sh),
  [`WindowsAD/Harden.ps1`](../../CCDC_2026/Windows/WindowsAD/Harden.ps1)) are powerful and some use
  `set -e` (abort mid-run — see [`../06-repo-gaps-backlog.md`](../06-repo-gaps-backlog.md)). Members
  must back up first and read the script's header before running it.
- **Verify is non-negotiable.** Every change → test the service. Make members show the verify step;
  don't accept "it should be fine."
- **No revert in competition.** Rollback is a skill they build by hand, not a snapshot.

## Definition of done
Every member has `T2-C4`, `T2-C5`, `T2-C6` ✅ — hand-written firewall rule that preserves the service,
a script run they can explain, a demonstrated rollback, and a verify after every change — or a partner
+ plan.
