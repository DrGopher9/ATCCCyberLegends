# Week 3 — Facilitator Guide: Linux Fundamentals II (Services, systemd, Logs, Packages)

> **Phase 0, Week 3.** Built from [`../templates/module-template.md`](../templates/module-template.md).

**Rubric target:** `T1-L3` (start/stop/status a service, read its logs, patch). See
[`../02-readiness-rubric.md`](../02-readiness-rubric.md).

**Council lens:** the Blue Teamer (service uptime *is* points — recovering a stopped service fast is
the single most valuable Linux reflex) and the Red Teamer (attackers hide in services and logs tell you
when they act).

**You need:** a lab Linux box per member (Ubuntu Ecom `172.20.242.30` runs a real web service — ideal).
This week they *stop and restart* a service on purpose; that's fine on a practice box. Don't touch a
box another exercise depends on.

---

## Learning objectives
By end of the weeknight session, every member can:
1. Check, stop, start, and restart a service with `systemctl`.
2. Read a service's logs with `journalctl` and the files under `/var/log`.
3. Recover a service that won't start by reading its logs.
4. Update packages / apply patches (`apt`, `dnf`) and understand why.

By end of the weekend lab, every member does all four **unaided**, including a recovery.

## Weeknight session plan (2–3 hr)
- **0:00–0:15 — Warm-up:** last week's `ss -tlnp` + "name every listener" on a box (keeps `T1-L2`
  warm). Homework check.
- **0:15–0:45 — Concept + demo:** what a *service/daemon* is; `systemd` as the thing that runs them;
  the lifecycle (`status`/`start`/`stop`/`restart`/`enable`). Demo on a real service (e.g. the web
  server on Ubuntu Ecom, or `ssh`).
- **0:45–1:05 — Concept + demo:** logs — `journalctl -u <svc>`, `journalctl -xe`, and classic files
  (`/var/log/syslog`, `/var/log/auth.log`). Show how a failed start explains itself in the logs.
- **1:05–2:15 — Guided lab:** run [`lab-exercises.md`](lab-exercises.md), including the break/recover
  drill.
- **2:15–2:30 — Debrief + assign [`homework.md`](homework.md); preview Week 4 (Windows).**

## Weekend lab plan (3–5 hr)
- **Warm-up (30m):** Week 2 users/permissions unaided.
- **Recovery relay (75m):** facilitator breaks a service on each box in a *different* way (stop it;
  misconfigure a port; kill the process). Members diagnose from logs and recover. Time each recovery;
  celebrate fast ones. This is the highest-value drill of Phase 0.
- **Assessment (30m):** run [`assessment.md`](assessment.md).
- **AAR (15m).**

## Facilitator notes & common snags
- **`journalctl` is the superpower.** Hammer the habit: *service won't start → read the log first,
  guess second.* New members will want to guess; redirect them to the log every time.
- **Keep breakage reversible.** Break things in ways you know how to undo. Snapshot nothing — the real
  competition has no revert (see [`../07-competition-reference.md`](../07-competition-reference.md)),
  so practicing genuine recovery is the point.
- **Patching etiquette:** in competition, patch deliberately and log it; a bad patch can drop a scored
  service. Teach "update, then verify the service still works" — the Phase-1 habit starts here.

## Definition of done
Every member has `T1-L3` ✅ (including one real recovery), or a partner + plan before Week 4.
