# Week 2 — Facilitator Guide: Linux Fundamentals I (Filesystem, Users, Permissions, Processes)

> **Phase 0, Week 2.** Built from [`../templates/module-template.md`](../templates/module-template.md).

**Rubric targets:** `T1-L1` (navigate FS, manage users, read/set permissions), `T1-L2` (inspect
processes and network listeners). See [`../02-readiness-rubric.md`](../02-readiness-rubric.md).

**Council lens:** the Coach (beginners at a Linux prompt for the first time — slow and correct beats
fast) and the Blue Teamer (everything here is a defensive primitive: you can't spot a rogue user or a
malicious process if you can't list normal ones).

**You need:** each member able to reach a lab **Linux** box — use **Ubuntu Ecom (`172.20.242.30`)** or
the **Ubuntu Wks** from [`../07-competition-reference.md`](../07-competition-reference.md). A throwaway
practice user is fine; don't harden anything yet.

---

## Learning objectives
By end of the weeknight session, every member can:
1. Navigate the filesystem and find files (`cd`, `ls`, `pwd`, `find`, `cat`, `less`).
2. Create, inspect, and remove a user; understand `/etc/passwd`.
3. Read and set file permissions and ownership (`chmod`, `chown`, `ls -l`).
4. List processes and network listeners (`ps`, `top`, `ss`).

By end of the weekend lab, every member does all four **unaided**.

## Weeknight session plan (2–3 hr)
- **0:00–0:15 — Warm-up / homework check (spaced repetition):** everyone clones/pulls the repo and
  makes a branch (re-drills Week 1 `T1-G1`). Collect last week's three penalties.
- **0:15–0:45 — Concept + demo:** the Linux filesystem tree, what lives where (`/etc`, `/home`,
  `/var/log`, `/tmp`), users vs. groups, the permission triad (user/group/other × read/write/execute).
  Demo reading `/etc/passwd` and explaining a line.
- **0:45–1:00 — Concept + demo:** processes and listeners — why a defender cares (a backdoor is a
  process listening on a port). Demo `ps aux`, `ss -tlnp`.
- **1:00–2:15 — Guided lab:** run [`lab-exercises.md`](lab-exercises.md) together.
- **2:15–2:30 — Debrief + assign [`homework.md`](homework.md); preview Week 3 (services & logs).**

## Weekend lab plan (3–5 hr)
- **Warm-up (30m):** Week 1 git workflow unaided (keeps `T1-G1` warm).
- **Main lab (90m):** repeat the Week 2 lab solo; then a "find the odd one out" drill — facilitator
  pre-creates one extra user and one unusual file; members find them using only this week's commands.
- **Assessment (30m):** run [`assessment.md`](assessment.md).
- **AAR (15m):** what was confusing; who needs a partner for Week 3.

## Facilitator notes & common snags
- **`sudo` confusion is universal.** Explain "you are a normal user; admin actions need `sudo`" once,
  clearly, and expect to repeat it.
- **Permission numbers scare people.** Teach `rwx` first, then show `chmod 640` as shorthand — don't
  lead with octal.
- **Don't let them harden anything.** This week is *observe and operate*, not defend. Hardening is
  Phase 1. A beginner who "secures" a box now will just lock themselves out.
- Pair the shakiest members; have them drive, not watch.

## Definition of done
Every member has `T1-L1` and `T1-L2` ✅, or a named partner + plan to close before Week 3. Record in
the rubric sheet.
