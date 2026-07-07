# Week 8 — Facilitator Guide: The Credential Sweep (Passwords, Keys, Accounts)

> **Phase 1, Week 8.** Built from [`../templates/module-template.md`](../templates/module-template.md).

**Rubric targets:** `T2-C1` (Linux credential sweep), `T2-C2` (Windows credential sweep), `T2-C3`
(remove unauthorized SSH keys). See [`../02-readiness-rubric.md`](../02-readiness-rubric.md).

**Council lens:** the Red Teamer owns this week. The Red Team starts with **your** default passwords —
they're printed in the packet ([`../07-competition-reference.md`](../07-competition-reference.md)) and
the attackers have them too. The first thing that happens in a real round is credential stuffing. If
you don't rotate everything in the first 30 minutes, you're already owned.

**You need:** lab access to Linux boxes (Ubuntu Ecom/Wks, Fedora Webmail, Splunk) and Windows boxes
(Server 2019 AD/DNS, Win11). The default creds from `07`. A stopwatch. This is the first week members
*change* real settings — teach the safety rails before they touch anything.

---

## Learning objectives
By end of the weeknight session, every member can:
1. Rotate root/admin and all user passwords on a Linux box, and disable/remove unknown accounts.
2. Rotate Administrator and audit local/Domain admins on Windows; disable unknown accounts.
3. Find and remove unauthorized SSH `authorized_keys` across all users.
4. Do it **fast** — the sweep is a timed reflex, not a leisurely audit.

By the weekend lab, every member sweeps a Linux box and a Windows box under a time budget, unaided.

## The safety rails (teach these FIRST — every session in Phase 1 opens with them)
1. **admin/root/sysadmin passwords are NOT scored** — change them freely, no notification (packet
   rule). **But** POP3/mail auth uses **AD user** accounts — don't disable or mangle those or you drop
   the mail score. When in doubt on a scored-service account, rotate carefully and **verify the service
   still works** afterward.
2. **Log every change** in the [change-log](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/change-log.md)
   and the [password-tracker](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/password-tracker.md).
3. **There is no revert.** If you lock yourself out, you own fixing it. Keep one known-good session open
   while you change credentials.

## Weeknight session plan (2–3 hr)
- **0:00–0:15 — Warm-up:** Tier-1 recall — list local admins (Win) + human accounts (Linux). Close any
  Phase-0 remediation still open.
- **0:15–0:35 — Concept:** the Red Team's opening (from [`red-team-playbook.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/red-team-playbook.md)):
  credential stuffing, known defaults, pre-planted accounts, SSH keys. Show the default-cred table in
  `07` — "the attackers have this page too."
- **0:35–0:55 — Concept + demo:** the safety rails above; the password-tracker and change-log habit.
- **0:55–2:15 — Guided lab:** run [`lab-exercises.md`](lab-exercises.md) — Linux sweep, then Windows
  sweep, then SSH keys.
- **2:15–2:30 — Debrief + assign [`homework.md`](homework.md); preview Week 9 (hardening + firewalls).**

## Weekend lab plan (3–5 hr)
- **Warm-up (20m):** the safety rails, recited; one Tier-1 service recovery.
- **Timed sweeps (90m):** each member sweeps a Linux box, then a Windows box, against a clock, logging
  every change. Facilitator plants an unknown account + an SSH key on each; members must catch them.
- **Assessment (30m):** run [`assessment.md`](assessment.md).
- **AAR (15m):** who missed a planted account/key, and why; where the change-log slipped.

## Facilitator notes & common snags
- **Lockout is the #1 risk.** Drill "keep a second session open" until it's automatic. Someone *will*
  lock themselves out — make it a low-stakes lesson now, not in competition.
- **The AD-account trap.** Reinforce: don't disable AD users wholesale — POP3/mail rides on them. Rotate
  admin/service creds aggressively; touch scored-service accounts carefully + verify.
- **Speed comes from a checklist that becomes muscle memory.** Point at the repo
  [`quick-reference.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/quick-reference.md) "First
  15 Minutes"; by end of phase they shouldn't need it.
- Log discipline slips first under time pressure — grade it, don't just mention it.

## Definition of done
Every member has `T2-C1`, `T2-C2`, `T2-C3` ✅ — a full sweep of a Linux and a Windows box, catching
planted accounts/keys, with a clean change-log — or a partner + plan.
