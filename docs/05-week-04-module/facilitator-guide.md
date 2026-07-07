# Week 4 — Facilitator Guide: Windows Fundamentals (Users, Services, Event Viewer, PowerShell)

> **Phase 0, Week 4.** Built from [`../templates/module-template.md`](../templates/module-template.md).

**Rubric targets:** `T1-W1` (manage local users/groups and services), `T1-W2` (Event Viewer + basic
PowerShell). See [`../02-readiness-rubric.md`](../02-readiness-rubric.md).

**Council lens:** the Blue Teamer (half the scored surface is Windows — AD/DNS, IIS web, FTP) and the
Red Teamer (Windows is where credential attacks and scheduled-task persistence live; you find them in
the Security log).

**You need:** a lab **Windows** box per member. Use **Windows 11 Wks (`172.20.240.100`)** for local-
account practice, or a **Server 2019** box. Default creds are in
[`../07-competition-reference.md`](../07-competition-reference.md) (`administrator:!Password123`,
`UserOne:ChangeMe123`). Practice with a throwaway local user; **don't touch Active Directory yet** —
that's Week 6 / Phase 2.

---

## Learning objectives
By end of the weeknight session, every member can:
1. Manage local users and groups (create, disable, check group membership).
2. Check, stop, start, and restart a Windows service.
3. Open Event Viewer, find the Security log, and locate failed logons (Event ID 4625).
4. Run basic PowerShell: `Get-Service`, `Get-LocalUser`, `Get-WinEvent`.

By end of the weekend lab, every member does all four **unaided**.

## Weeknight session plan (2–3 hr)
- **0:00–0:15 — Warm-up:** last week's Linux service check on a box (keeps `T1-L3` warm). Homework
  check.
- **0:15–0:40 — Concept + demo:** Windows local users vs. domain users (note: real accounts live in
  **AD** — that's later); local groups, especially **Administrators**. Demo `lusrmgr.msc` / Settings
  and the PowerShell equivalents.
- **0:40–1:00 — Concept + demo:** Services (`services.msc` and `Get-Service`); Event Viewer, the
  **Security** log, and **Event ID 4625 = failed logon** / **4624 = successful logon**. This is where
  you'll watch for the Red Team's credential attacks.
- **1:00–2:15 — Guided lab:** run [`lab-exercises.md`](lab-exercises.md).
- **2:15–2:30 — Debrief + assign [`homework.md`](homework.md); preview Week 5 (networking).**

## Weekend lab plan (3–5 hr)
- **Warm-up (30m):** Week 2/3 Linux drills unaided (don't let Linux go cold while learning Windows).
- **Main lab (75m):** repeat the Windows lab solo; then a "spot the bad account" drill — facilitator
  pre-creates an extra local admin; members find it with `Get-LocalGroupMember Administrators`.
- **Assessment (30m):** run [`assessment.md`](assessment.md).
- **AAR (15m).**

## Facilitator notes & common snags
- **GUI vs. PowerShell:** teach both, but push PowerShell — it's faster under pressure and scriptable.
  Show each GUI action's PowerShell equivalent side by side.
- **"Which admins group?"** Local Administrators ≠ Domain Admins. Flag the distinction now; it matters
  a lot in Phase 2 when they audit AD.
- **Don't change the Administrator password on a shared box** during a group session — you'll lock out
  the next pair. Use a throwaway user for password practice.
- Beginners find Event Viewer overwhelming. Give them exactly one target: **Security log → 4625.**

## Definition of done
Every member has `T1-W1` and `T1-W2` ✅, or a partner + plan before Week 5.
