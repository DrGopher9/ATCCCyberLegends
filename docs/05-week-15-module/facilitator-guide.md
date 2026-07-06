# Week 15 — Facilitator Guide: Persistence Hunting + Tier-3 Specialty Gate

> **Phase 2, Week 15 — the phase exit gate.** Built from [`../templates/module-template.md`](../templates/module-template.md).

**Rubric targets:** the **persistence-removal** item per track (`T3-AD2`, `T3-WEB3`*, `T3-EC2`,
`T3-EM2`, `T3-NET4`, `T3-SP*`) **plus the full Tier-3 gate** — each member passes **all four items** of
their track. See [`../02-readiness-rubric.md`](../02-readiness-rubric.md).
(*Web/FTP's persistence surface overlaps its web-shell/file item; hunt handlers, tasks, services too.)

**Council lens:** the Red Teamer (persistence is how they survive your eviction — pre-planted backdoors
that reactivate after you "clean up") and the Coach (this is a checkpoint to get everyone to Tier 3, not
a cut). Persistence hunting is the skill that turns "I evicted them" into "they're actually gone."

**You need:** the [`persistence-hunting.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/persistence-hunting.md)
checklist, the red team to plant persistence on each box, and the per-member Tier-3 tracking sheet.

---

## Learning objectives
By end of the week, every member can, **for their box**:
1. Hunt every persistence class systematically: accounts, keys, cron/scheduled tasks, services,
   startup, and box-specific mechanisms.
2. Find and evict pre-planted persistence the red team hid — and confirm it doesn't come back.
3. Pass the **full Tier-3 track** for their specialty.

## Weeknight session plan (2–3 hr)
- **0:00–0:15 — Warm-up:** run your Week-14 detection; confirm it still fires.
- **0:15–0:40 — Concept:** persistence classes (from the playbook) — a backdoor account, an SSH key, a
  cron job / scheduled task, a malicious service, a startup script, a web shell, a GPO/registry run-key.
  "Killing the process isn't eviction if the cron job respawns it."
- **0:40–2:15 — Hunt lab (split by track):** red team has pre-planted persistence; members work their
  section of [`lab-exercises.md`](lab-exercises.md) to find and evict all of it, then confirm clean.
- **2:15–2:30 — Debrief; set expectations for the weekend Tier-3 gate; assign [`homework.md`](homework.md).**

## Weekend lab plan (3–5 hr) — the Tier-3 gate
- **Warm-up (20m):** persistence checklist recited on your box.
- **Persistence hunt under time (50m):** red team plants a fresh set; members find + evict all of it and
  prove the box is clean (nothing respawns; detection quiet).
- **Tier-3 gate (75m):** run [`assessment.md`](assessment.md) — each member is graded on **all four
  items of their track**. Two assessors. Record ✅/🔁 per item.
- **Remediation + Phase 2 AAR (25m):** plans for anyone short; confirm every box has a cross-trained
  backup at (at least) a lighter Tier-3. Celebrate: the team now has specialists. Preview Phase 3
  (Integrate & Injects — becoming a *team*).

## Facilitator notes & common snags
- **"Evicted" ≠ "gone."** The classic miss: kill the process/account but leave the cron job or scheduled
  task that recreates it. Drill "hunt every class, then re-check after eviction."
- **Systematic beats clever.** Push the checklist, in order, every box, every time — that's what catches
  the boring backdoor the flashy one distracted you from.
- **Don't break the service hunting.** Removing a "suspicious" thing that's actually a scored-service
  dependency is a self-own — verify after eviction (Phase-1 reflex).
- **Backups get gated too (lighter).** Every box needs two people who can at least hunt persistence on
  it by Phase 4.

## Definition of done
Every member passes their **full Tier-3 track** (or has an owned remediation plan with a near-term close
date), and can hunt + evict persistence on their box such that nothing respawns. Phase 2 exit gate =
team at Tier 3, every box double-covered.
