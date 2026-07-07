# Week 20 — Facilitator Guide: Full Scrimmage #1 (Moderate) + AAR

> **Phase 4, Week 20.** Built from [`../templates/module-template.md`](../templates/module-template.md).
> Phase 4 is repetition against a real red team at rising intensity, with a disciplined AAR every time.

**Rubric targets:** first real measurement against the capstone dimensions in
[`../02-readiness-rubric.md`](../02-readiness-rubric.md) — uptime, no self-owns, injects on time,
footholds evicted + reported, first-30, docs, comms.

**Council lens:** the **Red Teamer** brings the pressure (moderate — a real step up from Week 19's
gentle touch); the **Coach** runs the AAR so the team *learns* rather than just survives. The rule of
Phase 4: **alternate scrimmage weeks with fix-it weeks** — cramming scrimmages without fixing gaps just
rehearses the same mistakes.

**You need:** the full lab, the live red team dialed to **moderate**, a **full service load and a full
inject set**, the [scorecard](../templates/scrimmage-scorecard.md) and [AAR template](../templates/aar-template.md),
and a solid block (aim for a **half-day, ~3–4 hr** compressed run — building toward the full 7 hr at
Week 24).

---

## What's different from Week 19
- **Moderate red team** (not gentle): more footholds, real persistence, active re-entry after eviction,
  a probe on the weak boxes. They *will* get in somewhere — the test is detection + eviction + reporting.
- **Full service load + full inject set**: all scored services live, injects with real deadlines
  throughout.
- **Longer**: half-day, so stamina and sustained comms matter.
- **Scored against the capstone dimensions** for the first time — this is the baseline Phase 4 improves.

## Learning objectives
By end of the week, the team can:
1. Run a half-day scrimmage under moderate pressure as one unit.
2. Detect, evict, and **report** footholds a competent attacker establishes.
3. Produce an AAR with an owned **top-3 fix list** that Week 21 will close.

## Weeknight session plan (2–3 hr) — readiness check
- **0:00–0:20 — Warm-up:** team First-30 status pass; confirm everyone's detections + backups are ready.
- **0:20–0:45 — Review Week 19's AAR:** did we close last time's top-3? Name what's still open.
- **0:45–2:15 — Targeted drills:** work the specific seams from Week 19 (comms, injects-under-fire, IR
  reports) so the weekend scrimmage tests improvement, not the same gaps.
- **2:15–2:30 — Pre-brief the weekend scrimmage; assign [`homework.md`](homework.md).**

## Weekend lab plan (half-day) — the scrimmage + AAR
- **Set-up (20m):** boards, scorecard, roles, red team briefed to moderate.
- **Scrimmage (2.5–3 hr):** run per [`lab-exercises.md`](lab-exercises.md) (same runbook as Week 19,
  higher intensity + full length). Facilitators score live.
- **AAR (45m):** full [AAR template](../templates/aar-template.md); blameless; **top-3 fixes with
  owners/dates → Week 21.**
- **Debrief (15m):** compare the scorecard to Week 19's baseline — what improved, what didn't.

## Facilitator notes & common snags
- **Ramp, don't spike.** Moderate means "a competent attacker who gets in but is catchable." Don't jump
  to qualifier intensity yet — that's Week 24.
- **Stamina is a real variable now.** Watch for comms/docs decay in hour 3 — that's a finding, not a
  failure; note it for fix-it week.
- **Score honestly and share it.** The scorecard is the objective baseline; the team needs to see it to
  own the fixes.
- **Protect the AAR.** The scrimmage is worthless without it. Top-3 fixes, owned and dated, are the
  deliverable that makes Week 21 productive.

## Definition of done
The team completed a moderate half-day scrimmage scored on the capstone dimensions, and produced an
honest AAR with an owned top-3 fix list. Those fixes are Week 21's agenda.
