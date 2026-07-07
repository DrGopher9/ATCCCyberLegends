# Week 24 — Facilitator Guide: Dress Rehearsal (Full 7-Hour Qualifier Conditions)

> **Phase 4, Week 24 — the capstone gate.** Built from [`../templates/module-template.md`](../templates/module-template.md).

**Rubric targets:** the **capstone scrimmage thresholds** in [`../02-readiness-rubric.md`](../02-readiness-rubric.md).
This is the scrimmage where the team must hit them — the readiness bar for the whole program.

**Council lens:** all five, at full intensity. The **Red Teamer** runs qualifier-like pressure; the
**White Team** scores injects + IR to standard via a portal; the **Former Tech Lead** watches team ops
over a full day; the **Coach** manages energy and runs the AAR. This is as close to the real MN qualifier
as the team will get before competing.

**You need:** a **full 7-hour block modeling 9am–4pm CST** (see [`../07-competition-reference.md`](../07-competition-reference.md)),
the full lab + service load, the red team at **qualifier intensity**, a **full inject set delivered like
NISE** (PDF responses, staggered deadlines, business + technical, times in CST), and the
[scorecard](../templates/scrimmage-scorecard.md) + [AAR template](../templates/aar-template.md).

---

## Run it like the real thing
- **Timing:** model the real day — a ~30-min pre-brief/setup, then **7 hours of active scoring**, then
  debrief. If a true 7-hour block isn't possible, run the longest you can (aim for 5–6 hr) and note the
  gap.
- **Injects via a portal:** deliver injects as the NISE would; require **PDF** responses submitted to a
  designated place before the deadline; keep running inject scores **hidden** from the team.
- **No revert:** if a box breaks, cold boot only; VM scrubs cost a penalty and are limited (model this).
- **Rules enforced:** keep ICMP up except the PA core port; nothing that breaks the scoring checks;
  professional comms and conduct scored.

## The capstone thresholds (must hit ALL in this run)
From [`../02-readiness-rubric.md`](../02-readiness-rubric.md):
- Scored-service uptime **≥ 90%** across HTTP/HTTPS/SMTP/POP3/DNS
- **Zero** self-inflicted outages
- Injects **≥ 90%** on time to White-Team quality
- **Every** red-team foothold detected + evicted + reported (to IR spec)
- First 30 minutes complete on all boxes
- Clean, audit-ready documentation
- Communication held under pressure; captain ran the floor

## Weeknight session plan (2–3 hr) — final readiness
- **0:00–0:20 — Warm-up:** team First-30, crisp.
- **0:20–0:45 — Confirm Week-23:** fixes closed? every box two-deep? Resolve any remaining single points
  of failure.
- **0:45–2:15 — Light targeted drills only:** don't exhaust the team the night before — sharpen, don't
  grind. Confirm logistics (portal, boards, roles, backups, energy plan for a long day).
- **2:15–2:30 — Pre-brief the dress rehearsal; assign [`homework.md`](homework.md) (prep + energy).**

## The dress rehearsal (full day) — the gate
- **Pre-brief/setup (30m):** boards, portal, roles, backups, red team + White Team briefed to qualifier
  intensity, energy/rotation plan.
- **7 hours active scoring:** run per [`lab-exercises.md`](lab-exercises.md). Facilitators score the
  full [scorecard](../templates/scrimmage-scorecard.md) live.
- **AAR (60m):** the most important AAR of the season — did we hit **all** capstone thresholds? Where
  are the last gaps? Top-3 → Week 25. Blameless, specific, honest.

## Facilitator notes & common snags
- **Energy management is now a skill.** Seven hours is a marathon. Watch for late-game collapse in comms,
  docs, and vigilance; practice rotations, breaks, and food. The team that's still sharp at hour 6 wins.
- **This is the real test — score it straight.** No grading on a curve. The team either hits the
  thresholds or has a specific, closeable gap for Week 25.
- **Qualifier intensity, not beyond.** Match the real MN qualifier, don't exceed it — you're measuring
  readiness, not breaking morale two weeks out.
- **Capture everything for Week 25.** The last fix-it week is short; the dress-rehearsal AAR must be
  precise about what remains.

## Definition of done (capstone gate)
The team runs a full-length dress rehearsal under qualifier conditions and **hits all capstone
thresholds** — or exits with a specific, owned, closeable top-3 for Week 25. Hitting them is the
green-light signal that the training worked.
