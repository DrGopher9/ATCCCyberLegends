# Week 23 — Facilitator Guide: Fix-It + Cross-Training (Bench Depth)

> **Phase 4, Week 23.** Built from [`../templates/module-template.md`](../templates/module-template.md).

**Rubric targets:** close Week-22's top-3; and the depth requirement in the green-light criteria —
**every role has a cross-trained backup** ([`../02-readiness-rubric.md`](../02-readiness-rubric.md),
[`../03-team-roles-and-comms.md`](../03-team-roles-and-comms.md)).

**Council lens:** the **Coach** (close the gaps + build the bench) and the **Former Tech Lead** (depth
wins long days — in a 7-hour event, a specialist gets buried, needs a break, or a box takes two people;
if only one person can run a box, that box is a single point of failure).

**You need:** Week-22's AAR + scorecard, the full lab, and the bench/alternates training alongside the
starters (10–12 total).

---

## Two jobs this week
1. **Close Week-22's top-3** (same demonstrated-closure discipline as Week 21).
2. **Cross-train every box** so at least two people can competently run it — hunt persistence, recover
   the scored service, and hold it under pressure.

## Learning objectives
By end of the week:
1. Week-22's top-3 fixes are demonstrably closed.
2. **Every box has a cross-trained backup** who has run it under realistic conditions.
3. The bench/alternates are integrated — they've held boxes, not just watched.

## Weeknight session plan (2–3 hr)
- **0:00–0:15 — Warm-up:** the weakest dimension from Week 22.
- **0:15–0:30 — Own the AAR:** top-3 on the board with owners + verification. Map the cross-training gaps
  (which boxes have only one competent operator?).
- **0:30–2:15 — Split work:** half the session on fix-verification drills (from
  [`lab-exercises.md`](lab-exercises.md)); half on **backups running boxes** while primaries coach/observe.
- **2:15–2:30 — Assign [`homework.md`](homework.md); preview Week 24 (full 7-hour dress rehearsal).**

## Weekend lab plan (3–4 hr)
- **Warm-up (20m):** re-drill a slipped skill.
- **Fix verification (60m):** each Week-22 top-3 demonstrated closed under realistic conditions.
- **Backup-runs-the-box (90m):** for each box, the **backup runs it** through a compressed pressure
  scenario (First-30 + a foothold + a service hiccup) while the primary is "unavailable." The backup
  must detect, evict, recover, and log — the primary only coaches afterward. Rotate through all boxes.
- **Assessment (30m):** run [`assessment.md`](assessment.md).
- **AAR-lite (10m):** which boxes still lack a solid backup? What's the plan before Week 24?

## Facilitator notes & common snags
- **Backups must actually run the box, not shadow it.** The only way to know a backup can hold a box is
  to make the primary unavailable and watch the backup do it. Uncomfortable but essential.
- **Coupled boxes need coupled backups.** The AD backup must understand the mail dependency; the network
  backup must know the ICMP/scoring rules. Cross-train the *relationships*, not just the boxes.
- **Integrate the bench for real.** Alternates who've only watched are not depth. Put them on boxes this
  week; the starting 8 is decided in Phase 5 on performance, so everyone should be competing for a seat.
- **Don't neglect the fixes for the cross-training** (or vice versa). Both matter before the dress
  rehearsal — split the time deliberately.

## Definition of done
Week-22's top-3 are closed, and **every box has a second person who has run it under pressure** (detect,
evict, recover, log). The bench is integrated. The team is ready for the full-length dress rehearsal.
