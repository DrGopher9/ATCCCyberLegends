# Week 21 — Fix-It Drills

There's no fixed lab this week — the drills come from **your team's Week-20 AAR**. Below is a menu keyed
to the most common gaps; pick the ones that match your top-3 and your weakest scorecard dimension. The
rule: a fix is only "closed" when you **re-create the failing situation and show it now succeeds.**

---

## If injects were missed or late (weak "injects on time")
- [ ] Inject-under-fire reps: release an inject with a deadline while a fire runs; the injects owner
      keeps the clock, the captain protects the deadline. Repeat until deadlines hold.
- [ ] Review the missed inject(s): why late — no owner? lost to a fire? slow writing? Fix that cause.

## If eviction didn't stick (weak "footholds evicted")
- [ ] Detect → evict → **re-check** reps: red team plants persistence, you evict, then confirm it
      doesn't respawn. Drill the "hunt the mechanism, not the symptom" habit.
- [ ] Build/adjust the detection that would have caught the re-entry sooner.

## If services dropped or self-owned (weak "uptime" / "self-inflicted outages")
- [ ] Harden-and-verify reps: make a change, verify the service, every time. Find what dropped the
      service in Week 20 and drill around it.
- [ ] Fast-recovery reps: break + recover each scored service under a clock.

## If comms collapsed (weak "communication")
- [ ] Simultaneous-events drill: 3 fires at once, called in format, captain triages, one owner each.
- [ ] Captain reps: keep the captain off keyboards while running the triage loop out loud.

## If the board went stale (weak "documentation")
- [ ] Docs-under-load + judge-audit reps (Week 18): work boxes while keeping the board current; the
      facilitator audits at random.
- [ ] Rollback-from-log reps: prove every logged change is detailed enough to undo.

## If stamina/late-game decay showed (hour-3 slump)
- [ ] Run a longer focused block so the team practices sustaining comms/docs past the fatigue point.
- [ ] Rotate the floater/backups to keep fresh eyes on the hottest boxes.

---

## Individual skill re-sharpening
Any member who fumbled a Tier-2/3 skill under pressure: calm reps of that exact skill (service recovery,
credential sweep, persistence hunt, IR report, a specialty item). Rusty-under-stress is normal — fix it
here, not in Week 22.

## Verify each fix is closed
For every top-3 fix: re-create the Week-20 failing scenario and show it now succeeds. If it doesn't, it
isn't closed — keep drilling. Log the closed fixes.

## Done?
You've had a productive fix-it week if every top-3 fix is demonstrably closed and your weakest dimension
is measurably better. Finish your owned fix solo for [`homework.md`](homework.md).
