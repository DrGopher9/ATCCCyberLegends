# Week 3 — Assessment

Member **performs** each item while observed. Mark ✅ / 🔁. Record in the rubric sheet.
**Covers:** `T1-L3` ([`../02-readiness-rubric.md`](../02-readiness-rubric.md)).

---

## Part A — `T1-L3`: Services, logs, recovery (hands-on, unaided)
Time budget: **8 minutes.** The facilitator breaks a service for A4.

| # | Task | ✅/🔁 |
|---|---|---|
| A1 | Report a service's status, active state, and enabled state | |
| A2 | Stop, start, and restart a service; confirm active | |
| A3 | Show the last N log lines for a service with `journalctl -u` | |
| A4 | **Recover a service the facilitator broke**, using its log to find the cause | |
| A5 | Verify the recovered service actually serves (`ss`/`curl`), not just "active" | |

**Pass A** = all five ✅ within the budget, with A4 done by *reading the log*, not trial-and-error.

## Bonus (not required to pass, but note it)
| # | Task | ✅/🔁 |
|---|---|---|
| A6 | Patch the box and confirm the service still serves afterward | |

---

## Scoring
- Pass → `T1-L3` ✅.
- 🔁 → note which item (usually A4), pair the member, re-check start of Week 4.

> A4 is the money skill of Phase 0. If a member can calmly recover a broken service from its log under
> a clock, they will save the team real points in competition. Give extra reps here freely.
