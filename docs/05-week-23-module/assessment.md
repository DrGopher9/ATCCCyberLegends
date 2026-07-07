# Week 23 — Assessment: Fixes Closed + Bench Depth

Verify both workstreams. Mark ✅ / 🔁. Record in the tracking sheet. Not a capstone gate — the readiness
check before the Week-24 dress rehearsal.

---

## Part A — Week-22 fixes closed
| # | Task | ✅/🔁 |
|---|---|---|
| A1 | Top-3 fix #1 demonstrated closed | |
| A2 | Top-3 fix #2 demonstrated closed | |
| A3 | Top-3 fix #3 demonstrated closed | |

**Pass A** = all three demonstrably closed.

## Part B — Cross-training depth (the green-light requirement)
Using the coverage grid ([`lab-exercises.md`](lab-exercises.md)):

| # | Task | ✅/🔁 |
|---|---|---|
| B1 | Every box has a backup who ran it solo (detect + evict + recover + log) under pressure | |
| B2 | Coupled-box backups understand the dependencies (AD↔mail, network↔scoring/ICMP) | |
| B3 | Bench/alternates have held boxes, not just observed | |

**Pass B** = the coverage grid is two-deep on every box.

---

## Scoring
- Pass A + B → the team has closed its gaps and is two-deep on every box: ready for the full-length
  dress rehearsal.
- 🔁 on B → a box with only one competent operator is a single point of failure for a 7-hour event.
  Prioritize a solo backup rep before Week 24; if it can't be closed, the captain must plan around it.

> Depth is a green-light criterion for a reason. In a real 7-hour qualifier, someone will be buried,
> need a break, or face a two-person problem. A two-deep team stays functional; a one-deep team stalls.
