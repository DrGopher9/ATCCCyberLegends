# Week 18 — Assessment (team + individual)

The team works under load while docs are audited; individuals prove log-driven rollback and report
writing. Mark ✅ / 🔁. **Feeds:** capstone "documentation" dimension, `T2-I2/I3` at team scale
([`../02-readiness-rubric.md`](../02-readiness-rubric.md)).

---

## Part A — Team: docs under load (observed)
While the team hardens + handles 2 incidents + an inject:

| # | Task | ✅/🔁 |
|---|---|---|
| A1 | Change-log stays current — nothing material touched without an entry | |
| A2 | Password-tracker captures every rotated credential | |
| A3 | Judge-audit: the board answers "what changed on X in the last 20 min?" instantly | |
| A4 | Incident list reflects real-time status; clean handoffs (no silent ones) | |

**Pass A** = the board survived a judge audit; nothing material missing.

## Part B — Individual: reports & rollback
| # | Task | ✅/🔁 |
|---|---|---|
| B1 | Write a scorable IR report (src/dst IP, timeline, creds, impact, remediation), ~1pg, not padded | |
| B2 | Roll back a logged change using **only** the log; verify the service | |

**Pass B** = report meets spec and isn't padded; rollback works from the log alone.

---

## Scoring
- Team A + most members B → documentation is competition-ready; the team can recover from its own
  mistakes and score its intrusions.
- 🔁 → common misses: board goes stale under load (A1/A3 — reset the habit), padded reports (B1), or a
  log entry too vague to roll back from (B2). Re-drill under a lighter load, then re-audit.

> A clean board is what lets a team survive its own worst moment — an accidental outage you can undo, an
> intrusion you can prove you caught. In a 7-hour day, that's the difference between a good score and a
> great one.
