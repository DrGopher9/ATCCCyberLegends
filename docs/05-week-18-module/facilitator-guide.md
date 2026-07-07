# Week 18 — Facilitator Guide: Documentation & Change Management Under Load

> **Phase 3, Week 18.** Built from [`../templates/module-template.md`](../templates/module-template.md).

**Rubric targets:** the capstone "documentation" dimension and `T2-I2/I3` at team scale
([`../02-readiness-rubric.md`](../02-readiness-rubric.md)). Incident reports are a scored **10–20%**
(see [`../07-competition-reference.md`](../07-competition-reference.md)).

**Council lens:** the **White Team Judge**. Documentation is where good teams quietly beat great
technicians: a clean change-log lets you undo a mistake and prove what you did; well-written incident
reports score real points; a team that "just fixes things" without logging can't recover from its own
errors and earns nothing for the intrusions it caught. Under load, docs are the first thing to slip —
so we train them under load.

**You need:** the [change-log](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/change-log.md), the
[password-tracker](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/password-tracker.md), the IR
format in [`inject-templates.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/inject-templates.md),
the full lab, and the live/simulated red team to generate incidents worth reporting.

---

## Learning objectives
By end of the week, the team can:
1. Keep a **clean change-log** and password-tracker while actively working boxes — nothing touched
   without a log entry.
2. Do **clean handoffs** (what changed, what's broken, where the log is).
3. Produce **scorable incident reports** at team pace: source/dest IP, timeline, creds cracked, impact,
   remediation — exploitation not misconfiguration, **not padded**.
4. Use the log to **roll back** a change or explain an action to a "judge."

## Weeknight session plan (2–3 hr)
- **0:00–0:15 — Warm-up:** a coordinated First-30 status pass (keeps Week 16 warm).
- **0:15–0:40 — Frame docs as scored:** IR reports = 10–20%; clean change-log prevents self-owns and
  enables rollback. Show a good vs. a padded/vague IR report. Reinforce "one report per real
  exploitation event; don't over-report" (frivolous reports score *negatively*).
- **0:40–1:00 — The mechanics:** the shared board (change-log + incident list), the password-tracker,
  who owns documentation (the Injects/Docs role), and how it stays current when everyone's busy.
- **1:00–2:15 — Guided lab:** run [`lab-exercises.md`](lab-exercises.md) — work boxes + injects while
  keeping docs clean, handle incidents, write reports, and demonstrate a log-driven rollback.
- **2:15–2:30 — Debrief + assign [`homework.md`](homework.md); preview Week 19 (mini-scrimmage).**

## Weekend lab plan (3–5 hr)
- **Warm-up (20m):** review a good vs. weak incident report.
- **Docs-under-load lab (90m):** the team works a realistic mix — some hardening, an inject or two, and
  a couple of red-team incidents — while the docs owner keeps the change-log and incident list current
  and the team files IR reports. Facilitator periodically "audits" the board like a judge: *"show me
  what changed on Ecom in the last 20 minutes."*
- **Rollback-from-log drill (30m):** facilitator points at a logged change; the responsible member rolls
  it back **using only the log** and verifies the service. Proves the log is real, not theater.
- **Assessment (30m):** run [`assessment.md`](assessment.md).
- **AAR (15m).**

## Facilitator notes & common snags
- **Docs slip first under pressure.** That's exactly why we load them up. If the board goes stale during
  the drill, stop and reset the habit — a stale board is a blind captain and an unrecoverable mistake.
- **IR report Goldilocks.** New teams write zero reports or ten padded ones. Train the middle: one
  clear, specific report per real exploitation event. Grade quality, penalize padding (as the White
  Team does).
- **Evidence before eviction (again).** You can't write the report if you wiped the evidence. Capture
  source IP + timeline first.
- **The log must enable rollback.** If a member can't undo their own logged change, the entry wasn't
  detailed enough. Coach specificity: what, where, before→after.

## Definition of done
The team keeps a clean, audit-ready change-log and password-tracker while working under load, does clean
handoffs, files scorable non-padded IR reports, and can roll back a change from the log. Ready for the
Week 19 mini-scrimmage.
