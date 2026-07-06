# Week 10 — Assessment

Member **performs** each item while observed. Mark ✅ / 🔁. Record in the rubric sheet.
**Covers:** `T2-S1`, `T2-S2` ([`../02-readiness-rubric.md`](../02-readiness-rubric.md)).

The facilitator stops one forwarder and generates failed logins from a known source IP before the
assessment.

---

## Part A — `T2-S1`: Forwarders + failed-login search (hands-on, unaided)
Time budget: **6 minutes.**

| # | Task | ✅/🔁 |
|---|---|---|
| A1 | List reporting hosts and identify the **silent** one the facilitator stopped | |
| A2 | Run the Linux failed-login search and read the top source IPs | |
| A3 | Run the Windows `EventCode=4625` search | |
| A4 | Identify the facilitator's planted source IP in the results | |

**Pass A** = all four ✅; silent host and planted IP both found.

## Part B — `T2-S2`: Read a dashboard (hands-on, unaided)
Time budget: **4 minutes.**

| # | Task | ✅/🔁 |
|---|---|---|
| B1 | Open a repo dashboard and identify an anomaly | |
| B2 | State it as "host X, [what], from IP Y, at time Z" | |

**Pass B** = anomaly correctly identified and clearly stated.

---

## Scoring
- Both pass → `T2-S1`, `T2-S2` ✅.
- 🔁 → note items. Common miss: not noticing the silent host (A1) — reinforce that a box which stops
  reporting is a priority, not a footnote.

> The deliverable is the reflex: *data flowing? → run the search → name the anomaly out loud.* A team
> that instinctively does this reads the Red Team's moves in near real time by Phase 4.
