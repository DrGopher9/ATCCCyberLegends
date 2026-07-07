# Week 14 — Assessment

Member **performs** on their box while observed; the red team re-runs the Week-13 attack. Mark ✅ / 🔁.
**Covers** the hardening/detection items for the member's track (e.g. `T3-AD1/AD3`, `T3-WEB1/2/3`,
`T3-EC1/EC3`, `T3-EM1/2/3`, `T3-NET1/NET2`, `T3-SP1/2/3` — [`../02-readiness-rubric.md`](../02-readiness-rubric.md)).

The scored service **must stay up throughout** — a drop is an auto-🔁.

---

## Part A — Harden + keep scored (hands-on, unaided)
Time budget: **8 minutes.**

| # | Task | ✅/🔁 |
|---|---|---|
| A1 | Back up, then apply the defense for your box's attack | |
| A2 | When the red team repeats the attack, it now **fails** | |
| A3 | Secure your box's key component(s) for your track | |
| A4 | The scored service stayed up the whole time (verify) | |

**Pass A** = all four ✅; attack blocked; service never dropped.

## Part B — Detection fires (hands-on, unaided)
Time budget: **4 minutes.**

| # | Task | ✅/🔁 |
|---|---|---|
| B1 | Show your saved detection/alert for the attack | |
| B2 | When the attack runs, the detection **fires** | |

**Pass B** = the detection triggers on the live attack.

---

## Scoring
- Both pass → the member's Week-14 track items ✅.
- 🔁 → common misses: the fix also broke the service (A4), or the detection didn't actually fire (B2).
  Re-drill and re-test before the Week-15 gate.

> This is the heart of the specialty: your box resists its known attack, keeps scoring, and tells you
> when it's hit. Members solid here are ready to be graded on the full Tier-3 track next week.
