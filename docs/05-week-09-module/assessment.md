# Week 9 — Assessment

Member **performs** each item while observed. Mark ✅ / 🔁. Record in the rubric sheet.
**Covers:** `T2-C4`, `T2-C5`, `T2-C6` ([`../02-readiness-rubric.md`](../02-readiness-rubric.md)).

The scored service on the box **must stay up the entire time** — a drop is an automatic 🔁 on `T2-C6`.

---

## Part A — `T2-C4` + `T2-C6`: Manual firewall + verify (hands-on, unaided)
Time budget: **8 minutes.**

| # | Task | ✅/🔁 |
|---|---|---|
| A1 | Back up firewall/config before changing anything | |
| A2 | Write a rule allowing the scored service + admin port; keep ICMP up | |
| A3 | Enable it without locking yourself out | |
| A4 | **Verify** the scored service still works AND ICMP still flows | |

**Pass A** = all four ✅; service never dropped; ICMP preserved.

## Part B — `T2-C5`: Script, explain, rollback (hands-on, unaided)
Time budget: **8 minutes.**

| # | Task | ✅/🔁 |
|---|---|---|
| B1 | Back up, then run a repo hardening script | |
| B2 | Explain **three** specific things the script changed | |
| B3 | Roll back one change by hand and confirm it | |
| B4 | Verify the scored service still works after the rollback | |

**Pass B** = all four ✅; explanation is accurate (not hand-wavy).

---

## Scoring
- Both pass → `T2-C4`, `T2-C5`, `T2-C6` ✅.
- 🔁 → note items. Auto-🔁 triggers: the scored service dropped, ICMP was blanket-dropped, the member
  locked themselves out, or they couldn't explain the script they ran.

> This week is where self-inflicted outages get trained out of the team. A member who instinctively
> verifies the service after every change — and can undo what they did — will not hand the White Team
> free points. That instinct is the whole deliverable.
