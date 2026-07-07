# Week 8 — Assessment

Member **performs** each item while observed, under a time budget. Mark ✅ / 🔁. Record in the rubric
sheet. **Covers:** `T2-C1`, `T2-C2`, `T2-C3` ([`../02-readiness-rubric.md`](../02-readiness-rubric.md)).

The facilitator plants **one unknown account and one unauthorized SSH key** on the Linux box, and **one
unknown local account** on the Windows box, before the assessment.

---

## Part A — `T2-C1` + `T2-C3`: Linux sweep (hands-on, unaided)
Time budget: **8 minutes.**

| # | Task | ✅/🔁 |
|---|---|---|
| A1 | Open a second session as a lockout safety net *before* changing anything | |
| A2 | Rotate root + the default account password; log them | | 
| A3 | Find and disable/remove the **planted unknown account** | |
| A4 | Audit sudoers; state whether anything is out of place | |
| A5 | Find and remove the **planted unauthorized SSH key** | |
| A6 | Verify a scored service still works after the sweep | |

**Pass A** = all six ✅ in budget, planted items caught, no lockout, no broken service.

## Part B — `T2-C2`: Windows sweep (hands-on, unaided)
Time budget: **6 minutes.**

| # | Task | ✅/🔁 |
|---|---|---|
| B1 | List local admins; rotate the local Administrator password (logged) | |
| B2 | Find and **disable** the planted unknown local account | |
| B3 | State why AD user accounts must be handled carefully (POP3/mail auth) | |

**Pass B** = all three ✅; B3 correct.

---

## Scoring
- Both pass → `T2-C1`, `T2-C2`, `T2-C3` ✅.
- 🔁 → note items, pair the member, re-check next week. Common misses: forgetting the second session
  (A1), missing the SSH key (A5), or breaking a service by mangling an AD/service account.

> The credential sweep is the single highest-value thing this team does in the first 30 minutes of a
> real round. Give reps freely — speed + safety here directly denies the Red Team their easiest win.
