# Week 4 — Assessment

Member **performs** each item while observed. Mark ✅ / 🔁. Record in the rubric sheet.
**Covers:** `T1-W1`, `T1-W2` ([`../02-readiness-rubric.md`](../02-readiness-rubric.md)).

---

## Part A — `T1-W1`: Local users, groups, services (hands-on, unaided)
Time budget: **6 minutes.**

| # | Task | ✅/🔁 |
|---|---|---|
| A1 | List the members of the local Administrators group | |
| A2 | Create a local user, disable it, then remove it | |
| A3 | Check a service's status and restart it; confirm Running | |
| A4 | Given a planted extra local admin, identify it as "not normal" | |

**Pass A** = all four ✅; A4 correctly flags the odd admin.

## Part B — `T1-W2`: Event Viewer & PowerShell (hands-on, unaided)
Time budget: **4 minutes.**

| # | Task | ✅/🔁 |
|---|---|---|
| B1 | Open the Security log and find a failed logon (4625) | |
| B2 | Run a `Get-WinEvent` query for Id 4625 | |
| B3 | State what 4625 means and why it matters to a defender | |

**Pass B** = B1 + B2 done, B3 correct.

---

## Scoring
- Both pass → `T1-W1`, `T1-W2` ✅.
- 🔁 → note items, pair the member, re-check start of Week 5.

> A4 (spot the rogue admin) and B (failed logons) are the seeds of the Windows credential sweep and
> attack detection you'll do for real in Phases 1–2. Building the instinct now pays off later.
