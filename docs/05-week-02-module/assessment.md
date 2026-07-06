# Week 2 — Assessment

Member **performs** each item while observed — no notes for the hands-on parts. Mark ✅ / 🔁. Record in
the rubric sheet. **Covers:** `T1-L1`, `T1-L2` ([`../02-readiness-rubric.md`](../02-readiness-rubric.md)).

---

## Part A — `T1-L1`: Filesystem, users, permissions (hands-on, unaided)
Time budget: **8 minutes.**

| # | Task | ✅/🔁 |
|---|---|---|
| A1 | Navigate to `/var/log` and find a `.log` file | |
| A2 | Show the human accounts from `/etc/passwd` (UID ≥ 1000) | |
| A3 | Create a user with a home dir, then remove it cleanly | |
| A4 | Create a file, set it to `640`, and correctly explain what that means | |
| A5 | Change a file's owner with `chown` | |

**Pass A** = all five ✅ within the budget.

## Part B — `T1-L2`: Processes & listeners (hands-on, unaided)
Time budget: **4 minutes.**

| # | Task | ✅/🔁 |
|---|---|---|
| B1 | List processes and name the user/PID/command of one | |
| B2 | Run `ss -tlnp` and list every listening port + its program | |
| B3 | Given a planted extra listener/process, identify it as "not normal" | |

**Pass B** = B1 + B2 correct, and B3 correctly flags the odd one.

---

## Scoring
- Both pass → `T1-L1`, `T1-L2` ✅.
- 🔁 → note which items, pair the member, re-check at the start of Week 3.

> The B3 "find the odd one out" is the seed of persistence hunting (Phase 2). It's fine if it's hard now
> — the point is to start building the instinct early.
