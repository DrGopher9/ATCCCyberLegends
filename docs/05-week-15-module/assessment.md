# Week 15 — Tier-3 Specialty Gate (Phase 2 Exit Assessment)

Two parts: the persistence hunt (this week's skill), then the **full Tier-3 track** for the member's
specialty — the gate that unlocks Phase 3. Performed under observation; two assessors. Mark ✅ / 🔁 per
item in the tracking sheet. Track items are canonical in
[`../02-readiness-rubric.md`](../02-readiness-rubric.md).

The red team plants fresh persistence on the member's box before the assessment.

---

## Part A — Persistence hunt (hands-on, unaided)
Time budget: **8 minutes.**

| # | Task | ✅/🔁 |
|---|---|---|
| A1 | Work the persistence checklist systematically across all classes | |
| A2 | Find **all** planted persistence on the box | |
| A3 | Evict it — mechanism, not just symptom — and confirm nothing respawns | |
| A4 | Scored service still works after eviction | |

**Pass A** = all planted persistence found + evicted, clean on re-check, service up.

## Part B — Full Tier-3 track (the gate)
Grade **all four items** of the member's track. Example (AD/DNS shown; use the member's actual track):

| ID | Item | ✅/🔁 |
|---|---|---|
| _*1_ | Harden without breaking the scored service | |
| _*2_ | Find + evict persistence / the planted foothold | |
| _*3_ | Secure the box's key component | |
| _*4_ | Detect the attack (detection fires) | |

Tracks: `T3-AD1–4`, `T3-WEB1–4`, `T3-EC1–4`, `T3-EM1–4`, `T3-NET1–4`, `T3-SP1–4`.

---

## Result
- **Part A + all four track items ✅ → Tier-3 passed.** The member is a competition-ready specialist for
  their box and is cleared for Phase 3.
- **Any 🔁 → not yet.** Record exact items; remediation plan (partner + close date early in Phase 3);
  re-test just those items.

## Phase 2 exit gate (team level)
Met when every member is at Tier 3 for their box (or on an owned remediation plan) **and every box has a
cross-trained backup** who can at least hunt persistence + recover the scored service on it. In the
Phase 2 AAR, capture the team detections list and any repo scripts flagged too aggressive
([`../06-repo-gaps-backlog.md`](../06-repo-gaps-backlog.md)). Then head into Phase 3 to become a *team*.
