# Week 11 — Tier-2 Core Gate (Phase 1 Exit Assessment)

Two parts: the new IR skills (`T2-I1/I2/I3`), then the **full Tier-2 Core checklist** — the gate that
unlocks Phase 2 (Specialize). Performed under observation; two assessors keep it moving. Mark ✅ / 🔁 per
item per member in the tracking sheet. Canonical items in
[`../02-readiness-rubric.md`](../02-readiness-rubric.md).

---

## Part A — IR cycle + report (`T2-I1`, `T2-I2`, `T2-I3`)
The facilitator plants an intrusion on a box. Member runs the full cycle. Time budget: **15 minutes.**

| ID | Item | ✅/🔁 |
|---|---|---|
| T2-I1 | Detect → contain → evict the intrusion; scored service stays up | |
| T2-I2 | Change-log every action taken | |
| T2-I3 | Write a spec-compliant incident report (src/dst IP, timeline, creds, impact, remediation), ~1 page, not padded | |

**Pass A** = all three ✅; containment didn't break a scored service; report meets the packet spec.

## Part B — Full Tier-2 Core checklist
Confirm the phase's skills. These should be near-automatic.

| ID | Item | ✅/🔁 |
|---|---|---|
| T2-C1/C2 | Credential sweep, Linux + Windows (catch a planted account) | |
| T2-C3 | Find + remove an unauthorized SSH key | |
| T2-C4 | Hand firewall rule allowing the scored service; ICMP preserved | |
| T2-C5 | Run a repo script, explain 3 changes, roll one back | |
| T2-C6 | Verify a scored service after a change | |
| T2-S1 | Confirm a forwarder is reporting; run the failed-login search | |
| T2-S2 | Read a dashboard; name an anomaly | |

---

## Result
- **Part A + all of Part B ✅ → Tier-2 Core passed.** Member is cleared for Phase 2 and can take a
  specialty.
- **Any 🔁 → not yet.** Record exact items; write a remediation plan (named partner + close date early
  in Phase 2); re-test just those items.

## Phase 1 exit gate (team level)
Met when the team as a whole is at Tier-2 Core — every member ✅ or on an owned remediation plan.
In the Phase 1 AAR, note the hardest items across the team (often `T2-C5` rollback or `T2-I3` report
quality) so Phase 2 warm-ups keep re-drilling them. Then assign specialties for Phase 2 based on
Tier-2 performance and interest.
