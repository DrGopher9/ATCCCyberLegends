# Week 13 — Assessment

Member **detects** an attack on their own box while observed. Mark ✅ / 🔁. Record in the rubric sheet.
**Covers:** the detection item of the member's track — `T3-AD4`, `T3-WEB4`, `T3-EC4`, `T3-EM4`,
`T3-NET3`, or `T3-SP4` ([`../02-readiness-rubric.md`](../02-readiness-rubric.md)).

The red team runs a bounded attack on the member's box just before/at assessment.

---

## Part A — Detect on your box (hands-on, unaided)
Time budget: **6 minutes.**

| # | Task | ✅/🔁 |
|---|---|---|
| A1 | Notice the attack as a deviation from your baseline (new user/file/listener/log spike) | |
| A2 | Find it in Splunk and/or the relevant on-box log | |
| A3 | Name the technique and the attacker's likely goal | |
| A4 | Capture the evidence: source IP + timeline + what was affected | |
| A5 | Leave the foothold in place (no premature eviction) | |

**Pass A** = A1–A4 ✅ and A5 respected (evidence intact for the report).

---

## Scoring
- Pass → the member's track detection item (`T3-*4` / `T3-NET3`) is ✅.
- 🔁 → usually A1 (didn't notice) or A4 (incomplete evidence). Re-run the attack, walk them through the
  baseline diff, and re-test. A weak Week-12 baseline is the usual root cause — send them back to it.

> Detection is half the Tier-3 bar for a reason: in competition, an attack you never see is a foothold
> that persists all day. A member who calmly spots and evidences their box's attack is exactly who you
> want on that box in Phase 4.
