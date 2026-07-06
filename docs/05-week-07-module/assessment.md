# Week 7 — Tier-1 Gate (Phase 0 Exit Assessment)

The full Tier-1 checklist, performed under observation. This is the gate that unlocks Phase 1. Two
assessors keep it moving. Mark ✅ / 🔁 per item per member in the rubric-tracking sheet. Items are the
canonical ones in [`../02-readiness-rubric.md`](../02-readiness-rubric.md).

**Format:** rotate members through four stations (git/rules, Linux, Windows, networking). Budget ~15
min per member per station; assessors can run members in parallel.

---

## Gate checklist (per member)

### Foundations — `T1-G1`, `T1-G2`
| ID | Item | ✅/🔁 |
|---|---|---|
| T1-G1 | Reach the lab; pull, branch, commit, push a branch (not `main`) unaided | |
| T1-G2 | State what CCDC is + 3 point-loss/DQ actions + 1 allowed action | |

### Linux — `T1-L1`–`T1-L4`
| ID | Item | ✅/🔁 |
|---|---|---|
| T1-L1 | FS navigation; create/remove a user; set + explain `640` | |
| T1-L2 | List processes; `ss -tlnp` list listeners; flag a planted one | |
| T1-L3 | **Recover a broken service from its log**; verify it serves | |
| T1-L4 | Inspect `/etc/passwd`, sudoers, crontabs; spot an out-of-place entry | |

### Windows — `T1-W1`, `T1-W2`
| ID | Item | ✅/🔁 |
|---|---|---|
| T1-W1 | List local admins (flag a planted one); create/disable/remove a user; restart a service | |
| T1-W2 | Find a 4625 in the Security log via Event Viewer + `Get-WinEvent`; explain it | |

### Networking — `T1-N1`
| ID | Item | ✅/🔁 |
|---|---|---|
| T1-N1 | IP/subnet/gateway/segment; 5 scored services → ports; **draw the topology** | |

---

## Result

- **All ✅ → Tier 1 passed.** Member is cleared for Phase 1.
- **Any 🔁 → not yet.** Record the exact items and write a remediation plan (see
  [`homework.md`](homework.md)): named partner + close date in early Phase 1. Re-test just those items.

## Phase 0 exit gate (team level)
Met when the team as a whole is at Tier 1 — every member either ✅ or on an owned remediation plan with
a near-term close date. Note in the Phase 0 AAR: which items were hardest across the team (usually
`T1-L3`), so Phase 1 warm-ups can keep re-drilling them.
