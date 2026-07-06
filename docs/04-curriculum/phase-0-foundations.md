# Phase 0 — Foundations (Weeks 1–7, Jul–Aug)

**Goal:** get every member — including total beginners — to a baseline where defending a system makes
sense. You cannot defend a box you can't operate.

**Council lens:** the Coach owns this phase. Early wins, visible progress, and psychological safety
matter more than content volume. Pair beginners with steadier members; nobody watches.

**Exit gate:** every member passes **Tier 1** in [`02-readiness-rubric.md`](../02-readiness-rubric.md)
(or leaves Week 7 with a written remediation plan and a partner).

## Weeks

| Wk | Focus | Lab spine | Rubric |
|---|---|---|---|
| 1 | Orientation, lab access, git, CCDC & rules of engagement | Clone repo, branch, reach lab, tour the topology | T1-G1, T1-G2 — **built in [`05-week-01-module/`](../05-week-01-module/)** |
| 2 | Linux I — filesystem, users, permissions, processes | Create/remove users, fix permissions, inspect `ps`/`ss` | T1-L1, T1-L2 |
| 3 | Linux II — services, systemd, logs, packages | Break & recover a service; read `journalctl`; patch | T1-L3 |
| 4 | Windows — users/groups, services, Event Viewer, PowerShell | Disable an account, restart a service, find failed logons | T1-W1, T1-W2 |
| 5 | Networking — IP/subnet/port/DNS, `ss`/`netstat`, topology | Map the lab; identify what listens where | T1-N1 |
| 6 | AD concepts + the CCDC scored-service map | Explain AD basics; list scored services from the packet | T1-L4 reinforced |
| 7 | **Foundations checkpoint** + review week | Timed Tier-1 assessment; remediation for anyone short | Tier 1 gate |

## Teaching notes
- **Manual, slow, correct** before fast. Speed comes in Phase 1.
- Re-drill the prior week's skill as each session's warm-up (spaced repetition starts now).
- Use the real lab boxes, not toy VMs, so the environment is familiar by September.

## Resources
- Repo topology & rules: [`Claude.md`](../../CCDC-main-Matt_2026/CCDC-main/Claude.md)
- Quick-reference (preview only; they'll master it later): [`quick-reference.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/quick-reference.md)
