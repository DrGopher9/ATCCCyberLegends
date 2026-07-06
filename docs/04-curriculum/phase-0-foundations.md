# Phase 0 — Foundations (Weeks 1–7, Jul–Aug)

**Goal:** get every member — including total beginners — to a baseline where defending a system makes
sense. You cannot defend a box you can't operate.

**Council lens:** the Coach owns this phase. Early wins, visible progress, and psychological safety
matter more than content volume. Pair beginners with steadier members; nobody watches.

**Exit gate:** every member passes **Tier 1** in [`02-readiness-rubric.md`](../02-readiness-rubric.md)
(or leaves Week 7 with a written remediation plan and a partner).

## Weeks

All seven weeks are built out as full modules (facilitator guide / lab / homework / assessment).

| Wk | Focus | Lab spine | Rubric | Module |
|---|---|---|---|---|
| 1 | Orientation, lab access, git, CCDC & rules of engagement | Clone repo, branch, reach lab, tour the topology | T1-G1, T1-G2 | [`05-week-01-module/`](../05-week-01-module/) |
| 2 | Linux I — filesystem, users, permissions, processes | Create/remove users, fix permissions, inspect `ps`/`ss` | T1-L1, T1-L2 | [`05-week-02-module/`](../05-week-02-module/) |
| 3 | Linux II — services, systemd, logs, packages | Break & recover a service; read `journalctl`; patch | T1-L3 | [`05-week-03-module/`](../05-week-03-module/) |
| 4 | Windows — users/groups, services, Event Viewer, PowerShell | Disable an account, restart a service, find failed logons | T1-W1, T1-W2 | [`05-week-04-module/`](../05-week-04-module/) |
| 5 | Networking — IP/subnet/port/DNS, `ss`/`netstat`, topology | Map the lab; identify what listens where | T1-N1 | [`05-week-05-module/`](../05-week-05-module/) |
| 6 | AD concepts + the CCDC scored-service map | Read-only AD tour; recite the scored-service map | reinforces T1-N1/T1-G2; previews T3-AD | [`05-week-06-module/`](../05-week-06-module/) |
| 7 | **Foundations checkpoint** + review week | Review circuit; full Tier-1 gate; remediation for anyone short | **Tier 1 gate** | [`05-week-07-module/`](../05-week-07-module/) |

> `T1-L4` (inspect `/etc/passwd`/sudoers/crontabs) is introduced in Week 2, reinforced through the
> phase, and formally checked at the Week 7 Tier-1 gate.

## Teaching notes
- **Manual, slow, correct** before fast. Speed comes in Phase 1.
- Re-drill the prior week's skill as each session's warm-up (spaced repetition starts now).
- Use the real lab boxes, not toy VMs, so the environment is familiar by September.

## Resources
- Repo topology & rules: [`Claude.md`](../../CCDC-main-Matt_2026/CCDC-main/Claude.md)
- Quick-reference (preview only; they'll master it later): [`quick-reference.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/quick-reference.md)
