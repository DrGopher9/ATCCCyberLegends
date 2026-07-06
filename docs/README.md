# ATCC CyberLegends — Training Program

This directory is the **training program** for the Alexandria Technical & Community College CCDC
team. The rest of the repository (`CCDC_2026/`, `CCDC-main-Matt_2026/`) is the **reference and
tooling layer**: hardening scripts, the Splunk SIEM, competition runbooks, and playbooks. Those are
what you *use during competition*. The docs here are how a mostly-brand-new team **gets good enough to
use them** — and win.

> Goal: take a brand-new team from zero (July 2026) to **competition-ready for the Minnesota CCDC
> state qualifier (Jan/Feb 2027)**, and on to the **Midwest Regional CCDC**.

## How this program was built

Five perspectives — a **red teamer**, a **blue teamer**, a **white team judge**, a **coach**, and a
**former technical team lead** — shaped one unified plan. See [`00-council-analysis.md`](00-council-analysis.md)
for what each of them said about the current state of the team and repo, and the gaps this program
closes.

## Start here

| If you are... | Read this |
|---|---|
| A **coach** setting up the season | [`01-master-plan.md`](01-master-plan.md), then [`04-curriculum/`](04-curriculum/) |
| A **team member** wondering what you must learn | [`02-readiness-rubric.md`](02-readiness-rubric.md) |
| The **captain** organizing the squad | [`03-team-roles-and-comms.md`](03-team-roles-and-comms.md) |
| Running **this week's** practice | [`04-curriculum/`](04-curriculum/) → the current phase → the week module |
| Building the **next** week's module | [`templates/module-template.md`](templates/module-template.md) |
| Wondering what's **broken in the repo** | [`06-repo-gaps-backlog.md`](06-repo-gaps-backlog.md) |

## The season at a glance

| Phase | Window | Theme |
|---|---|---|
| 0 — Foundations | Jul–Aug | Linux/Windows admin, networking, CLI, git, rules of engagement |
| 1 — Defensive Core | Sep | Hardening, credentials, host firewalls, Splunk basics, IR |
| 2 — Specialize | Oct | Own a box; red team attacks it; detect + defend; hunt persistence |
| 3 — Integrate & Injects | Nov | Team ops, inject workflow, documentation, comms, mini-scrimmages |
| 4 — Live-Fire & AAR | Dec–Jan | Full scrimmages vs. red team, After-Action Reviews, dress rehearsals |
| 5 — Taper & Qualifier | Late Jan–Feb | Final prep, logistics, rest, compete; Regional bridge if we win |

Full detail in [`01-master-plan.md`](01-master-plan.md).

## The weekly rhythm

Every week during the season:

1. **Weeknight session (2–3 hr)** — instruction + guided lab. Led by the facilitator guide.
2. **Weekend lab (longer)** — hands-on drills, and later, scrimmages.
3. **Individual homework** — before the next session, done solo, checked at the top of the next
   session.

Each week is one module folder — see [`05-week-01-module/`](05-week-01-module/) for the built
template.

## How "ready" is measured

Two gates, both in [`02-readiness-rubric.md`](02-readiness-rubric.md):

1. **Tiered role checklists** — every member proves fundamentals (Tier 1), core defense (Tier 2), and
   specialty mastery (Tier 3).
2. **Capstone scored scrimmage** — the team must hit target thresholds (service uptime, injects on
   time, red-team footholds evicted, clean documentation and comms).

## Conventions

- **Reference, don't copy.** When a module needs a hardening step, it points at the real script in
  `CCDC_2026/` or `CCDC-main-Matt_2026/` rather than duplicating it.
- **Confirm the rules.** Where a CCDC rule or scored-service list is uncertain, docs say *"confirm
  against the current MN/Midwest team packet"* — the packets change yearly. Current packets:
  `CCDC_2026/2026MWCCDCQTeamPack.pdf` and `CCDC-main-Matt_2026/CCDC-main/MWCC DCQ Team Pack.pdf`.
- **Defensive only.** This is a blue-team program. Offensive tooling exists solely so the coach/alumni
  red team can pressure-test the squad in the lab. See the rules of engagement in
  [`CCDC-main-Matt_2026/CCDC-main/Claude.md`](../CCDC-main-Matt_2026/CCDC-main/Claude.md).
