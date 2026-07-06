# CCDC Training Program — Design Spec

**Date:** 2026-07-06
**Author:** The Council (Red Teamer, Blue Teamer, White Team Judge, Coach, Former Technical Team Lead) via Claude
**Status:** Approved design — blueprint for building the `docs/` curriculum
**Owner:** Matt McCullough (Head Coach, ATCC CyberLegends)

---

## 1. Purpose

Turn the ATCC CyberLegends repository from a **tool dump** into a **training program** that takes a
mostly-brand-new team from zero to competition-ready for the **Minnesota CCDC state qualifier
(Jan/Feb 2027)** and, on qualification, the **Midwest Regional CCDC**.

The existing repo has strong *reference* and *in-competition* material (hardening scripts, Splunk
SIEM, runbooks, playbooks). What it lacks is **progression, practice regimen, and a way to measure
readiness**. This program supplies that.

## 2. Context & Constraints (from stakeholder interview)

| Dimension | Decision |
|---|---|
| Team experience | Mostly brand new (never competed; some new to Linux/Windows admin) |
| Runway | ~7 months (start Jul 2026 → MN qualifier Jan/Feb 2027) |
| Lab | Full replica CCDC topology available in a hypervisor for live practice |
| Council format | One unified plan; five personas inform it (not five separate docs) |
| Team size | 8 competition + alternates (10–12 total), bench trains alongside |
| Cadence | One weeknight session (2–3 hr) + one longer weekend lab/scrimmage per week |
| Live red team | Yes — coaches/alumni can attack the lab during scrimmages |
| Readiness bar | Per-role competency checklist (tiered) + capstone scored scrimmage |
| Coverage model | Everyone learns a common **core**, then owns **one specialty** system |
| Deliverable depth (this pass) | Master plan + Week 1 built as replicable template; full season built in later passes |
| Repo work | Training plan is the deliverable; council also flags repo gaps as a backlog (no code fixes this pass) |

## 3. Guiding Approach

**Threat-Informed Phased Progression.** Fundamentals first; red-team pressure ramps deliberately.
Rejected alternatives: *scrimmage-first immersion* (brutal/inefficient for beginners) and
*system-by-system rotation* (too slow, delays team-ops muscle). We fold the good part of immersion —
**early low-stakes scrimmages** — into the later phases.

## 4. The Council (five recurring lenses)

Each persona owns a concern that recurs through every phase and every module:

- **Red Teamer** — orders the curriculum by how teams actually get owned (default creds → unpatched
  services → web shells → persistence). Runs live scrimmages and authors attack scenarios.
- **Blue Teamer** — hardening baselines, Splunk detection, IR playbooks, service recovery.
- **White Team Judge** — inject discipline, documentation quality, professionalism, not breaking
  scored services. The quiet point-loss areas.
- **Coach** — pedagogy for beginners: progression, drills, spaced repetition, bench management,
  morale, running effective practices.
- **Former Technical Team Lead** — in-competition ops: roles, comms protocol, time triage, the
  "first 30 minutes" playbook, how the captain runs the floor.

Every built module names which lenses shaped it, so no concern silently drops.

## 5. Season Architecture

| Phase | Window | Theme | Exit condition |
|---|---|---|---|
| **0 — Foundations** | Jul–Aug (~7 wk) | Linux/Windows admin, networking, CLI, git, CCDC rules of engagement | Every member passes Tier-1 fundamentals check |
| **1 — Defensive Core** | Sep (~4 wk) | Universal skills: hardening, credential rotation, host firewalls, Splunk basics, IR fundamentals | Every member passes the Core checklist |
| **2 — Specialize + Threat-Informed** | Oct (~4 wk) | Own a specialty box; red team introduces attacks against it; detect + defend; persistence hunting | Each specialist passes their role Tier-2 check |
| **3 — Integrate & Injects** | Nov (~4 wk) | Full-team ops, inject workflow, documentation, comms protocol, first mini-scrimmages | Team completes a timed inject set + mini-scrimmage |
| **4 — Live-Fire & AAR** | Dec–Jan (~6 wk) | Full scrimmages vs. red team, After-Action Reviews, fix weaknesses, dress rehearsals | Team hits capstone scrimmage thresholds |
| **5 — Taper & Qualifier** | Late Jan–Feb | Final prep, logistics, rest, execute; + Regional bridge if they win | Compete |

**Weekly rhythm:** weeknight session (instruction + guided lab) → weekend lab (drills/scrimmage) →
individual homework before next session. Spaced repetition of prior-phase skills every week.

## 6. Readiness Model

- **Tiered role checklists.** Tier 1 = universal fundamentals; Tier 2 = core defense; Tier 3 =
  specialty mastery. Tiers give beginners visible progress and give the coach a gating mechanism.
- **Capstone scrimmage thresholds.** Team-level: scored-service uptime %, injects completed on time,
  red-team footholds detected + evicted, clean change-log & professional comms. Exact thresholds set
  in the rubric doc.
- **Bench policy.** Alternates train to the same checklist; standings decided by checklist completion
  + scrimmage performance, not seniority.

## 7. Deliverable Structure (`docs/`)

```
docs/
  README.md                     — index + how to run the program
  00-council-analysis.md        — 5 personas' assessment of current repo + gaps
  01-master-plan.md             — season roadmap, phase calendar, weekly rhythm
  02-readiness-rubric.md        — tiered role checklists + scrimmage graduation bar
  03-team-roles-and-comms.md    — roles, bench/alternate plan, in-comp comms protocol
  04-curriculum/                — one overview page per phase (0–5)
      phase-0-foundations.md
      phase-1-defensive-core.md
      phase-2-specialize.md
      phase-3-integrate-injects.md
      phase-4-live-fire.md
      phase-5-taper-qualifier.md
  05-week-01-module/            — FIRST WEEK FULLY BUILT (the replicable template)
      facilitator-guide.md
      lab-exercises.md
      homework.md
      assessment.md
  06-repo-gaps-backlog.md       — prioritized weaknesses the council flags in existing scripts
  templates/
      module-template.md        — blank module scaffold for building future weeks
      aar-template.md           — After-Action Review form
      scrimmage-scorecard.md    — scored-scrimmage scoring sheet
```

**This pass builds:** README, 00–04 (all phase overviews), 02 rubric, 03 roles, the full
`05-week-01-module/`, `06-repo-gaps-backlog.md`, and the three `templates/`. Weeks 2+ are scaffolded
by the phase overviews and built in later passes using `module-template.md`.

## 8. Design for Reuse & Isolation

- **Module template is the unit of reuse.** Every week is one folder matching `05-week-01-module/`:
  facilitator guide + lab + homework + assessment. Building the full season = filling templates, not
  inventing structure each time.
- **The rubric is the single source of truth for "ready."** Modules reference rubric items by ID; the
  master plan references phases; nothing duplicates the readiness criteria.
- **Existing competition-tools are cited, not copied.** The curriculum points members at the existing
  runbooks/playbooks as the reference layer; the docs teach *how to reach the point of using them*.

## 9. Non-Goals (this pass)

- No fixing or rewriting existing hardening scripts (flagged in `06` backlog only).
- No building of Weeks 2+ content (scaffolded, not written).
- No changes to lab/hypervisor setup automation.
- Nothing that assumes CCDC rules beyond what the existing `Claude.md` records; where specifics are
  unknown, the docs say "confirm against current MN/Midwest packet."

## 10. Success Criteria for the Deliverable

A new coach or returning captain can open `docs/README.md` and understand: the season, what each week
does, how members are assessed, how the team operates in competition, and how to build the next week's
module — without needing the person who wrote it.
