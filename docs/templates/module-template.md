# Week NN — Module Template

Copy this into `05-week-NN-module/` as **four files** to build a new week. The built
[`../05-week-01-module/`](../05-week-01-module/) is the worked example — match its shape and depth.

```
05-week-NN-module/
  facilitator-guide.md   ← from §1 below
  lab-exercises.md       ← from §2
  homework.md            ← from §3
  assessment.md          ← from §4
```

Fill from the week's row in [`../01-master-plan.md`](../01-master-plan.md) and its phase overview in
[`../04-curriculum/`](../04-curriculum/). **Every assessment must tie to specific rubric IDs** from
[`../02-readiness-rubric.md`](../02-readiness-rubric.md).

---

## §1 — facilitator-guide.md

```markdown
# Week NN — Facilitator Guide: <TITLE>

**Phase <N>, Week <NN>.**
**Rubric targets:** <IDs, e.g. T2-C1, T2-C6>
**Council lens for this week:** <which persona(s) own it and why>
**You need:** <lab state, credentials, materials, prep>

## Learning objectives
By end of weeknight session, every member can: <3–4 objectives>
By end of weekend lab, every member can do them **unaided**.

## Weeknight session plan (2–3 hr)
- 0:00–0:15 Homework check-in / warm-up (re-drill a prior-week skill — spaced repetition)
- 0:15–0:XX New concept + demo
- 0:XX–X:XX Guided lab (run lab-exercises.md together)
- last 15m Debrief + assign homework + preview next week

## Weekend lab plan (3–5 hr)
- Warm-up drill (prior skill)
- Main hands-on lab / (Phase 3+) scrimmage
- Assessment (run assessment.md)
- AAR (what went well / confusing / adjust)

## Facilitator notes & common snags
<known failure points, pairing guidance, guardrails>

## Definition of done
Every member has <rubric IDs> marked ✅ or a named partner + plan to close before next week.
```

## §2 — lab-exercises.md

```markdown
# Week NN — Lab Exercises: <TITLE>

**Prereqs:** <access, box state, tools>

## Exercise 1 — <name>
<step-by-step, real commands, expected output>

## Exercise 2 — <name>
...

> Manual-first where hardening is involved: do it by hand before running any repo script, and always
> verify the scored service still works + know the rollback (Blue Teamer's rule).

## Done?
You've hit the objectives if you: <checklist>. Repeat <which exercises> solo for homework.
```

## §3 — homework.md

```markdown
# Week NN — Homework (solo, before next session)

Do alone; prove you can do it without help. Budget ~1–2 hr.

## 1. <core skill> from memory
- [ ] <steps>

## 2. <verify / apply>
- [ ] <steps>

## Bring to next session
- <artifacts needed for the assessment>
```

## §4 — assessment.md

```markdown
# Week NN — Assessment

Member **performs** each item while observed; mark ✅ / 🔁. Record in the rubric sheet.
**Covers rubric items:** <IDs>

## Part A — <ID>: <skill> (hands-on, unaided)
Time budget: <X min>
| # | Task | ✅/🔁 |
|---|---|---|
| A1 | <task> | |

**Pass A** = <criterion>.

## Scoring
- Pass → mark <IDs> ✅.
- 🔁 → note which items, pair + re-check next week.
```

---

## Quality bar for a finished module
- Runnable by a coach who wasn't in the design conversation.
- Every objective maps to a rubric ID; every rubric ID has an assessment item.
- Hands-on, not lecture — members touch keyboards.
- Includes spaced-repetition warm-up of a prior skill.
- Names the council lens so no concern (safety, injects, comms) silently drops.
