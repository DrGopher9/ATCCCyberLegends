# Week 16 — Facilitator Guide: Roles, Comms Protocol & the First 30 Minutes

> **Phase 3, Week 16.** Built from [`../templates/module-template.md`](../templates/module-template.md).
> Phase 3 is team-level — the boxes are the same, but now you operate as one unit.

**Rubric targets:** team-level operation of the roles/comms in [`../03-team-roles-and-comms.md`](../03-team-roles-and-comms.md);
reinforces every member's Tier-2/3 skills under coordination. Feeds the capstone dimensions
"first 30 minutes," "communication," and "no self-inflicted outages" in
[`../02-readiness-rubric.md`](../02-readiness-rubric.md).

**Council lens:** the **Former Tech Lead** owns this week. Individual specialists don't win CCDC —
coordinated teams do. The single most common rookie failure is the best technician becoming captain and
disappearing into a box while the team loses the floor. This week fixes that.

**You need:** roles assigned (from Phase 2 specialties, per [`../03-team-roles-and-comms.md`](../03-team-roles-and-comms.md)),
a captain designated, the full lab available, and a shared board (change-log + incident list) the whole
team can see.

---

## Learning objectives
By end of the week, the **team** can:
1. Run with assigned roles and a captain who **coordinates, not keyboards**.
2. Use the comms protocol: call an incident in the standard form; captain runs the triage loop; clean
   handoffs; one owner per incident.
3. Execute the **First 30 Minutes** runbook in parallel across all boxes, on the clock.

## Weeknight session plan (2–3 hr)
- **0:00–0:15 — Warm-up:** each specialist runs one Tier-2/3 skill on their box (keeps skills warm).
- **0:15–0:45 — Frame roles & comms:** walk [`../03-team-roles-and-comms.md`](../03-team-roles-and-comms.md)
  — the 8 roles, the bench, and critically **the captain doesn't touch keyboards**. Teach the incident
  call format and the captain's triage loop (protect scored services → evict → injects → hardening).
- **0:45–1:05 — Demo the First 30 Minutes:** walk the opening runbook (credential sweep → persistence
  sweep → firewall/ICMP → logging → backup → log it) as a *coordinated* drill, not six solo efforts.
- **1:05–2:15 — Guided team lab:** run [`lab-exercises.md`](lab-exercises.md) — a timed First-30
  followed by comms drills.
- **2:15–2:30 — Debrief + assign [`homework.md`](homework.md); preview Week 17 (injects).**

## Weekend lab plan (3–5 hr)
- **Warm-up (20m):** the incident-call format and triage loop, recited.
- **First-30 reps (60m):** run the opening runbook as a team, timed, three times — the captain
  coordinating, specialists in parallel, everything logged on the shared board. Target: all boxes swept
  + firewalled + logging within 30 minutes. Get faster each rep.
- **Comms pressure drill (45m):** facilitator injects simultaneous events ("Ecom web down," "spray on
  AD," "unknown listener on FTP") verbally; team must call them correctly, the captain triages, one
  owner per incident, clean handoffs. No box work required — this drills the *talking*.
- **Assessment (30m):** run [`assessment.md`](assessment.md).
- **AAR (15m):** where comms broke down; did the captain stay off keyboards?

## Facilitator notes & common snags
- **The captain will want to fix things.** Hold the line: the captain coordinates, watches the clock,
  owns the White Team/inject relationship, keeps the team calm. Have them physically stand/walk, not
  sit at a box.
- **"Two people, one incident."** The classic failure is two people fighting the same red-team session
  in opposite directions. Drill: one owner per incident, the floater assists.
- **The board is the shared brain.** If it's not on the change-log/incident board, the captain can't
  triage it. Make logging part of the comms reflex, not an afterthought.
- **Silence is a failure mode.** A specialist quietly working a fire the captain doesn't know about is
  as bad as not working it. Call it out loud, in format.

## Definition of done
The team can run a coordinated First-30 within the time budget, uses the comms protocol under simultaneous
events, and has a captain who runs the floor without touching keyboards. Rough edges are expected — this
is the first team rep. Note them for Week 19's mini-scrimmage.
