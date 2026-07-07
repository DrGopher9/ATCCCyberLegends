# Week 19 — Running the Mini-Scrimmage

This is a **compressed (~2–2.5 hr), gentle** dress rehearsal that puts all of Phase 3 together. It's
scored on the [scrimmage scorecard](../templates/scrimmage-scorecard.md), but the score is a **baseline
to beat**, not a cut. Below is the runbook for the team (and the facilitator/red-team notes).

---

## Before the whistle (facilitator + team)
- **Boards up:** change-log, incident list, password-tracker visible.
- **Roles confirmed:** captain (off keyboards), injects owner, docs owner, six specialists + backups
  ([`../03-team-roles-and-comms.md`](../03-team-roles-and-comms.md)).
- **Red team briefed to GENTLE:** default creds, one or two footholds, a bit of persistence, a light
  probe or two — catchable if the team is paying attention.
- **Scorecard + timer ready** ([`../templates/scrimmage-scorecard.md`](../templates/scrimmage-scorecard.md)).

## Phase 1 (first 30 min) — the opening
On the whistle, run the **First 30 Minutes** as a team (Week 16):
- [ ] Every box: credential sweep + persistence sweep
- [ ] Every box: firewall up, scored service verified, **ICMP up except PA core**
- [ ] Every box: forwarder reporting
- [ ] Back up configs; log everything on the board
- [ ] Captain tracks the board and calls the clock; the injects owner watches for the first inject

## Phase 2 (remaining time) — hold the line
Run concurrently, captain triaging by priority (**protect scored services → evict → injects → harden**):
- [ ] **Services:** keep HTTP/HTTPS/SMTP/POP3/DNS up; recover fast if one drops; **no self-owns**
- [ ] **Injects:** owner logs each, assigns, team executes, submits **PDF before deadline**, logs it
- [ ] **Incidents:** detect the red team's footholds; capture evidence; contain + evict without breaking
      a service; **file scorable IR reports** (not padded)
- [ ] **Comms:** incidents called in format; one owner per incident; clean handoffs
- [ ] **Docs:** board stays current and audit-ready throughout

## Facilitator scoring (on the scorecard)
Track live: service uptime %, self-inflicted outages, injects on time + quality, footholds
detected/evicted/reported, first-30 completion, docs + comms marks. This produces the baseline the team
improves on in Phase 4.

## After the whistle — the AAR (don't skip)
Run the full [AAR template](../templates/aar-template.md):
1. What was supposed to happen / what actually happened (facts, blameless)
2. What went well (name it — reinforce good habits)
3. What didn't, and the **root cause** (usually a team seam, not an individual)
4. **Top-3 fixes** with owners and a due date (carry into Phase 4)
5. Rubric/readiness impact — which capstone dimensions did we hit or miss?

## Done?
You've hit the objective if the team ran a full compressed scrimmage as one unit — opened with the
First-30, held services, completed injects, handled light incidents with reports, kept clean docs — and
produced an honest AAR with an owned top-3 fix list. That top-3 list is your [`homework`](homework.md)
into Phase 4.
