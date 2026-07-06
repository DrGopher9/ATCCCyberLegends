# Week 1 — Facilitator Guide: Orientation, Lab, Git & Rules of Engagement

> **Phase 0, Week 1.** This is the built template every future week copies (see
> [`../templates/module-template.md`](../templates/module-template.md)). It's written so *any* coach
> can run the session cold.

**Rubric targets:** `T1-G1` (reach the lab, clone/pull the repo, work on a branch),
`T1-G2` (state the rules of engagement and 3 things that cause point loss/DQ). See
[`../02-readiness-rubric.md`](../02-readiness-rubric.md).

**Council lens for this week:** the Coach (first impressions, psychological safety, early win) and the
White Team Judge (the rules are load-bearing from day one).

**You need:** the replica lab reachable, repo access sorted for every member, a projector/screen, and
the current MN/Midwest team packet on hand.

---

## Learning objectives

By the end of the weeknight session, every member can:
1. Explain in one sentence what CCDC is and how it's scored (services + injects − penalties).
2. State the rules of engagement and name three things that cost points or cause DQ.
3. Reach the lab and identify the major systems on the topology.
4. Clone/pull the repo and make a change on a branch (never on `main`).

By the end of the weekend lab, every member can do all of the above **unaided**.

---

## Weeknight session plan (2–3 hours)

### 0:00–0:15 — Welcome & the map (Coach)
- Who's here, what the season looks like (show the calendar from [`../01-master-plan.md`](../01-master-plan.md)).
- The promise: *"You don't need to know any of this yet. By January you'll defend a live network
  against a real attacker. We get there one week at a time."*
- Set the norm: **hands on keyboards, questions encouraged, nobody watches.**

### 0:15–0:45 — What is CCDC, and how do you win? (whiteboard)
Cover, simply:
- **You are the blue team** running a small company's IT. A live **red team** attacks. **White team**
  judges, sends business tasks (**injects**), and enforces rules.
- **Scoring** = uptime of scored services **+** injects completed on time **−** penalties (services
  down, red-team compromises, rule violations, unprofessional conduct).
- **The counter-intuitive truth:** most rookie teams lose points to *themselves* (breaking their own
  services, missing injects) more than to the red team. That's what this whole season fixes.
- Show the topology from [`../../CCDC-main-Matt_2026/CCDC-main/Claude.md`](../../CCDC-main-Matt_2026/CCDC-main/Claude.md).

### 0:45–1:15 — Rules of Engagement (the load-bearing part)
Walk the **Forbidden / Allowed** lists in [`Claude.md`](../../CCDC-main-Matt_2026/CCDC-main/Claude.md)
§3. Emphasize the DQ-level ones:
- ❌ Attacking/scanning other teams or the red team infrastructure
- ❌ DoS / traffic flooding; blocking the scoring engine
- ❌ Changing IPs/hostnames without inject approval; breaking public access
- ✅ Patching, hardening, host firewalls, logging, credential rotation, IR

> **Confirm against the current MN/Midwest team packet** (`CCDC_2026/2026MWCCDCQTeamPack.pdf`) — rules
> shift year to year. If the packet and `Claude.md` disagree, the packet wins.

Have each member write down **three things that cause point loss or DQ** — that's the `T1-G2` check.

### 1:15–2:15 — Guided lab: reach the lab + git workflow
Run [`lab-exercises.md`](lab-exercises.md) together, step by step. Everyone at a keyboard. Slow is
fine — this is the environment they'll live in for seven months.

### 2:15–2:30 — Debrief & assign homework
- Recap the four objectives; take questions.
- Assign [`homework.md`](homework.md).
- Preview Week 2: Linux fundamentals.

---

## Weekend lab plan (3–5 hours)

- **Warm-up (30m):** each member reaches the lab and clones/branches **unaided** while you observe —
  this is the `T1-G1` check.
- **Topology scavenger hunt (60m):** in pairs, find and label every scored system on the topology;
  note IP and role. Builds the mental map they'll need all season.
- **Rules quiz + discussion (30m):** scenario cards — *"The red team is hammering SSH. Can you block
  their whole subnet at the perimeter?"* (Careful — don't block the scoring engine. Confirm the
  packet.) Reinforces `T1-G2`.
- **Git practice (45m):** everyone makes a branch, edits a scratch file, commits, and opens a
  merge/PR request per the repo rule (**never push to `main`** — see the root
  [`README.md`](../../README.md)).
- **Assessment (30m):** run [`assessment.md`](assessment.md); record pass / needs-another-rep per
  member.
- **AAR (15m):** what went well, what was confusing, what to adjust for Week 2.

---

## Facilitator notes & common snags
- **Access will break for someone.** Have repo access and lab creds pre-provisioned; budget slack.
- **Beginners freeze at the terminal.** Pair them with a steadier member for the guided lab, then
  have them redo it solo in the weekend warm-up.
- **Don't over-teach the rules as legalese.** Anchor them to *"this costs points / this gets you
  removed."*
- **Keep it a win.** Week 1 should end with every member feeling *"I can do this."* That feeling is
  the retention lever for the whole season (Coach's non-negotiable).

## Definition of done for Week 1
Every member has `T1-G1` and `T1-G2` marked ✅, or has a named partner and a plan to close them before
Week 2. Record results in the team's rubric-tracking sheet.
