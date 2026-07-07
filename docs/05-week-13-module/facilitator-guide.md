# Week 13 — Facilitator Guide: The Red Team Attacks Your Box (Observe & Detect)

> **Phase 2, Week 13.** Built from [`../templates/module-template.md`](../templates/module-template.md).

**Rubric targets:** the **detection** item of each track — `T3-AD4`, `T3-WEB4`, `T3-EC4`, `T3-EM4`,
`T3-NET3`, `T3-SP4`. See [`../02-readiness-rubric.md`](../02-readiness-rubric.md).

**Council lens:** the **Red Teamer** owns this week — it's the whole reason for the attack-first design.
Members feel the threat against *their* box before they memorize defenses. The Blue Teamer co-drives the
detection half: every attack must be *seen* (in a log or Splunk) before it can be evicted.

**You need:** the live coach/alumni red team, a **safe attack script per track** run against the lab
(non-destructive — the point is to generate detectable signal, not to wreck boxes), and each member's
Week-12 baseline in hand. Members **only observe and detect this week — no hardening yet.**

---

## How to run the red team this week (facilitator/red team)
- Run a **scripted, bounded** attack against each box that maps to a real technique but is safe to
  repeat: credential spray, a web-shell drop, a scheduled-task/cron persistence, a firewall/config
  poke, a forwarder kill. See the per-track list in [`lab-exercises.md`](lab-exercises.md).
- **Announce nothing.** Let members detect from their baseline + Splunk. Then reveal what you did and
  compare against what they caught.
- Keep it **low-stakes**: this is "here's what it looks like," not a graded scrimmage. Morale matters
  (Coach's guardrail) — getting "caught not catching it" now is the lesson.
- Repeat the attack on request so members can watch the signal appear a second time.

## Learning objectives
By end of the week, every member can, **for their box**:
1. Recognize the attack(s) against it as a **deviation from their Week-12 baseline**.
2. Find the attack in the logs and in Splunk (the right search / dashboard).
3. Describe the attacker's goal (foothold? persistence? cred theft? service disruption?).
4. Capture the evidence needed for an incident report (source IP, timeline) — **without evicting yet**.

## Weeknight session plan (2–3 hr)
- **0:00–0:15 — Warm-up:** Splunk failed-login search + "which hosts report" (keeps `T2-S1/S2` warm).
- **0:15–0:35 — Frame:** the Red Team's timeline (from [`red-team-playbook.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/red-team-playbook.md)):
  first 30 min creds/backdoors, then priv-esc, lateral movement, persistence. This week you learn to
  *see* stages 1–2 on your box.
- **0:35–2:15 — Live-detect lab (split by track):** red team runs the attacks; members work their
  section of [`lab-exercises.md`](lab-exercises.md) to detect + capture evidence. Reveal + compare.
- **2:15–2:30 — Debrief + assign [`homework.md`](homework.md); preview Week 14 (now you defend).**

## Weekend lab plan (3–5 hr)
- **Warm-up (20m):** the detection reflex — data flowing? run the search.
- **Detection reps (100m):** red team re-runs a rotating set of attacks; each member races to detect
  the one on their box, name the technique, and capture source IP + timeline. Multiple rounds; members
  should get faster and calmer.
- **Cross-track show-and-tell (20m):** each member shows the rest of the team what their box's attack
  looked like in Splunk — so the whole team recognizes more techniques.
- **Assessment (30m):** run [`assessment.md`](assessment.md).
- **AAR (15m).**

## Facilitator notes & common snags
- **No eviction this week.** If members start deleting/blocking, redirect them — detection and evidence
  capture first (Week 14 is defense). Evicting before you understand the attack destroys the evidence
  you need for the report.
- **Baseline is the detection tool.** Members who did Week 12 well spot the deviation instantly; those
  who didn't will flail — that's the feedback that makes Week 12 matter.
- **Normalize getting owned.** In a low-stakes setting, missing an attack is a lesson, not a failure.
  Keep it light; the goal is calm recognition under pressure by Phase 4.
- Coupled boxes: the AD spray may show up in mail-auth logs too — good teaching moment on shared signal.

## Definition of done
Every member can detect their box's attack, find it in Splunk/logs, name the technique, and capture the
evidence for a report (their track's detection item, `T3-*4` / `T3-NET3`) — or a partner + plan.
