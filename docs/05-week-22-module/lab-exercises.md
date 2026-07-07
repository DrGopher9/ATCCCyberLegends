# Week 22 — Running Full Scrimmage #2 (Heavier)

Same runbook as Weeks 19–20, now **heavier and longer**. The red team moves laterally between segments,
re-enters aggressively, and targets your weak boxes. Hold services + injects + docs while you detect,
evict (make it stick), and report.

Use the [scorecard](../templates/scrimmage-scorecard.md) and [AAR template](../templates/aar-template.md).

---

## Before the whistle
- Boards up; roles + captain confirmed; backups ready to rotate in.
- Red team briefed to **heavy**: simultaneous footholds, lateral movement (PA side ↔ FTD side),
  aggressive re-entry, late-game escalation.
- **Full inject load**, tight/staggered deadlines. Half-to-full-day block. Scorecard + timer ready.

## Opening — First 30 Minutes (as a team)
- [ ] Every box swept (creds + persistence), firewalled (ICMP up except PA core), forwarder reporting,
      backed up, logged — fast and clean, because the red team is heavier this time.

## Sustained play — the heavier tests
Captain triages (**protect services → evict → injects → harden**); watch for the new patterns:
- [ ] **Lateral movement:** a foothold on one box → creds/access to another. Splunk owner + captain
      connect the dots across specialists; coupled boxes (AD↔mail, network↔all) coordinate.
- [ ] **Aggressive re-entry:** eviction must **stick** — hunt the mechanism, re-check, adjust detections.
- [ ] **Full inject load:** more injects, tighter deadlines — the owner + captain protect deadlines hard.
- [ ] **Services under targeted attack:** keep HTTP/HTTPS/SMTP/POP3/DNS up; fast recovery; **no self-owns.**
- [ ] **Docs + comms past hour 3:** sustain the board and the comms protocol through fatigue; rotate
      backups to keep fresh eyes.
- [ ] **IR reports:** one scorable report per real exploitation event; not padded.

## Facilitator scoring
Track the scorecard live; especially note **lateral-movement detection** and whether **Week-21's fixes
held**. Flag any Week-20 repeat as a priority for Week 23.

## AAR
Full [AAR template](../templates/aar-template.md). Key question: **new problems or repeats?** Top-3
fixes (owned/dated) → Week 23. Plot the scorecard trend across Weeks 19 → 20 → 22.

## Done?
You've run Full Scrimmage #2 if the team held heavier + longer pressure, caught lateral movement, made
evictions stick, and produced an owned top-3 → Week 23. Follow-through: [`homework.md`](homework.md).
