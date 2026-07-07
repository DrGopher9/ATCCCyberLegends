# Week 20 — Running Full Scrimmage #1 (Moderate)

Same runbook as the Week 19 mini-scrimmage, at **moderate intensity and full length (half-day)**. The
red team is a competent attacker now — they'll get a foothold somewhere; your job is to see it, evict
it, and report it while holding services and completing injects.

Use the [scorecard](../templates/scrimmage-scorecard.md) and [AAR template](../templates/aar-template.md).

---

## Before the whistle
- Boards up (change-log, incidents, password-tracker); roles + captain confirmed; backups ready.
- Red team briefed to **moderate**: multiple footholds, real persistence, re-entry after eviction,
  probes on the weakest boxes.
- Full service load + a full inject set with staggered deadlines. Scorecard + timer ready.

## Opening — First 30 Minutes (as a team)
- [ ] Every box: credential sweep + persistence sweep
- [ ] Every box: firewall up, scored service verified, **ICMP up except PA core**
- [ ] Every box: forwarder reporting; configs backed up; everything logged
- [ ] Captain tracks the board + clock; injects owner watches for the first inject

## Sustained play (rest of the scrimmage)
Captain triages by priority (**protect services → evict → injects → harden**):
- [ ] **Hold services:** HTTP/HTTPS/SMTP/POP3/DNS up; fast recovery; **no self-owns**
- [ ] **Injects:** owned, executed, PDF before deadline, logged — don't let a fire eat the deadline
- [ ] **Incidents:** detect footholds; capture evidence first; contain + evict without breaking a
      service; **re-check that eviction stuck** (moderate red team re-enters); file scorable IR reports
- [ ] **Comms:** incidents in format; one owner per incident; clean handoffs; captain off keyboards
- [ ] **Docs:** board audit-ready throughout — watch for hour-3 decay

## Facilitator scoring
Track live on the scorecard: uptime %, self-owns, injects on-time/quality, footholds
detected/evicted/reported, first-30, docs, comms. Note *when* things slipped (early vs. late) for the AAR.

## AAR (immediately after)
Run the full [AAR template](../templates/aar-template.md): facts → what went well → root causes (team
seams) → **top-3 fixes with owners/dates** → rubric impact. Compare the scorecard to the Week-19
baseline.

## Done?
You've run Full Scrimmage #1 if the team played a moderate half-day as one unit, handled real footholds
with reports, and produced an owned top-3 fix list. Those fixes go to Week 21. Your follow-through is
[`homework.md`](homework.md).
