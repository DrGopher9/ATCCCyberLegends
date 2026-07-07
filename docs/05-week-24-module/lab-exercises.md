# Week 24 — Running the Dress Rehearsal (Full 7-Hour)

The full runbook at qualifier intensity and full length. This is the closest thing to the real MN
qualifier before you compete. Model **9am–4pm CST**, injects via a NISE-like portal (PDF responses,
hidden scores), no VM reverts. Score the full [scorecard](../templates/scrimmage-scorecard.md); the
capstone thresholds must be hit.

---

## Pre-brief / setup (30 min, "8:30am")
- Boards up; portal ready for inject delivery + PDF submission; roles + captain + backups confirmed;
  energy/rotation/food plan set. Red team + White Team briefed to qualifier intensity.

## The opening — First 30 Minutes ("9:00am drop flag")
- [ ] Every box: credential sweep + persistence sweep (defaults are known — move fast)
- [ ] Every box: firewall up, scored service verified, **ICMP up except PA core**
- [ ] Every box: forwarder reporting; configs backed up; everything logged
- [ ] Captain runs the board + clock; injects owner watches the portal for the first inject

## Sustained play (7 hours) — hold ALL fronts
Captain triages (**protect services → evict → injects → harden**); rotate backups to sustain:
- [ ] **Services:** HTTP/HTTPS/SMTP/POP3/DNS ≥ 90% uptime; fast recovery; **zero self-owns**
- [ ] **Injects:** ≥ 90% on time to standard; PDFs to the portal before deadline; scores hidden so no
      coasting; owner runs the deadline clock
- [ ] **Incidents:** detect every foothold; capture evidence first; contain + evict (make it stick);
      **file scorable IR reports** (spec-compliant, not padded) for every exploitation event
- [ ] **Lateral movement:** connect footholds across boxes; coupled boxes coordinate
- [ ] **Comms:** in format; one owner per incident; clean handoffs; captain off keyboards all day
- [ ] **Docs:** board audit-ready for all 7 hours — the real test is late-game
- [ ] **Energy:** rotations, breaks, food — stay sharp past hour 4

## Facilitator live scoring
Track the full scorecard through the day; timestamp when anything slips (early vs. late). Note whether
each capstone threshold is met by the end.

## AAR (60 min) — the season's most important debrief
Run the full [AAR template](../templates/aar-template.md). Central question: **did we hit all capstone
thresholds?** For each miss: root cause + an owned Week-25 fix. Plot the trend across all scrimmages.
Blameless, specific.

## Done?
You've run the dress rehearsal if the team completed a full-length qualifier-condition scrimmage and
either hit all capstone thresholds or produced a precise, owned top-3 for Week 25. Follow-through:
[`homework.md`](homework.md).
