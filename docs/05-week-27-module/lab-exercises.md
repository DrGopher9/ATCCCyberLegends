# Week 27 — Competition-Day Runbook

The season's playbook, executed live at the Minnesota qualifier. This is the same day you rehearsed in
Week 24. Model: **9am–4pm CST**, injects via NISE (PDF responses), no VM reverts. Stay calm, stay
coordinated, keep documenting.

---

## Before the drop flag ("8am–9am")
- [ ] Log into the **NISE/Team Portal**; respond to the **Welcome inject**; complete survey part 1
- [ ] Set up boards (change-log, incidents, password-tracker); confirm roles + backups
- [ ] Confirm the repo is reachable via the web proxy (you submitted the URL in Week 26)
- [ ] Captain: confirm White-Team contact; brief the priority order one last time

## The opening — First 30 Minutes ("9:00am drop flag")
- [ ] Every box: credential sweep (defaults are known — move fast) + persistence sweep
- [ ] Every box: firewall up, scored service verified, **ICMP up except PA core port**
- [ ] Every box: forwarder reporting; configs backed up; **everything logged from minute one**
- [ ] Captain tracks the board + clock; injects owner watches the portal

## Sustained play (7 hours)
Captain triages (**protect services → evict → injects → harden**); rotate backups to stay fresh:
- [ ] **Services:** keep HTTP/HTTPS/SMTP/POP3/DNS up; recover fast; **no self-owns** (this is the #1
      avoidable point loss)
- [ ] **Injects:** owner logs/assigns each; submit **PDFs before deadline**; address every part;
      professional tone; scores are hidden — no coasting
- [ ] **Incidents:** detect footholds; capture evidence first; contain + evict (make it stick); **file
      scorable IR reports** for real exploitation (not padded)
- [ ] **Comms:** in format; one owner per incident; clean handoffs; captain off keyboards
- [ ] **Docs:** board audit-ready all day; the White Team may check
- [ ] **Conduct:** professional with White Team; **no contact with the red team**; follow all rules
- [ ] **Energy:** breaks, food, rotations — stay sharp to 4pm

## At the close ("~4pm")
- [ ] Final inject/survey submissions in
- [ ] Ensure documentation is complete
- [ ] Debrief as a team (short AAR) while it's fresh

## Done?
You've executed the season's training when the team ran the full qualifier day as one coordinated unit —
opened clean, held services, completed injects, evicted the red team with reports, documented cleanly,
and stayed professional and rested to the end. Follow-through + regional prep: [`homework.md`](homework.md).
