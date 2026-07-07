# Week 16 — Lab Exercises: Team Ops Drills

These are **team** drills. Everyone has a role ([`../03-team-roles-and-comms.md`](../03-team-roles-and-comms.md));
the captain coordinates and does **not** touch a keyboard. Use a shared board for the change-log and
incident list so the whole team — especially the captain — can see current fires.

---

## Drill 1 — The First 30 Minutes, as a team (timed)
On the whistle, every specialist works their box **in parallel**; the captain tracks progress on the
board and calls the clock. The runbook (from [`../03-team-roles-and-comms.md`](../03-team-roles-and-comms.md)):

1. **Credential sweep** — rotate creds, kill unknown accounts (admin/root free; careful with AD).
2. **Persistence sweep** — accounts/keys/cron/tasks/services.
3. **Firewall up** — host + PA/FTD policy; scored services allowed; **keep ICMP (except PA core port)**;
   verify each service still serves.
4. **Logging on** — confirm your forwarder reports to Splunk.
5. **Back up** — config/state before heavy hardening.
6. **Log it** — every action on the shared board from minute one.

**Captain's job during the drill:** confirm each box's sweep is done, watch for the first "injects"
(Week 17), keep a running status on the board, and re-assign help to whoever's behind. **Target: every
box done inside 30 minutes.** Run it 2–3 times; beat your time.

## Drill 2 — Calling an incident (the format)
Practice the standard call until it's reflex:
> **"Incident — [system] — [what you see] — I'm [containing / need help]."**

Facilitator names a scenario; the owner calls it in format; the captain acknowledges and triages. Rounds:
- "Unknown listener on 4444, Ecom" → *"Incident — Ecom — unknown listener on 4444 — I'm containing."*
- "Spray of failed logons on AD" → owner calls it; captain decides priority vs. current fires.
Do ten fast reps. Short, structured, loud enough for the captain to hear.

## Drill 3 — The captain's triage loop
With several items on the board at once, the captain runs the loop out loud, every couple of minutes:
1. Scan the board — what's down, what's under attack, what injects are due.
2. Assign the hottest fire to its owner (or the floater); **confirm someone owns it.**
3. Priority order: **protect scored services → evict → injects → hardening.**
4. Watch the clock on any deadline.
Rotate a second person as backup captain so the role has depth.

## Drill 4 — Handoffs & "one owner per incident"
- **Handoff:** when passing a box (break, shift, backup takes over), state **what you changed, what's
  still broken, where the log is.** No silent handoffs.
- **One owner:** facilitator points two people at the same incident on purpose; the team must resolve to
  a single owner (the floater assists, the owner decides). Two people pulling opposite directions on one
  session is the failure to kill here.

## Done?
You've hit the objectives if the team ran a coordinated First-30 inside the time budget, called incidents
in format, and the captain triaged simultaneous events without touching a keyboard. Individuals review
the runbook + comms format solo for [`homework.md`](homework.md).
