# Week 23 — Fix-It + Cross-Training Drills

Two workstreams: close Week-22's gaps, and prove every box has a real backup. Pick fix drills from the
Week-21 menu that match your top-3; the cross-training drill below is the same for every box.

---

## Workstream 1 — Close the Week-22 top-3
Use the [Week-21 fix-it menu](../05-week-21-module/lab-exercises.md) keyed to your gaps (injects,
eviction stickiness, self-owns, comms, docs, stamina, lateral-movement detection). Rule unchanged: a fix
is **closed** only when you re-create the failing scenario and show it now succeeds. Log each closure.

---

## Workstream 2 — Backup Runs the Box
For **each** box, run this with the **primary unavailable** (out of the room / on another task). The
**backup** runs the box solo through a compressed scenario:

1. **First-30 on the box:** credential sweep + persistence sweep + firewall (ICMP up except PA core) +
   forwarder + backup + log.
2. **A foothold:** the red team plants persistence; the backup **detects it** (from the box's baseline
   + Splunk), **evicts** it (mechanism, not symptom), and **confirms it's gone**.
3. **A service hiccup:** the scored service drops; the backup **recovers** it and **verifies** it serves.
4. **Document:** the backup logs every action on the board.
5. **Coupled awareness:** if it's AD, the backup knows mail depends on it; if it's network, the backup
   knows the ICMP/scoring rules; etc.

Only after the backup finishes does the primary debrief them. Rotate through all boxes so **every box
has two people who've run it under pressure.**

### Cross-training coverage grid
Fill this in — the goal is two ✅ per box before Week 24:

| Box | Primary | Backup ran it solo? |
|---|---|---|
| AD/DNS | | |
| Web/FTP | | |
| E-Comm | | |
| Email/Webmail | | |
| Network (PA/FTD/VyOS) | | |
| Splunk | | |

---

## Done?
You've had a good Week 23 if every Week-22 top-3 is closed **and** every box in the grid has a backup who
ran it solo under pressure. Any box with only one operator is a Week-24 risk — note it. Individual
prep: [`homework.md`](homework.md).
