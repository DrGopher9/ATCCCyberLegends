# Team Roles & Communication

Builds on the existing [`team-roles.md`](../CCDC-main-Matt_2026/CCDC-main/competition-tools/team-roles.md).
That doc defines the roles; this one adds **the bench plan, cross-training/backups, and the drilled
comms protocol** — the parts that only work if you practice them (per the Former Tech Lead's analysis
in [`00-council-analysis.md`](00-council-analysis.md)).

CCDC competes **8** on the floor. You are training **10–12** (8 + alternates). Everyone trains as an
equal; the starting 8 is earned, not assigned by seniority.

---

## Roles (the competition 8)

Boxes map to the **actual 11-VM topology** in [`07-competition-reference.md`](07-competition-reference.md)
(6 servers, 2 workstations, Palo Alto + Cisco FTD + VyOS). More boxes than people, so some roles own
two.

| Role | Owns | Backs up | Rubric track |
|---|---|---|---|
| **Captain** | Coordination, injects relationship, White Team contact, the clock, morale | *Everything* (knows enough to redirect, doesn't fix) | T3 of their secondary box |
| **Windows AD Lead** | AD/DNS (Server 2019, `.102`); Windows 11 Wks | Windows Web/FTP | T3-AD |
| **Windows Web/FTP Lead** | Server 2019 Web/IIS (`.101`), Server 2022 FTP (`.104`) | Windows AD | T3-WEB |
| **E-Commerce Lead** | Ubuntu Ecom (`.30`, HTTP/HTTPS); Ubuntu Wks | Email | T3-EC |
| **Email/Webmail Lead** | Fedora mail + webmail (`.40`, SMTP/POP3) | E-Commerce | T3-EM |
| **Network Lead** | Palo Alto, Cisco FTD, VyOS router, connectivity | Windows AD | T3-NET |
| **Splunk/Monitoring Lead** | SIEM, dashboards, forwarders, the team's "eyes" | Any Linux box | T3-SP |
| **Injects/Docs + IR** | Inject execution, documentation, incident reports (the scored 10–20%) | Captain | T2-I1/I2/I3 + one T3 |

> That's 8 seats for a two-segment network (Palo Alto side: Ecom, Webmail, Splunk, Ubuntu Wks; Cisco
> FTD side: AD/DNS, Web, FTP, Win11). A **Floater/IR** role emerges naturally from whoever is least
> loaded at any moment — in a 7-hour single-day event the captain re-assigns rovers as fires shift.
> Small-team fallback: merge Injects/Docs+IR into the Captain and fold Web/FTP into AD. The existing
> team-roles doc has function-based options too.

### The Captain does not touch keyboards

The single most common rookie failure: the most technical person becomes captain and disappears into a
box, and the team loses coordination. The captain **coordinates, watches the clock, owns the White
Team/inject relationship, and keeps the team calm.** Train this explicitly (Phase 3, Week 16).

---

## The bench & cross-training

- **Alternates train the full rubric.** They are not spectators; they run every checklist and
  scrimmage. Depth wins long competitions and covers illness/no-shows.
- **Every role has a cross-trained backup** (the "Backs up" column). By Phase 4, Week 23, every box
  can be run competently by at least two people. When a specialist is buried, their backup takes the
  next fire.
- **Starting 8 decided late (Phase 5)** on checklist completion + scrimmage performance. Keeping it
  open keeps everyone invested (Coach's call).

---

## Communication Protocol (drilled from Phase 3)

A protocol only works if it's a reflex. Drill it every scrimmage.

### Channels
- **Primary:** whatever the competition allows in-room (voice + a shared channel/board if permitted —
  *confirm against the rules packet*).
- **Shared board:** the [change-log](../CCDC-main-Matt_2026/CCDC-main/competition-tools/change-log.md)
  and a visible incident list. Everyone can see current fires and who owns them.

### Calling an incident (say it this way)
> **"Incident — [system] — [what you see] — I'm [containing / need help]."**

Example: *"Incident — E-Comm — unknown process listening on 4444, I'm containing."* Short, structured,
loud enough for the captain to hear and triage.

### The captain's triage loop (every few minutes)
1. Scan the board: what's down, what's under attack, what injects are due.
2. Assign the hottest fire to its owner or the Floater; confirm someone owns it.
3. Protect scored services first, then evict, then injects, then hardening.
4. Watch the clock on inject deadlines — pull people to injects *before* they're late.

### Handoff rule
When you hand a box to someone (breaks, backups, shift): **state what you changed, what's still
broken, and where the change-log is.** No silent handoffs.

### The "two people, one session" trap
If two people fight the same red-team session in opposite directions, both lose. The rule: **one owner
per active incident.** The Floater/IR assists; the owner decides.

---

## The First 30 Minutes (opening runbook)

Drilled until it needs no checklist (Red Teamer's non-negotiable). Every member, in parallel on their
box:

1. **Credential sweep** — every box ships with a **known default password** (see the table in
   [`07-competition-reference.md`](07-competition-reference.md)); the Red Team has these too. Rotate
   every password/key, kill unknown accounts (T2-C1/C2/C3). Admin/root/sysadmin change freely; be
   careful with AD accounts (POP3/mail auth uses them).
2. **Persistence sweep** — cron/scheduled tasks/services/UID-0/authorized_keys
   ([persistence-hunting](../CCDC-main-Matt_2026/CCDC-main/competition-tools/persistence-hunting.md)).
3. **Firewall up** — host firewalls + Palo Alto/Cisco FTD policy, scored services allowed, everything
   verified still up (T2-C4/C6). **Keep ICMP up everywhere except the Palo Alto core port** — the
   scoring engine needs it. Anything that breaks a scoring check is *your* point loss.
4. **Logging on** — confirm the Splunk forwarder reports (T2-S1).
5. **Back up** — config/state backup before heavy hardening. **There is no snapshot/revert** — cold
   boot only, and VM scrubs are limited to 3 (penalized). If you break it, you own fixing it.
6. **Log it** — every change in the change-log from minute one.

Captain simultaneously: confirm White Team contact, watch for the first injects, track who's done with
their opening sweep.

See the full built session for how this is first taught in
[`05-week-01-module/`](05-week-01-module/) (context) and drilled in Phase 3, Week 16.
