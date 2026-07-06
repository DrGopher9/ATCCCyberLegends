# Team Roles & Communication

Builds on the existing [`team-roles.md`](../CCDC-main-Matt_2026/CCDC-main/competition-tools/team-roles.md).
That doc defines the roles; this one adds **the bench plan, cross-training/backups, and the drilled
comms protocol** — the parts that only work if you practice them (per the Former Tech Lead's analysis
in [`00-council-analysis.md`](00-council-analysis.md)).

CCDC competes **8** on the floor. You are training **10–12** (8 + alternates). Everyone trains as an
equal; the starting 8 is earned, not assigned by seniority.

---

## Roles (the competition 8)

| Role | Owns | Backs up | Rubric track |
|---|---|---|---|
| **Captain** | Coordination, injects relationship, White Team contact, the clock, morale | *Everything* (knows enough to redirect, doesn't fix) | T3 of their secondary box |
| **Windows AD Lead** | AD, DNS, DHCP | Firewall | T3-AD |
| **E-Commerce Lead** | Ubuntu web/app/DB | Email | T3-EC |
| **Email/Webmail Lead** | Fedora mail + webmail | E-Commerce | T3-EM |
| **Firewall/Network Lead** | Palo Alto, connectivity | Windows AD | T3-FW |
| **Splunk/Monitoring Lead** | SIEM, dashboards, forwarders, the team's "eyes" | Any Linux box | T3-SP |
| **Floater / IR** | Roves to the hottest fire; runs incident response | Whichever box is under attack | Passes 2 T3 tracks |
| **Injects/Docs** | Inject execution, documentation, change-log discipline | Captain | T2-I1/I2 + one T3 |

> Small-team fallback: on a thin roster, merge Injects/Docs into the Captain and Floater into
> Monitoring. The existing team-roles doc has function-based options too.

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

1. **Credential sweep** — rotate every password/key; kill unknown accounts (T2-C1/C2/C3).
2. **Persistence sweep** — cron/scheduled tasks/services/UID-0/authorized_keys
   ([persistence-hunting](../CCDC-main-Matt_2026/CCDC-main/competition-tools/persistence-hunting.md)).
3. **Firewall up** — host firewall / Palo Alto policy, scored services allowed, everything verified
   still up (T2-C4/C6).
4. **Logging on** — confirm the Splunk forwarder reports (T2-S1).
5. **Back up** — config/state backup before heavy hardening.
6. **Log it** — every change in the change-log from minute one.

Captain simultaneously: confirm White Team contact, watch for the first injects, track who's done with
their opening sweep.

See the full built session for how this is first taught in
[`05-week-01-module/`](05-week-01-module/) (context) and drilled in Phase 3, Week 16.
