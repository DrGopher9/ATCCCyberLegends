# Week 12 — Facilitator Guide: Own Your Box (Deep-Dive & Baseline)

> **Phase 2, Week 12.** Built from [`../templates/module-template.md`](../templates/module-template.md).
> Phase 2 branches into six specialty tracks — this week each member learns their box cold.

**Rubric targets:** the foundation for every Tier-3 track (`T3-AD`, `T3-WEB`, `T3-EC`, `T3-EM`,
`T3-NET`, `T3-SP`) — you can't defend a box whose *normal* you don't know. See
[`../02-readiness-rubric.md`](../02-readiness-rubric.md).

**Council lens:** the Blue Teamer (baseline first — you detect attacks as *deviations from normal*, so
normal has to be documented) and the Coach (specialties are assigned now; make sure each member owns a
box they can grow into, and seat each with their cross-training backup).

**Specialty tracks & boxes** (from [`../07-competition-reference.md`](../07-competition-reference.md)):

| Track | Box(es) | Scored service(s) |
|---|---|---|
| **AD/DNS** | Server 2019 AD/DNS `172.20.240.102` | AD auth (backs POP3), DNS |
| **Web/FTP** | Server 2019 Web/IIS `.101`, Server 2022 FTP `.104` | HTTP/HTTPS, FTP |
| **E-Comm** | Ubuntu Ecom `172.20.242.30` | HTTP/HTTPS (app + DB) |
| **Email/Webmail** | Fedora Webmail `172.20.242.40` | SMTP, POP3 |
| **Network** | Palo Alto, Cisco FTD, VyOS | (protects all) |
| **Splunk** | Oracle Linux / Splunk `172.20.242.20` | (the team's eyes) |

**You need:** specialties assigned (from Phase 1 Tier-2 performance + interest), lab access to each
box, and the change-log/password-tracker habit carried over from Phase 1.

---

## Learning objectives
By end of the week, every member can, **for their own box**:
1. List its services, its scored component(s), and how they're tested.
2. Describe its **normal state**: normal processes, listeners, users, config, and a healthy log.
3. Break and recover each scored service on it (carrying the Phase-0/1 recovery reflex to *their* box).
4. Back up its config/state so they can restore fast (no revert in competition).

## Weeknight session plan (2–3 hr)
- **0:00–0:15 — Warm-up:** Tier-2 recall — credential sweep or firewall+verify (keeps Phase 1 warm).
- **0:15–0:35 — Frame the phase:** attack-first pedagogy — this week baseline, next week the **red team
  attacks your box**, then you defend it. Assign/confirm specialties and backups.
- **0:35–2:15 — Guided lab (split by track):** members run their track's section of
  [`lab-exercises.md`](lab-exercises.md); coaches rotate. Everyone documents their box's baseline.
- **2:15–2:30 — Debrief + assign [`homework.md`](homework.md); preview Week 13 (red team attacks).**

## Weekend lab plan (3–5 hr)
- **Warm-up (20m):** Tier-2 skill, cross-OS.
- **Baseline mastery (100m):** each member produces a **one-page baseline** of their box (services,
  scored components, normal listeners/processes/users, backup location) and demos breaking + recovering
  each scored service. Backups seated with the primary all session.
- **Baseline swap (20m):** members present their box's baseline to their backup, so two people know
  each box.
- **Assessment (30m):** run [`assessment.md`](assessment.md).
- **AAR (15m).**

## Facilitator notes & common snags
- **Normal is the whole point.** A member who can't say what "normal" looks like on their box will not
  spot the Red Team next week. Push for specifics: exact listeners, exact service accounts.
- **Back up before Week 13.** Everyone should have a known-good config backup before the red team shows
  up — restoring fast is a Tier-3 item for most tracks.
- **Coordinate the coupled boxes.** AD/DNS ↔ Email (POP3 auth uses AD) and Network ↔ everyone. Have
  those owners talk now.
- **Backups aren't optional roles.** Every box needs two competent people by Phase 4; it starts here.

## Definition of done
Every member has a documented one-page baseline for their box, can break+recover each scored service on
it, and has a config backup. Backups have seen their box. This is the launchpad for the Tier-3 track.
