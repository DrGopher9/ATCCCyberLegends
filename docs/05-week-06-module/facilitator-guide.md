# Week 6 — Facilitator Guide: Active Directory Concepts & the Scored-Service Map

> **Phase 0, Week 6.** Built from [`../templates/module-template.md`](../templates/module-template.md).

**Rubric targets:** reinforces `T1-N1` (the service map) and `T1-G2` (what's scored / what matters).
This week also **previews** the Tier-3 AD track (`T3-AD`) — AD concepts here are the on-ramp, not a
gated Tier-1 item. See [`../02-readiness-rubric.md`](../02-readiness-rubric.md).

**Council lens:** the Blue Teamer (AD is the backbone — DNS is scored on it, and **POP3/mail auth runs
against AD accounts**, so AD sits under multiple scored services) and the Red Teamer (AD is the crown
jewel; Domain Admins and scheduled tasks are prime persistence).

**You need:** the topology from [`../07-competition-reference.md`](../07-competition-reference.md) and
read access to the **Server 2019 AD/DNS** box (`172.20.240.102`) to *look* at AD — this week is
concept + observe, **no changes** to AD.

---

## Learning objectives
By end of the weeknight session, every member can:
1. Explain what Active Directory is: domain, users, groups, especially **Domain Admins**.
2. Explain why AD is load-bearing: it serves **DNS** (scored) and backs **POP3/mail** auth (scored).
3. List every scored service and which box it lives on, from memory.
4. View AD users/groups read-only (`Get-ADUser`, `Get-ADGroupMember "Domain Admins"`).

By end of the weekend lab, every member recites the scored-service map and explains AD's role.

## Weeknight session plan (2–3 hr)
- **0:00–0:15 — Warm-up:** draw the topology from memory (keeps `T1-N1` hot). Homework check.
- **0:15–0:45 — Concept:** AD basics — a domain is a central directory of users/computers; you log in
  once and it authenticates you everywhere. Domains, OUs, groups; **Domain Admins = keys to the
  kingdom**. Local admin ≠ Domain Admin (callback to Week 4).
- **0:45–1:05 — Concept:** why AD matters for *scoring* — **DNS** runs on the AD box and is scored;
  **POP3** authenticates against AD usernames (break an AD account, break mail scoring). This is why
  the AD lead and the mail lead must coordinate.
- **1:05–2:00 — Guided lab:** run [`lab-exercises.md`](lab-exercises.md) — read-only AD tour + build
  the scored-service map.
- **2:00–2:30 — Debrief + assign [`homework.md`](homework.md); preview Week 7 (the Tier-1 checkpoint).**

## Weekend lab plan (3–5 hr)
- **Warm-up (30m):** cross-OS recall — Linux service recovery + Windows admin group + topology draw.
- **Service-map mastery (60m):** teams race to fill a blank service map (service → port → box → segment
  → firewall) correctly, from memory. Repeat until fast.
- **AD read-only tour (45m):** each member lists Domain Admins and a few AD users; discuss what would
  look suspicious (an unexpected Domain Admin).
- **Assessment (30m):** run [`assessment.md`](assessment.md).
- **AAR (15m).**

## Facilitator notes & common snags
- **Keep AD read-only.** No account changes, no password resets on the domain this week — a broken AD
  account can silently break mail scoring. Observation only; hardening is Phase 2.
- **Hammer the AD↔scoring links.** "DNS is on AD" and "POP3 auth uses AD accounts" are the two facts
  that prevent a self-inflicted mail/DNS outage later.
- Some members won't have seen AD at all — that's fine. The goal is a correct *mental model*, not
  mastery. Mastery is the Phase-2 `T3-AD` track.

## Definition of done
Every member can recite the scored-service map and explain AD's role in DNS and mail auth (`T1-N1`/
`T1-G2` reinforced), and has seen AD read-only. Flag anyone shaky ahead of the Week 7 checkpoint.
