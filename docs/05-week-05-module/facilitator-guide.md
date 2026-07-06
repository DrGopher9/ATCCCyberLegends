# Week 5 — Facilitator Guide: Networking (IP/Subnets, Ports, DNS, Reading the Topology)

> **Phase 0, Week 5.** Built from [`../templates/module-template.md`](../templates/module-template.md).

**Rubric target:** `T1-N1` (explain IP/subnet/port/DNS; identify and map the lab's key services). See
[`../02-readiness-rubric.md`](../02-readiness-rubric.md).

**Council lens:** the Former Tech Lead (you cannot defend or triage a network you can't picture — the
whole team needs a shared mental map) and the Network Lead specialty (this is the on-ramp to owning the
firewalls and router in Phase 2).

**You need:** the real topology from [`../07-competition-reference.md`](../07-competition-reference.md)
(11 VMs, two segments, Palo Alto + Cisco FTD + VyOS) on screen, and lab access so members can `ping`,
`ss`, and `nslookup` between boxes.

---

## Learning objectives
By end of the weeknight session, every member can:
1. Explain IP address, subnet/CIDR, and gateway in plain terms.
2. Explain ports and match the scored services to their ports (HTTP 80, HTTPS 443, SMTP 25, POP3 110,
   DNS 53).
3. Use `ip a`, `ss -tlnp`, `ping`, and `nslookup`/`dig` to see the network.
4. **Draw the competition topology** — the two segments, the firewalls, the router, and where each
   scored service lives.

By end of the weekend lab, every member draws the topology from memory and labels it correctly.

## Weeknight session plan (2–3 hr)
- **0:00–0:15 — Warm-up:** Week 4 `Get-LocalGroupMember Administrators` + Week 2 `ss -tlnp` (cross-OS
  recall). Homework check.
- **0:15–0:45 — Concept:** IP/subnet/CIDR/gateway using the *real* numbers — Linux segment
  `172.20.242.0/24` behind Palo Alto, Windows segment `172.20.240.0/24` behind Cisco FTD, VyOS router
  connecting out. Ports and the scored-service → port mapping.
- **0:45–1:05 — Concept:** DNS — what a lookup does, why the DNS server (`172.20.240.102`) is a scored
  service, `nslookup`/`dig`.
- **1:05–2:15 — Guided lab:** run [`lab-exercises.md`](lab-exercises.md), ending with each member
  drawing the topology.
- **2:15–2:30 — Debrief + assign [`homework.md`](homework.md); preview Week 6 (AD + the service map).**

## Weekend lab plan (3–5 hr)
- **Warm-up (30m):** Linux + Windows service checks unaided (keep `T1-L3`/`T1-W1` warm).
- **Topology build (75m):** in pairs, members `ping`/`nslookup`/`ss` their way around the lab and build
  a labeled diagram of all 11 VMs — IP, segment, firewall, and scored service. Compare to `07`.
- **Assessment (30m):** run [`assessment.md`](assessment.md) — including drawing the topology from
  memory.
- **AAR (15m).**

## Facilitator notes & common snags
- **Two firewalls surprises people.** Make the two-segment split concrete: Linux boxes (Ecom, Webmail,
  Splunk, Ubuntu Wks) behind Palo Alto; Windows boxes (AD/DNS, Web, FTP, Win11) behind Cisco FTD.
- **CIDR panic.** Keep it simple: `/24` = 256 addresses, same first three octets = same subnet. Don't
  go deep on subnetting math in Phase 0.
- **Reinforce the scoring link:** DNS `53`, HTTP `80`, HTTPS `443`, SMTP `25`, POP3 `110` — these are
  the ports the scoring engine checks. Knowing them cold speeds triage.
- Point them at the repo's [`quick-reference.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/quick-reference.md)
  Critical Ports table as a home reference.

## Definition of done
Every member has `T1-N1` ✅ (can draw + label the topology and map services to ports), or a partner +
plan before Week 6.
