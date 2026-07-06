# Week 5 — Homework (solo, before the weekend lab / Week 6)

Alone. Budget ~1 hour. Goal: the topology and the scored-service→port map become second nature.

## 1. Your network position (~10 min)
- [ ] From a lab box, state your IP, subnet (`/24`?), gateway, and which segment/firewall you're behind

## 2. Scored services → ports, from memory (~15 min)
Fill this in without looking, then check against `07`:
- [ ] HTTP → ___  · HTTPS → ___  · SMTP → ___  · POP3 → ___  · DNS → ___
- [ ] Which box serves DNS? Which serves mail (SMTP/POP3)?

## 3. See the network (~15 min)
- [ ] `ping` two other hosts; note which answer and which don't (and whether that's expected)
- [ ] Do a DNS lookup against `172.20.240.102`
- [ ] `curl -I` the Ecom web service and confirm it responds

## 4. Draw the topology from memory (~20 min)
- [ ] On one page, draw all 11 VMs with: name, IP, segment, firewall, scored service (if any), plus the
      two firewalls and the VyOS router
- [ ] Check it against [`../07-competition-reference.md`](../07-competition-reference.md); mark what you
      missed

## Bring to the weekend lab / Week 6
- Your from-memory topology drawing
- The 5 scored-service ports, memorized
- One question that came up
