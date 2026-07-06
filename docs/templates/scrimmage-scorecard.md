# Scrimmage Scorecard — Template

Score every scrimmage (Phase 3 on) so progress is measurable and the capstone gate in
[`../02-readiness-rubric.md`](../02-readiness-rubric.md) is objective. The White Team judge / coach
fills this in; share it in the AAR ([`aar-template.md`](aar-template.md)).

Mirror the real competition scoring model where known — **confirm weights against the current
MN/Midwest team packet.** The structure below matches the capstone thresholds.

---

## Header
- **Date / scrimmage #:** ___  · **Duration:** ___  · **Red team intensity:** ___
- **Captain:** ___

## 1. Scored-service uptime
Record up/down per scored service across the window. Target: **≥ 90%** each.

| Service | System | Uptime % | Notes (when down / why) |
|---|---|---|---|
| AD auth | Windows AD | | |
| DNS | Windows AD | | |
| DHCP | Windows AD | | |
| HTTP/HTTPS | E-Commerce | | |
| Database | E-Commerce | | |
| SMTP/IMAP | Email | | |
| Webmail | Fedora | | |
| Splunk | Splunk | | |

**Team uptime (avg):** ___%

## 2. Self-inflicted outages (target: 0)
Any scored service the **team's own change** took down. List each — these are the most fixable.

| Service | What we did | Minutes down |
|---|---|---|
| | | |

## 3. Injects (target: ≥ 90% on time, to standard)
| Inject # | Title | Due | Submitted | On time? | Quality (1–5) |
|---|---|---|---|---|---|
| | | | | | |

**Injects on time:** ___ / ___  · **Avg quality:** ___

## 4. Red-team footholds (target: 100% detected + evicted + reported)
| # | System | What they got in with | Detected? | Evicted? | Reported? |
|---|---|---|---|---|---|
| | | | | | |

## 5. First 30 minutes (target: complete on all boxes)
- [ ] Credential sweep done on all boxes within 30 min
- [ ] Persistence sweep done on all boxes within 30 min
- [ ] Host firewall up + services verified on all boxes
- [ ] Forwarders confirmed reporting

## 6. Process (judge's marks)
| Dimension | 1–5 | Notes |
|---|---|---|
| Change-log kept clean | | |
| Incident reports filed | | |
| Communication / captain ran the floor | | |
| Professional tone (comms, injects) | | |

---

## Capstone gate check (Week 24 dress rehearsal)
Ready = **all** true in one scrimmage:
- [ ] Uptime ≥ 90% across services
- [ ] Zero self-inflicted outages
- [ ] Injects ≥ 90% on time to standard
- [ ] Every foothold detected + evicted + reported
- [ ] First-30 complete on all boxes
- [ ] Clean docs + comms held under pressure

Feed misses straight into the AAR's "Top 3 fixes."
