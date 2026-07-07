# Week 5 — Assessment

Member **performs** each item while observed. Mark ✅ / 🔁. Record in the rubric sheet.
**Covers:** `T1-N1` ([`../02-readiness-rubric.md`](../02-readiness-rubric.md)).

---

## Part A — `T1-N1`: Networking basics (hands-on + verbal, unaided)
Time budget: **8 minutes.**

| # | Task | ✅/🔁 |
|---|---|---|
| A1 | State this box's IP, subnet, gateway, and which segment/firewall it's behind | |
| A2 | Map all 5 scored services to their ports (HTTP 80, HTTPS 443, SMTP 25, POP3 110, DNS 53) | |
| A3 | Use `ss`/`ping`/`nslookup` to show a listener, reach a host, and resolve a name | |
| A4 | `curl` a web service and confirm it actually responds (not just port-open) | |

**Pass A** = all four ✅.

## Part B — Draw the topology (from memory)
Time budget: **6 minutes.** On paper/whiteboard.

| # | Task | ✅/🔁 |
|---|---|---|
| B1 | Draw the two segments with the correct subnets and firewalls (PA / Cisco FTD) | |
| B2 | Place at least the 6 servers + VyOS router in the right segment | |
| B3 | Label which boxes carry scored services (Web, Ecom, Webmail, AD/DNS) | |

**Pass B** = segments + firewalls correct (B1), most boxes placed (B2), scored boxes labeled (B3).

---

## Scoring
- Both pass → `T1-N1` ✅.
- 🔁 → note items, pair the member, re-check start of Week 6.

> A shared, accurate mental map of the network is what lets the team triage fast in a 7-hour
> competition. If most of the team can draw it cold, you're in good shape heading into Week 6.
