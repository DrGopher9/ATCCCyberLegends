# Week 7 — Review Circuit (five stations)

No new material — this is a rotation to sharpen every Tier-1 skill before the gate. Spend the most time
on *your own* 🔁 items from the Week 6 self-check. If you've mastered a station, coach someone at it.

Each station is a lab box + a task card. Rotate every ~20 minutes.

---

## Station 1 — Linux ops (`T1-L1`, `T1-L2`)
On a lab Linux box:
- List human accounts from `/etc/passwd`; create and cleanly remove a user
- Set a file to `640` and explain it
- `ss -tlnp`: list every listener and its program; **find the one the facilitator planted**

## Station 2 — Linux service recovery (`T1-L3`)  ← usually the hardest
On a box where the facilitator has broken a service:
- Read `journalctl -u <service>` to find the cause
- Fix it and restart; confirm it **serves** (`ss`/`curl`), not just "active"
- Beat your Week 3 recovery time

## Station 3 — Windows admin & events (`T1-W1`, `T1-W2`)
On a lab Windows box (elevated PowerShell):
- `Get-LocalGroupMember Administrators`; **spot the planted extra admin**
- Create, disable, remove a local user
- Restart a service; find a 4625 in the Security log and say what it means

## Station 4 — Networking & topology (`T1-N1`)
- State this box's IP/subnet/gateway/segment
- Map the 5 scored services to ports; `nslookup` against `172.20.240.102`
- **Draw the full topology from memory**, then check against `07`

## Station 5 — Git & rules (`T1-G1`, `T1-G2`)
- Pull, branch, commit, push **your branch** (never `main`)
- State what CCDC is + 3 penalties that cost points or cause DQ
- Name one allowed action

---

## Done?
You're ready for the gate when you can clear all five stations without help — especially Station 2
(service recovery) and the "spot the planted item" tasks in Stations 1 and 3, which are the seeds of
the defensive work in Phase 1+. The gate itself is [`assessment.md`](assessment.md).
