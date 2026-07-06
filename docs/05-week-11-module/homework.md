# Week 11 — Homework (solo, before the weekend Tier-2 gate)

Alone. Budget ~1.5 hr. Week 11's weekend is the **Tier-2 Core gate**, so this is both new-skill
practice and phase review.

## 1. Run an IR cycle solo (~30 min)
On a box where the facilitator planted something (or replay the session scenario):
- [ ] **Detect** — capture source IP, what, when, which box (write it down first)
- [ ] **Contain** — block the source / kill the session, then verify the scored service still works
- [ ] **Evict** — remove the foothold; re-scan to confirm it's gone
- [ ] **Document** — change-log every action

## 2. Write an incident report to spec (~25 min)
- [ ] Include: source/dest IP, timeline, passwords cracked, what was affected, remediation
- [ ] Focus on the exploitation event, not misconfiguration; keep it to ~1 page; save as PDF
- [ ] Self-check: would a judge call this clear, thorough, and accurate — and not padded?

## 3. Tier-2 Core self-check (~30 min) — you'll be gated on ALL of this
Rate ✅ / 🔁 and drill the 🔁s:
- [ ] `T2-C1/C2` credential sweep (Linux + Windows)
- [ ] `T2-C3` remove unauthorized SSH keys
- [ ] `T2-C4` hand firewall rule without breaking the service (keep ICMP)
- [ ] `T2-C5` run a script, explain it, roll it back
- [ ] `T2-C6` verify a scored service after any change
- [ ] `T2-S1` confirm a forwarder + failed-login search
- [ ] `T2-S2` read a dashboard, name an anomaly
- [ ] `T2-I1/I2/I3` IR cycle + change-log + incident report

## Bring to the weekend gate
- Your incident report (PDF)
- Your Tier-2 self-check with 🔁 items circled
