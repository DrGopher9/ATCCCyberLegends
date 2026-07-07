# Week 18 — Lab Exercises: Docs Under Load

The team works boxes, injects, and incidents **while keeping the documentation clean**. The docs owner
runs the board; everyone logs their own changes. Use the
[change-log](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/change-log.md),
[password-tracker](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/password-tracker.md), and the IR
format in [`inject-templates.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/inject-templates.md).

---

## Set-up — the shared board
Stand up a visible board with three lists everyone can see:
- **Change-log** — time · system · change · who · result (· rollback note)
- **Incident list** — open incidents, owner, status
- **Password-tracker** — every credential you rotate

## Drill 1 — Log every change (while hardening)
Each specialist does a couple of real hardening actions on their box. Rule: **no action without a log
entry**, written as you go (not reconstructed later).
- [ ] Every change appears on the board with enough detail to undo it
- [ ] Every rotated credential is in the password-tracker

## Drill 2 — The judge audit
The facilitator plays a judge and, at random, asks: *"Show me every change to [box] in the last 20
minutes"* or *"What's the current status of the AD incident?"* The team must answer **from the board**,
instantly.
- [ ] The board answers the question without anyone having to remember
- [ ] Nothing material is missing from the log

## Drill 3 — Incident reports at team pace
The red team (live or simulated) generates two incidents. For each, the owner:
- [ ] Captures evidence **first** (source/dest IP, timeline) — before evicting
- [ ] Contains + evicts (without breaking a scored service)
- [ ] Writes a scorable IR report: src/dst IP, timeline, creds cracked, impact, remediation —
      exploitation not misconfiguration, ~1 page, **not padded**
- [ ] Files it as a PDF; logs it
> One report per real exploitation event. Don't write a report for every port scan — padding scores
> *negatively*.

## Drill 4 — Clean handoff
Simulate a shift change / break: one member hands their box to their backup.
- [ ] Handoff states: what changed, what's still broken, where the log is
- [ ] The backup can pick up **from the board** with no gap

## Drill 5 — Rollback from the log
The facilitator points at one logged change. The responsible member:
- [ ] Rolls it back using **only** the change-log entry (no memory)
- [ ] Verifies the scored service still works
> If you can't undo it from the log, the entry wasn't detailed enough — fix the entry.

## Done?
You've hit the objectives if the board stayed clean and audit-ready under load, incidents produced
scorable non-padded reports, handoffs were clean, and a change was rolled back straight from the log.
Practice one IR report + a change-log habit solo for [`homework.md`](homework.md).
