# Week 15 — Homework (solo, before the weekend Tier-3 gate)

Alone on your box. Budget ~1.5 hr. The weekend is your **Tier-3 track gate** — this is persistence
practice + full-track review.

## 1. Run the persistence checklist, from memory (~30 min)
- [ ] Work every class on your box: accounts, keys, cron/tasks, services/startup, listeners, plus your
      track add-ons
- [ ] Time it; you should be able to sweep your box in a few minutes
- [ ] If a partner plants something, find + evict it, then confirm it doesn't respawn

## 2. Eviction discipline (~15 min)
- [ ] For one planted mechanism, remove it AND whatever would restart it
- [ ] Re-run the checklist to confirm it's gone
- [ ] Verify the scored service still works

## 3. Full Tier-3 self-check (~30 min) — you'll be gated on ALL four items
For your track (see [`../02-readiness-rubric.md`](../02-readiness-rubric.md)), rate each item ✅ / 🔁 and
drill the 🔁s. Typical track shape:
- [ ] Item 1 — harden without breaking the scored service
- [ ] Item 2 — find + evict persistence / the planted foothold
- [ ] Item 3 — secure the box's key component
- [ ] Item 4 — detect the attack (your Week-14 detection fires)

## 4. Back up your backup (~15 min)
- [ ] Walk your cross-training partner through hunting persistence on your box (two people must be able
      to hold it in Phase 4)

## Bring to the weekend gate
- Your Tier-3 self-check with 🔁 items circled
- A clean-box demonstration ready (persistence hunt + service verify)
