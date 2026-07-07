# Week 14 — Homework (solo, before the weekend lab / Week 15)

Alone on your box. Budget ~1.5 hr. Week 15 is the **Tier-3 gate** for your track — this is defense
practice + review. Back up first; verify the service after every change.

## 1. Re-harden against your attack, from memory (~30 min)
- [ ] Apply the defense(s) for your box's Week-13 attack
- [ ] After each change, verify the scored service still works
- [ ] Confirm (with a partner playing attacker, or by re-running the technique) the attack now fails

## 2. Secure your components (~25 min)
- [ ] Do your track's component hardening (AD/GPO, IIS/FTP, app+DB, mail config, firewall policy, or
      Splunk itself)
- [ ] Verify nothing you did broke the scored service

## 3. Make your detection bulletproof (~20 min)
- [ ] Refine your Splunk detection so it clearly fires on the attack and doesn't drown in false
      positives
- [ ] Save it as an alert; write down exactly what it catches
- [ ] Add it to the shared team detections list

## 4. Tier-3 self-check (~15 min) — you'll be gated next week
Rate your track's items ✅ / 🔁 (see [`../02-readiness-rubric.md`](../02-readiness-rubric.md)) and drill
the 🔁s. Note anything you can't yet do without help.

## Bring to the weekend lab / Week 15
- Your working detection (and its description)
- Your Tier-3 self-check with 🔁 items circled
- Any change that risked the scored service and how you verified around it
