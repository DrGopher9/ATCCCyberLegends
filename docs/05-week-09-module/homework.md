# Week 9 — Homework (solo, before the weekend lab / Week 10)

Alone on a lab box you may harden/restore. Budget ~1.5 hr. **Back up first; verify after every change;
keep a second session open.**

## 1. Manual firewall, from memory (~25 min)
- [ ] Back up the current firewall state
- [ ] Write rules that allow your box's scored service + your admin port + ICMP, deny the rest
- [ ] Enable it and confirm with `ufw status` / `Get-NetFirewallRule`
- [ ] **Verify** the scored service still works and ICMP still flows

## 2. Script + explain (~25 min)
- [ ] Read a repo hardening script's header (what it changes; does it use `set -e`?)
- [ ] Back up, then run it
- [ ] Write down **three specific changes** it made and where it logged them
- [ ] Verify the scored service survived

## 3. Rollback, from memory (~20 min)
- [ ] Undo one change by hand (restore a config from backup + restart the service)
- [ ] Confirm the rollback took and the service still works

## 4. Self-own awareness (~10 min)
- [ ] Write down two ways a firewall rule could accidentally cost your team points
      (hint: blocking the scoring engine / dropping ICMP / locking out a scored port)
- [ ] Write down the exact verify command(s) for your box's scored service

## Bring to the weekend lab / Week 10
- Your three script changes, explained
- The two self-own failure modes you listed
- Any step where the service dropped and how you recovered it
