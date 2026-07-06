# Week 2 — Homework (solo, before the weekend lab / Week 3)

Do it alone on a lab Linux box. Budget ~1 hour. Goal: the observe-and-operate primitives become quick.

## 1. Users, from memory (~20 min)
- [ ] Create a user `hwtest` with a home directory and a bash shell
- [ ] Show its line in `/etc/passwd` and run `id hwtest`
- [ ] Remove it (including its home) and confirm it's gone
- [ ] Write down the command that lists only human accounts (UID ≥ 1000)

## 2. Permissions prediction (~15 min)
- [ ] Create a file in `/tmp`
- [ ] Before running `ls -l`, **write down** what you expect the permissions to be
- [ ] `chmod 640` it, predict again, then verify
- [ ] Explain in one line what `640` means (owner / group / other)

## 3. Processes & listeners (~15 min)
- [ ] List all processes; find one and name its user, PID, and command
- [ ] Run `ss -tlnp` (with sudo) and write down **every listening port** and the program behind it
- [ ] Circle any listener you couldn't explain (bring it to the session)

## 4. Look ahead (~10 min)
- [ ] Skim [`../04-curriculum/phase-0-foundations.md`](../04-curriculum/phase-0-foundations.md) row for
      Week 3 (services, systemd, logs).

## Bring to the weekend lab / Week 3
- Your list of listening ports from a lab box
- Any listener or process you couldn't explain
- One question that came up
