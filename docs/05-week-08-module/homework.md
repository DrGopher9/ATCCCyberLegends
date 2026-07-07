# Week 8 — Homework (solo, before the weekend lab / Week 9)

Alone on lab boxes. Budget ~1.5 hr. Goal: the credential sweep becomes a fast, safe reflex. **Always
keep a second session open** before changing credentials.

## 1. Linux sweep, timed (~30 min)
- [ ] Open a second session as your safety net
- [ ] List UID-0 accounts, human accounts, and anyone with a login shell
- [ ] Rotate root + the `sysadmin` default password (log them in the password-tracker)
- [ ] Audit sudoers and `/etc/sudoers.d/`
- [ ] Check every user's `authorized_keys` (including root) and note any you can't explain
- [ ] Time yourself; write it down

## 2. Windows sweep, timed (~30 min)
- [ ] List local users and the Administrators group
- [ ] Rotate the local Administrator password (log it)
- [ ] Disable (don't delete) any unknown local account you find
- [ ] List enabled scheduled tasks and flag anything unfamiliar
- [ ] Time yourself

## 3. The AD trap, in your own words (~10 min)
- [ ] Write down: why must you be careful with **AD user accounts** during a sweep? (Which scored
      service depends on them?)
- [ ] Write down: which account types can you change **freely** with no notification?

## 4. Verify habit (~15 min)
- [ ] After a sweep, list the checks you'd run to confirm no scored service broke (mail, web, DNS)

## Bring to the weekend lab / Week 9
- Your two sweep times (we'll try to beat them)
- Your answer on the AD-account trap
- Any account/key/task you couldn't explain
