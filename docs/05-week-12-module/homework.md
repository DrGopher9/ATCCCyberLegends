# Week 12 — Homework (solo, before the weekend lab / Week 13)

Alone on **your** box. Budget ~1.5 hr. Next week the red team attacks it — everything you document now
is what lets you notice them.

## 1. Finish your one-page baseline (~40 min)
Write it so your backup could use it. Include:
- [ ] Every listening port + the program behind it (this is your "normal" reference)
- [ ] Normal running processes and service accounts
- [ ] Normal users / admins
- [ ] Your scored component(s) and exactly how to test each (the command that proves it works)
- [ ] Where your config backup lives

## 2. Break + recover each scored service (~30 min)
- [ ] For each scored service on your box: stop it, recover it, and **verify it serves**
- [ ] Time your slowest recovery; write it down

## 3. Know your attack surface (~15 min)
- [ ] From [`../../CCDC-main-Matt_2026/CCDC-main/competition-tools/red-team-playbook.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/red-team-playbook.md),
      write down **two attacks** you'd expect against your specific box
- [ ] For each, note where you'd *see* it (which log / Splunk search)

## 4. Coupled-box coordination (if applicable) (~5 min)
- [ ] AD/DNS & Email owners: confirm together how POP3 auth uses AD accounts
- [ ] Network owner: confirm which allow-rules the scoring engine needs

## Bring to the weekend lab / Week 13
- Your one-page baseline (bring a copy for your backup)
- Your slowest recovery time
- The two attacks you expect on your box + where you'd see them
