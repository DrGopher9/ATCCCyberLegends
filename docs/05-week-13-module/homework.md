# Week 13 — Homework (solo, before the weekend lab / Week 14)

Alone. Budget ~1 hour. Goal: detecting your box's attacks becomes fast and calm. Next week you defend
against exactly these.

## 1. Your detection searches, from memory (~25 min)
- [ ] Write the Splunk search that would catch the main attack on your box
- [ ] Write the on-box check (log file / `ss` / file listing) that shows the same thing
- [ ] Run both against your box and confirm they'd surface the attack

## 2. Baseline-diff drill (~20 min)
- [ ] Re-capture your box's current listeners/users/files
- [ ] Diff against your Week-12 baseline — can you spot what (if anything) changed?
- [ ] Write down how long the diff took (faster each time)

## 3. Evidence capture (~10 min)
For the attack you saw this week, write a mini evidence sheet:
- [ ] Source IP, timeline (first→last), technique, what was affected
- [ ] Note: this is what feeds the incident report — is it complete enough for a judge?

## 4. Anticipate Week 14 (~5 min)
- [ ] For your box's main attack, write one sentence: how would you *stop* it? (You'll implement this
      next week — just predict it now.)

## Bring to the weekend lab / Week 14
- Your box's detection searches, memorized
- Your evidence sheet from this week's attack
- Your one-sentence defense prediction
