# Week 14 — Facilitator Guide: Defend Your Box (Harden + Monitor Against the Attacks)

> **Phase 2, Week 14.** Built from [`../templates/module-template.md`](../templates/module-template.md).

**Rubric targets:** the **hardening + detection-writing** items per track — `T3-AD1/AD3`,
`T3-WEB1/WEB2/WEB3`, `T3-EC1/EC3`, `T3-EM1/EM2/EM3`, `T3-NET1/NET2`, `T3-SP1/SP2/SP3`. See
[`../02-readiness-rubric.md`](../02-readiness-rubric.md).

**Council lens:** the Blue Teamer owns the defense; the Red Teamer keeps probing so members defend
against a *live* adversary, not a memory. The iron rule from Phase 1 still governs: **harden without
breaking the scored service — verify after every change.**

**You need:** each member's box + their Week-13 evidence (what the attack looked like), the repo
hardening scripts for their box, Splunk for writing detections, and the live red team to re-probe.

---

## Learning objectives
By end of the week, every member can, **for their box**:
1. Harden it against the specific attack(s) from Week 13 — **without dropping the scored service.**
2. Secure the box's key components (AD/GPO, IIS/FTP, web app + DB, mail config, firewall policy, Splunk
   itself).
3. **Write a detection** (a Splunk search/alert or a monitoring check) that fires on that attack.
4. Verify the scored service still works after all of it (the Phase-1 reflex, on their own box).

## Weeknight session plan (2–3 hr)
- **0:00–0:15 — Warm-up:** detect your box's attack again from baseline (keeps Week 13 warm).
- **0:15–0:35 — Frame:** "you saw it; now stop it." Map each Week-13 attack to a defense + a detection.
  Reinforce verify-after-every-change and back-up-first.
- **0:35–2:15 — Defend lab (split by track):** members run their section of
  [`lab-exercises.md`](lab-exercises.md) — harden, secure components, write a detection. Red team
  re-probes so members can confirm their fix holds and their alert fires.
- **2:15–2:30 — Debrief + assign [`homework.md`](homework.md); preview Week 15 (persistence + Tier-3 gate).**

## Weekend lab plan (3–5 hr)
- **Warm-up (20m):** a Tier-2 skill on your box (credential sweep / firewall+verify).
- **Harden-under-fire (100m):** members harden their box while the red team re-runs the Week-13 attack;
  success = the attack now fails **and** the scored service stayed up **and** the detection fired.
  Coaches verify the service never dropped.
- **Detection review (20m):** each member shows their new detection firing in Splunk; peers copy useful
  ones to a shared "team detections" list.
- **Assessment (30m):** run [`assessment.md`](assessment.md).
- **AAR (15m).**

## Facilitator notes & common snags
- **Verify or it doesn't count.** The temptation to over-harden and drop the service is highest here.
  Every hardening step → test the scored service. An attack blocked at the cost of the service is a
  loss, not a win.
- **Detections must actually fire.** "I wrote a search" isn't enough — re-run the attack and watch the
  alert trigger. A detection that doesn't fire is a false sense of security.
- **Coupled boxes, again.** AD hardening must not break POP3 auth (mail owner verifies mail after AD
  changes). Network policy must not block the scoring engine or ICMP.
- **Use the repo scripts as understood accelerators** — and log every change. Note any script that's
  too aggressive for a scored box (feed [`../06-repo-gaps-backlog.md`](../06-repo-gaps-backlog.md)).

## Definition of done
Every member has hardened their box against the Week-13 attack (service still scoring), secured its
components, and written a working detection — their track's hardening/detection items — or a partner +
plan. Ready for the Tier-3 gate in Week 15.
