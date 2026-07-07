# Week 11 — Facilitator Guide: Incident Response + Tier-2 Core Checkpoint

> **Phase 1, Week 11 — the phase exit gate.** Built from [`../templates/module-template.md`](../templates/module-template.md).

**Rubric targets:** `T2-I1` (run the IR cycle: detect → contain → evict → document), `T2-I2` (keep a
change-log), `T2-I3` (write a **scorable incident report**), **plus the full Tier-2 Core gate**
(`T2-C1`–`C6`, `T2-S1`–`S2`, `T2-I1`–`I3`). See [`../02-readiness-rubric.md`](../02-readiness-rubric.md).

**Council lens:** the Blue Teamer (the IR cycle is the core loop of the whole competition) and the
**White Team Judge** — incident reports are a **scored 10–20%**, and they must follow the packet's spec:
source/dest IP, timeline, passwords cracked, what was affected, remediation — focused on **exploitation,
not misconfiguration**, and **not padded** (frivolous/excessive reports can be scored *negatively*).

**You need:** everything from Weeks 8–10 in the lab, the repo IR references (paths below), and the
per-member Tier-2 tracking sheet. This week combines a new skill (IR + reports) with the Tier-2 gate.

---

## Learning objectives
By end of the weeknight session, every member can:
1. Run the IR cycle on a single intrusion: **detect** (Splunk/logs) → **contain** → **evict** →
   **document**.
2. Keep a clean change-log during an incident (`T2-I2`).
3. Write an incident report to the packet spec (`T2-I3`).

By the weekend gate, every member passes the full **Tier-2 Core** checklist (or gets a remediation
plan).

## The IR cycle (the loop everything else serves)
1. **Detect** — a Splunk alert, a failed-login spike, an odd process/listener, a service down.
2. **Contain** — stop the bleeding without destroying evidence (block the IP, kill the session,
   disable the account) — and **without breaking a scored service.**
3. **Evict** — remove the foothold (kill the process, remove the key/account/task, close the hole).
4. **Document** — change-log the actions **and** write the incident report (the scored part).

References: [`persistence-hunting.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/persistence-hunting.md),
[`service-recovery.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/service-recovery.md),
[`inject-templates.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/inject-templates.md)
(report format), [`change-log.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/change-log.md).

## Weeknight session plan (2–3 hr)
- **0:00–0:15 — Warm-up:** Week 10 — confirm forwarders + run the failed-login search (keeps `T2-S1`
  warm).
- **0:15–0:45 — Concept + demo:** the IR cycle end to end on one scripted intrusion (facilitator plays
  a light attacker: a planted account logs in, starts a process). Walk detect → contain → evict →
  document live.
- **0:45–1:05 — Concept:** the **incident report** — the packet's required contents, "exploitation not
  misconfiguration," and "don't over-report." Show a good vs. a padded example.
- **1:05–2:15 — Guided lab:** run [`lab-exercises.md`](lab-exercises.md) — each member runs a full IR
  cycle on a planted intrusion and writes the report.
- **2:15–2:30 — Debrief; set expectations for the weekend Tier-2 gate; assign [`homework.md`](homework.md).**

## Weekend lab plan (3–5 hr) — the Tier-2 gate
- **Warm-up (20m):** the IR cycle recited; one credential sweep.
- **IR scenario (60m):** facilitator runs a light multi-step intrusion across a couple of boxes;
  members detect, contain, evict, keep the change-log, and file reports. This is `T2-I1/I2/I3` under
  realistic conditions.
- **Tier-2 gate (75m):** run [`assessment.md`](assessment.md) — the full Core checklist. Two assessors.
  Record ✅/🔁 per item per member.
- **Remediation + Phase 1 AAR (25m):** plans for anyone short; celebrate the jump from "operating
  boxes" (Phase 0) to "defending them" (Phase 1). Preview Phase 2 (Specialize).

## Facilitator notes & common snags
- **Contain without self-owning.** The classic mistake: blocking an IP range that includes the scoring
  engine, or killing a service to "stop the attacker." Reinforce Week 9's verify reflex inside IR.
- **Reports: quality over quantity.** New teams either don't write reports or write ten padded ones.
  Train the middle: one clear report per real exploitation event.
- **Evidence before eviction.** Note the source IP, timeline, and what you saw *before* you wipe it —
  you need it for the report and you don't get it back (no revert).
- `T2-C*`/`T2-S*` should be near-automatic by now; the gate confirms it. Give remediation, not
  judgment, to anyone still closing items.

## Definition of done
Every member has `T2-I1`, `T2-I2`, `T2-I3` ✅ and passes the full **Tier-2 Core** gate (or has an owned
remediation plan with a near-term close date). Phase 1 exit gate = team at Tier-2 Core.
