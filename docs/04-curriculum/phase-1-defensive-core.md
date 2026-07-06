# Phase 1 — Defensive Core (Weeks 8–11, Sep)

**Goal:** the universal defensive skillset every member owns regardless of specialty — done fast and
*safely*.

**Council lens:** the Blue Teamer owns this phase, with a hard rule: **manual first, then the script;
always verify the scored service still works; always know the rollback.** No member runs a hardening
script they can't explain and can't reverse.

**Exit gate:** every member passes **Tier 2 Core** in [`02-readiness-rubric.md`](../02-readiness-rubric.md).

## Weeks

All four weeks are built out as full modules (facilitator guide / lab / homework / assessment).

| Wk | Focus | Lab spine | Rubric | Module |
|---|---|---|---|---|
| 8 | Credentials — rotate all passwords/keys, kill unknown accounts, audit sudoers/admins | Full credential sweep on a Linux box, then Windows, against the clock | T2-C1, T2-C2, T2-C3 | [`05-week-08-module/`](../05-week-08-module/) |
| 9 | Hardening & host firewalls — manual rule-writing, then repo scripts; **verify + rollback** | Harden a box without dropping its scored service; reverse one change | T2-C4, T2-C5, T2-C6 | [`05-week-09-module/`](../05-week-09-module/) |
| 10 | Splunk basics — architecture, forwarders, first searches & dashboards | Confirm forwarder reports; run the failed-login search; read a dashboard | T2-S1, T2-S2 | [`05-week-10-module/`](../05-week-10-module/) |
| 11 | Incident response + **Tier-2 Core checkpoint** | Detect→contain→evict→document a scripted intrusion; write the incident report; full Tier-2 gate | T2-I1, T2-I2, T2-I3 + gate | [`05-week-11-module/`](../05-week-11-module/) |

## Teaching notes
- Pair every hardening action with two questions: *"Did the scored service survive?"* and *"How do I
  undo this?"* Backups and change-logs become habits here, not afterthoughts.
- Introduce Splunk in Week 10 and then **use it every week for the rest of the season** — detection
  must become reflex, not a Phase-4 scramble.

## Resources
- [`quick-reference.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/quick-reference.md) — now they master it
- [`service-recovery.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/service-recovery.md)
- Hardening scripts in `CCDC_2026/` and `CCDC-main-Matt_2026/CCDC-main/` (understand before running)
- Splunk: `CCDC-main-Matt_2026/CCDC-main/splunk-siem/`, `splunk-forwarders/`, `splunk-dashboards/`
