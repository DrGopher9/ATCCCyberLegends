# Week 10 — Facilitator Guide: Splunk Basics (Forwarders, Searches, Dashboards)

> **Phase 1, Week 10.** Built from [`../templates/module-template.md`](../templates/module-template.md).

**Rubric targets:** `T2-S1` (confirm a host's forwarder is reporting; run the failed-login search),
`T2-S2` (read a dashboard and identify an anomaly). See [`../02-readiness-rubric.md`](../02-readiness-rubric.md).

**Council lens:** the Blue Teamer and the Monitoring specialty. Splunk is the team's eyes — you can't
evict what you can't see. The key discipline this week isn't advanced SPL; it's making detection a
**weekly reflex** so that by Phase 4 the team reads dashboards instinctively instead of scrambling.

**You need:** the Splunk box (Oracle Linux 9.2 / Splunk 10.0.2, `172.20.242.20`, creds in
[`../07-competition-reference.md`](../07-competition-reference.md)), the repo's Splunk assets (paths
below), and a few hosts whose logs should be flowing in.

---

## Learning objectives
By end of the weeknight session, every member can:
1. Explain the Splunk model: **forwarders** on each host ship logs to the **indexer/search head**.
2. Confirm a host's forwarder is connected and reporting.
3. Run the core failed-login search (Linux + Windows) and read the results.
4. Open a repo dashboard and spot an anomaly (a spike in failed logins, an odd source IP).

By the weekend lab, every member confirms a forwarder, runs the failed-login search, and reads a
dashboard, unaided.

## Weeknight session plan (2–3 hr)
- **0:00–0:15 — Warm-up:** Week 9 — write a firewall rule + verify the service (keeps `T2-C4/C6` warm).
- **0:15–0:40 — Concept:** the Splunk architecture — universal forwarders on each box → the Splunk
  indexer/search head. Where the repo deploys them: [`splunk-forwarders/`](../../CCDC-main-Matt_2026/CCDC-main/splunk-forwarders/)
  (`deploy-forwarder-linux.sh`, `Deploy-Forwarder-Windows.ps1`) and
  [`Linux/Splunk/`](../../CCDC_2026/Linux/Splunk/) (`LinuxUF.sh`, `WindowsUF.sh`).
- **0:40–1:05 — Concept + demo:** searching — `index=* "Failed password"` (Linux) and Windows
  `EventCode=4625`; the dashboards in [`splunk-dashboards/`](../../CCDC-main-Matt_2026/CCDC-main/splunk-dashboards/)
  (`ccdc_security_overview.xml`, `ccdc_linux_security.xml`, `ccdc_windows_security.xml`).
- **1:05–2:15 — Guided lab:** run [`lab-exercises.md`](lab-exercises.md) — confirm forwarders, run
  searches, load dashboards, generate a failed login and watch it appear.
- **2:15–2:30 — Debrief + assign [`homework.md`](homework.md); preview Week 11 (IR + Core checkpoint).**

## Weekend lab plan (3–5 hr)
- **Warm-up (20m):** credential sweep OR firewall+verify, one box (keep Weeks 8–9 warm).
- **Detection lab (90m):** members confirm every assigned host's forwarder, run the failed-login search
  live while a partner generates failed logins, and identify the source in a dashboard. Facilitator
  breaks one forwarder; members find and fix the gap (a silent host is a blind spot in competition).
- **Assessment (30m):** run [`assessment.md`](assessment.md).
- **AAR (15m).**

## Facilitator notes & common snags
- **A missing forwarder = a blind box.** Drill "which hosts are reporting, which aren't?" — a host
  that stops sending logs is exactly where the Red Team wants to work.
- **Keep SPL minimal.** This week is *confirm data flows + run two known searches + read a dashboard.*
  Building custom detections is Phase 2 (`T3-SP2`). Don't overload beginners with SPL syntax.
- **Make it live.** The best moment is a member generating a failed login on one box and watching it
  appear in Splunk seconds later — that "I can see them" click is what makes monitoring stick.
- Splunk hardening (`T3-SP3`) is later; this week just get everyone *using* it.

## Definition of done
Every member has `T2-S1`, `T2-S2` ✅ — confirmed a forwarder, ran the failed-login search, read a
dashboard and named an anomaly — or a partner + plan.
