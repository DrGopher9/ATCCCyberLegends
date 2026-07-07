# Week 10 — Homework (solo, before the weekend lab / Week 11)

Alone in the Splunk UI. Budget ~1 hour. Goal: confirming data and running the core searches becomes
automatic.

## 1. Who's reporting? (~15 min)
- [ ] Run `| metadata type=hosts index=*` and list which competition hosts are reporting
- [ ] Write down any host that is **silent** (a blind spot)

## 2. The two searches, from memory (~20 min)
- [ ] Run the Linux failed-login search (`"Failed password"` → `stats count by src_ip`)
- [ ] Run the Windows failed-login search (`EventCode=4625` → `stats count by Account_Name, src_ip`)
- [ ] Note the top source IPs each returns

## 3. Read a dashboard (~15 min)
- [ ] Open the security overview dashboard
- [ ] Write one anomaly sentence in the format: **"host X, [what], from IP Y, at time Z"**

## 4. Concept check (~10 min)
- [ ] In your own words: what's the difference between a forwarder and the indexer/search head?
- [ ] Why is a host that stops sending logs a problem in competition?

## Bring to the weekend lab / Week 11
- Your list of silent hosts (if any)
- Your two failed-login searches, memorized
- Your one anomaly sentence
