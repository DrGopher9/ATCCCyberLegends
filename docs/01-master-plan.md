# Master Plan — The Season

**Start:** July 2026 · **Target:** Minnesota CCDC state qualifier, **~late Jan 2027** (2026 was Jan 31,
one day, 9am–4pm CST) · **Stretch:** Erich J. Spengler Midwest Regional CCDC, **~March 2027** (2026 was
Mar 20–21 at Purdue University Northwest)

This is the season roadmap. Each phase has its own overview in [`04-curriculum/`](04-curriculum/); each
week is (or will be) a module folder like [`05-week-01-module/`](05-week-01-module/). Readiness is
measured by [`02-readiness-rubric.md`](02-readiness-rubric.md). Roles by
[`03-team-roles-and-comms.md`](03-team-roles-and-comms.md). **What the competition actually is** —
topology, scored services, scoring weights, rules — is in
[`07-competition-reference.md`](07-competition-reference.md); read it before planning any scrimmage.

> **Design principle:** *threat-informed phased progression.* Fundamentals first; red-team pressure
> ramps deliberately; early low-stakes scrimmages before high-stakes ones. Every week re-drills prior
> skills (spaced repetition).

---

## Calendar overview

| Phase | Weeks | Approx. dates | Theme | Exit gate |
|---|---|---|---|---|
| **0 — Foundations** | 1–7 | Jul – late Aug | Admin, networking, CLI, git, ROE | Tier-1 fundamentals check |
| **1 — Defensive Core** | 8–11 | Sep | Hardening, credentials, host FW, Splunk basics, IR | Tier-2 Core checklist |
| **2 — Specialize** | 12–15 | Oct | Own a box; red team attacks it; detect + defend; hunt persistence | Tier-3 specialty check |
| **3 — Integrate & Injects** | 16–19 | Nov | Team ops, injects, docs, comms, mini-scrimmages | Timed inject set + mini-scrimmage |
| **4 — Live-Fire & AAR** | 20–25 | Dec – mid-Jan | Full scrimmages, AARs, dress rehearsals | Capstone scrimmage thresholds |
| **5 — Taper & Qualifier** | 26–27 | Late Jan – Feb | Final prep, logistics, rest, compete | Compete at MN qualifier |
| **Regional bridge** | +2–4 | Feb – Mar | Harder red team, more services, scale up | Compete at Midwest Regional |

Adjust exact weeks to the academic calendar, breaks, and the confirmed qualifier date from the
current MN/Midwest team packet.

---

## The weekly rhythm (every week in-season)

```
   WEEKNIGHT SESSION (2–3 hr)          WEEKEND LAB (3–5 hr)            HOMEWORK (solo, ~1–2 hr)
   ───────────────────────────        ─────────────────────────      ─────────────────────────
   • Homework check-in (15m)          • Warm-up drill (prior skill)   • Reading / video
   • New concept + demo (45m)         • Main hands-on lab             • Repeat the week's core
   • Guided lab (60–75m)              • (Phase 3+) scrimmage           lab solo until fast
   • Debrief + assign homework        • AAR / debrief                 • Rubric self-check
```

- **Facilitator-led.** Each week's `facilitator-guide.md` lets any coach run the session.
- **Hands on keyboards.** No spectators. Pair beginners with steadier members early, then split them.
- **Spaced repetition.** The weekend warm-up always re-drills a skill from an earlier week.

---

## Phase 0 — Foundations (Weeks 1–7, Jul–Aug)

**Goal:** get every member — including total beginners — to a baseline where Phase 1 makes sense.
Nobody defends a Linux box well if they can't move around one.

| Wk | Focus | Key outcomes |
|---|---|---|
| 1 | Orientation, lab access, git, CCDC & ROE | Everyone can clone the repo, reach the lab, and state the rules of engagement — **built out in [`05-week-01-module/`](05-week-01-module/)** |
| 2 | Linux fundamentals I — filesystem, users, permissions, processes | Navigate, manage users/permissions, inspect processes |
| 3 | Linux fundamentals II — services, systemd, logs, packages | Start/stop/inspect services, read `journalctl`, patch |
| 4 | Windows fundamentals — users/groups, services, Event Viewer, PowerShell basics | Manage local users, services, read Security log |
| 5 | Networking — IP/subnets, ports, DNS, `ss`/`netstat`, reading a topology | Map the lab, identify what listens where |
| 6 | Active Directory concepts + the CCDC service map | Explain AD basics and which services are scored |
| 7 | **Foundations checkpoint** — Tier-1 assessment + review | Every member passes Tier 1 (or gets a remediation plan) |

Exit gate: **Tier-1 fundamentals check** in the rubric.

---

## Phase 1 — Defensive Core (Weeks 8–11, Sep)

**Goal:** the universal defensive skillset every member owns regardless of specialty. Manual first,
then the repo's scripts as understood accelerators.

| Wk | Focus | Key outcomes |
|---|---|---|
| 8 | Credentials — rotate every password/key, kill unknown accounts, sudoers/Domain Admins audit | The "credential sweep" done fast on Linux + Windows |
| 9 | Hardening & host firewalls — manual, then the repo scripts; **verify service + rollback** | Harden a box without breaking its scored service |
| 10 | Splunk basics — architecture, forwarders, first searches & dashboards | Confirm logs flow; run the failed-login search |
| 11 | Incident response fundamentals — detect, contain, evict, document; **Core checkpoint** | Run a basic IR cycle; pass Tier-2 Core |

Exit gate: **Tier-2 Core checklist.** Ties to the repo's
[quick-reference](../CCDC-main-Matt_2026/CCDC-main/competition-tools/quick-reference.md) and
[service-recovery](../CCDC-main-Matt_2026/CCDC-main/competition-tools/service-recovery.md).

---

## Phase 2 — Specialize + Threat-Informed (Weeks 12–15, Oct)

**Goal:** each member takes a specialty box, learns it deeply, and — crucially — **defends it against
the red team attacking it live in the lab.** Everyone still keeps the Core sharp via warm-ups.

Specialty tracks (the actual boxes — map to roles in [`03-team-roles-and-comms.md`](03-team-roles-and-comms.md)
and rubric tracks in [`02-readiness-rubric.md`](02-readiness-rubric.md)): Windows **AD/DNS** (Server
2019) · Windows **Web/FTP** (IIS + Server 2022) · **E-Commerce** (Ubuntu) · **Email/Webmail** (Fedora,
SMTP/POP3) · **Network** (Palo Alto + Cisco FTD + VyOS) · **Splunk** SIEM.

| Wk | Focus | Key outcomes |
|---|---|---|
| 12 | Deep-dive your box: what it runs, what's scored, how it breaks | Own your box's normal state cold |
| 13 | **Red team introduces attacks on your box**; you detect them in Splunk | See the attack, then the detection |
| 14 | Harden + monitor your box against those attacks; write detections | Defend against what you just saw |
| 15 | **Persistence hunting** across your box; Tier-3 specialty checkpoint | Find & evict planted persistence; pass Tier 3 |

Exit gate: **Tier-3 specialty check.** Uses
[persistence-hunting.md](../CCDC-main-Matt_2026/CCDC-main/competition-tools/persistence-hunting.md).

---

## Phase 3 — Integrate & Injects (Weeks 16–19, Nov)

**Goal:** stop being individuals with boxes and become a team. Introduce the inject workstream, the
comms protocol, and the first *low-stakes* scrimmages.

| Wk | Focus | Key outcomes |
|---|---|---|
| 16 | Team roles & comms protocol; the "first 30 minutes" runbook | Run the opening tempo as a team |
| 17 | Injects — workflow, templates, deadlines, professional writing | Complete a timed inject set to White Team standard |
| 18 | Documentation & change management under load | Keep a clean change-log during activity |
| 19 | **First mini-scrimmage** (short, gentle red team) + AAR | Survive contact; run an honest AAR |

Exit gate: **timed inject set + a mini-scrimmage** completed as a team. Uses
[inject-templates.md](../CCDC-main-Matt_2026/CCDC-main/competition-tools/inject-templates.md) and
[change-log.md](../CCDC-main-Matt_2026/CCDC-main/competition-tools/change-log.md).

---

## Phase 4 — Live-Fire & AAR (Weeks 20–25, Dec–mid-Jan)

**Goal:** repetition against a real red team, at increasing intensity, with a disciplined AAR after
every scrimmage. This is where the team actually gets good.

| Wk | Focus |
|---|---|
| 20 | Full scrimmage #1 (full service load, moderate red team) + AAR + fix list |
| 21 | Fix-it week: close the AAR gaps; re-drill weak skills |
| 22 | Full scrimmage #2 (heavier red team, full inject load) + AAR |
| 23 | Fix-it week + specialty cross-training (bench depth, backups for every role) |
| 24 | **Dress rehearsal:** full **7-hour (9am–4pm)** scrimmage under qualifier conditions + AAR |
| 25 | Final fixes; confirm the capstone thresholds are met |

Model scrimmages on the real format: a **single ~7-hour day**, injects via a NISE-like portal as PDFs,
IR reports scored, no VM reverts. See [`07-competition-reference.md`](07-competition-reference.md).

Exit gate: **capstone scrimmage thresholds** in the rubric (uptime %, injects on time, footholds
evicted, clean docs & comms). Every scrimmage uses [`templates/scrimmage-scorecard.md`](templates/scrimmage-scorecard.md)
and [`templates/aar-template.md`](templates/aar-template.md).

---

## Phase 5 — Taper & Qualifier (Weeks 26–27, late Jan–Feb)

**Goal:** peak, don't cram. Lock logistics, keep skills warm with light drills, rest, and execute.

- Confirm roster (up to 12; **8 compete**, min 4, max 2 grad students), roles, travel/setup logistics.
- **Submit the team GitHub repo URL to the State Director** so it's reachable via the web proxy during
  play — otherwise the repo is unavailable at game time (packet rule).
- Light skill-maintenance drills only — **no new content, no exhausting scrimmages** the final week.
- Print/prepare the in-competition kit (**printed materials are allowed; no USB/media**): quick-
  reference, first-30-minutes runbook, inject templates, change-log, password tracker, contact list,
  and the confirmed scored-service list.
- Pre-competition brief: rules review, comms plan, "if X breaks, who owns it," inject ownership,
  **times are CST**, inject responses are **PDFs** in the portal.
- **Compete.**

---

## Regional bridge (post-qualifier, if we advance)

A short, intense block: harder red team, more/faster injects, larger service surface. Focus on the
specific weaknesses the qualifier exposed, deepen bench cross-training, and raise scrimmage intensity.
Same rhythm, higher difficulty.

---

## How to build the rest of the season

Weeks 2+ are **scaffolded above, not yet written.** To build one:

1. Copy [`templates/module-template.md`](templates/module-template.md) into a new
   `05-week-NN-module/` folder (four files: facilitator guide, lab, homework, assessment).
2. Fill it from the week's row above and the phase overview.
3. Tie its assessment to the relevant rubric items.
4. Follow the shape of the built [`05-week-01-module/`](05-week-01-module/).
