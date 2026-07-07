# Repo Gaps — Prioritized Backlog

Per the scope decision, this pass **flags** weaknesses the council found in the existing repo; it does
**not** fix them. Each item has a priority and a suggested owner/phase. Work these as a backlog during
fix-it weeks (Phase 4) or off-session — they directly affect how safely beginners can use the tooling.

Priority: **P1** = fix before scrimmages (Phase 3); **P2** = fix during Phase 4; **P3** = cleanup, any
time.

---

## P1 — Fix before the team relies on these under fire

| # | Gap | Where | Why it bites a beginner | Suggested fix |
|---|---|---|---|---|
| 1 | **Two parallel repo trees** with overlapping content | `CCDC_2026/` and `CCDC-main-Matt_2026/CCDC-main/` | Beginners won't know which script is current; they'll run a stale one | Pick one canonical tree; move the other to an `Archive/` or delete; document the choice in root README |
| 2 | **Hardening scripts use `set -e`** and abort mid-run | e.g. [`CCDC_2026/Linux/Ubuntu/Harden.sh`](../CCDC_2026/Linux/Ubuntu/Harden.sh) | A failure partway leaves a box **half-hardened** with no clear state — worst case for a novice | Make scripts idempotent + resumable, or log a clear "stopped at step N, state is X" on exit; teach rollback (Phase 1, T2-C5) |
| 3 | **Duplicate/ambiguous `Harden` scripts** per system | multiple `Harden.ps1` / `Harden.sh` / `Harden2.ps1` / `CCDC_3.0.ps1` | Which one is the real one? Beginners guess | Name by version/date, keep one blessed per system, archive the rest |
| 4 | **No dry-run / verify mode** on hardening scripts | most `*.sh` / `*.ps1` | Members can't preview what a script changes before running it live during a scored round | Add a `--dry-run` / `-WhatIf` path, or a companion "verify service still up" check |
| 5 | **`Claude.md` topology is inaccurate vs. the team packet** | [`CCDC-main-Matt_2026/CCDC-main/Claude.md`](../CCDC-main-Matt_2026/CCDC-main/Claude.md) §4 | Lists **only Palo Alto** (packet has **Palo Alto + Cisco FTD + VyOS**, 11 VMs), wrong subnets, and a "Public 172.20.241.x" that isn't in the packet. Beginners will build a wrong mental map | Reconcile to [`07-competition-reference.md`](07-competition-reference.md); update `Claude.md` from the 2027 packet when published |

---

## P2 — Fix during Phase 4 hardening

| # | Gap | Where | Why | Suggested fix |
|---|---|---|---|---|
| 6 | **Firewall posture is inconsistent** across scripts | Ubuntu harden notes "NO FIREWALL as requested"; others add rules; Palo Alto configs separate | Inconsistent defaults → a box is unexpectedly exposed or unexpectedly locked down. Also: **keep ICMP up except the PA core port** (packet) | Define one host-firewall standard per OS; make every script state its firewall behavior at the top |
| 7 | **Credential/rotation logic scattered** across per-service scripts | `*credential-rotation.sh`, `*PWchange.sh`, `root_pw.sh`, `pw.sh`, `windows_password_Reset.ps1` | No single trusted "sweep" — beginners miss a system | Consolidate into one documented credential-sweep runbook per OS, mapped to T2-C1/C2 |
| 8 | **Injects are `.docx`** (binary) | `CCDC_2026/Injects/*.docx` | Can't diff/review in git; easy to lose edits (note: real inject *responses* are submitted as PDF) | Convert templates to Markdown (mirror [`inject-templates.md`](../CCDC-main-Matt_2026/CCDC-main/competition-tools/inject-templates.md)) |
| 9 | **Detection coverage unverified** | `splunk-dashboards/`, `splunk-siem/` | Dashboards exist but no test that each detection actually fires on the matching attack | In Phase 2, for each attack the red team runs, confirm a dashboard/search catches it; log gaps |

---

## P3 — Cleanup, any time

| # | Gap | Where | Suggested fix |
|---|---|---|---|
| 10 | Leftover debug artifacts | commits like "Update print statement from 'Hello' to 'Goodbye'"; `cheese.sh`, `dove.sh` | Remove or clearly label sample/scratch scripts |
| 11 | `Archive.zip` and loose `Archive/` scripts unversioned/opaque | `CCDC-main-Matt_2026/CCDC-main/Archive.zip` | Unzip, keep what's used in git, drop the zip |
| 12 | Mixed/undocumented script assumptions (target OS version, default creds in comments) | various | Standard header block per script: target, assumptions, what it changes, how to roll back |
| 13 | No top-level index of "what script does what" | repo-wide | A `SCRIPTS.md` mapping system → blessed script → purpose |

---

## How to use this backlog
- **Don't let beginners run P1/P2-flagged scripts in a scrimmage until they understand the risk** —
  this is exactly why Phase 1 trains manual-first, verify, and rollback (Blue Teamer's rule).
- Turn each item into a branch + PR (never push to `main`) during a fix-it week.
- Re-audit after Phase 2, when specialists know their box well enough to fix its scripts properly.
