# Council Analysis — Where the Team Stands, and What's Missing

Before designing the program, five perspectives assessed the repository and the situation: a
mostly-brand-new team, ~7 months of runway, a full replica lab, and a live coach/alumni red team.
Each speaks in their own voice below. Their combined verdict became the master plan.

> **The one-line verdict:** *You have an excellent competition toolbox and almost no way to train a
> beginner to open it under fire.* The repo is a strong reference layer; it is not a curriculum. This
> program is the curriculum.

---

## 🔴 The Red Teamer

> "I've owned teams like yours in the first ten minutes. Here's how, and here's what your repo tells
> me about you."

**What I see in your favor:** Your [`red-team-playbook.md`](../CCDC-main-Matt_2026/CCDC-main/competition-tools/red-team-playbook.md)
and [`persistence-hunting.md`](../CCDC-main-Matt_2026/CCDC-main/competition-tools/persistence-hunting.md)
are genuinely good. Whoever wrote them understands that I start with pre-planted access, default
creds, and persistence — not zero-days. That's the right mental model.

**What worries me:** A checklist is not a reflex. A brand-new team *reading* "check for UID 0 users"
is a world away from a nervous 19-year-old *finding* my backdoor account while I'm actively logging
back in and three services are alarming red. Your material assumes a defender who already moves fast.
Yours don't yet.

**How this changed the plan:**
- The curriculum is **ordered by my attack timeline**, not by technology. Week for week, students
  learn to defend against the *next* thing I'll do to them: credentials first, then unpatched
  services, then web shells, then persistence.
- Every specialty module in Phase 2 opens with **me attacking that box** so they feel the threat
  before they memorize the defense.
- Phases 3–4 put me in the lab live. Beginners must experience getting owned in a *low-stakes* setting
  long before the qualifier, and run the eviction until it's muscle memory.

**My non-negotiable:** by December, every member can execute the "first 30 minutes" — change every
credential, kill unknown sessions, find the obvious persistence — under time pressure, without a
checklist in front of them.

---

## 🔵 The Blue Teamer

> "The scripts are strong. The judgment to use them safely is what's untrained."

**What I see in your favor:** Real hardening depth. The [Windows AD script](../CCDC_2026/Windows/WindowsAD/Harden.ps1)
alone shows sophistication — GPO backups, monitor de-duplication, safe firewall defaults, a documented
changelog of bug fixes. The Splunk SIEM, dashboards, and forwarder deployment are a serious
detection stack most college teams never build.

**What worries me:** Powerful scripts in beginner hands are a **self-inflicted outage waiting to
happen**. A hardening script that's a touch too aggressive locks out the scoring engine, and now
you're losing points to *yourself* — no red team required. The team needs to understand *what each
script does and how to undo it* before they run it in anger. Right now the knowledge lives in the
scripts and in one or two people's heads.

**How this changed the plan:**
- Phase 1 teaches the **manual version of every automated step first** — change a password by hand,
  write a firewall rule by hand — so the script is a time-saver they understand, not a magic wand.
- Every hardening action in the curriculum is paired with **"how to verify the scored service still
  works"** and **"how to roll this back."** Backups and change-logs are trained as habits, not
  afterthoughts.
- Splunk is introduced early and used *every week* thereafter, so detection is a reflex, not a Phase-4
  panic.

**My non-negotiable:** no member runs a hardening script in a scrimmage they can't explain and can't
reverse.

---

## ⚪ The White Team Judge

> "Teams don't lose to the red team as often as they lose to themselves. I score both."

**What I see in your favor:** You have [inject templates](../CCDC-main-Matt_2026/CCDC-main/competition-tools/inject-templates.md),
a [change-log](../CCDC-main-Matt_2026/CCDC-main/competition-tools/change-log.md), and an incident
response template. You clearly know injects and documentation matter. Most rookie teams don't even
have that.

**What worries me:** Having a template is not the same as having the *discipline* to fill it out at
2:47 PM while everything is on fire. In my experience the point spread between a good team and a
great team is almost entirely: **injects completed on time, professional communication, and clean
documentation.** New teams treat injects as an interruption to "the real work." That mindset costs
more points than the red team does.

**How this changed the plan:**
- Injects are trained as a **first-class workstream from Phase 3 on**, with a dedicated owner and a
  clock. Every scrimmage includes a realistic inject load with hard deadlines.
- **Professional communication** is graded in scrimmages — how you talk to "the CEO," how you report
  an incident, how you say "no" to a request that would break a scored service or a rule.
- The rubric explicitly rewards **not breaking scored services** and **clean change-logs**, because I
  reward them.

**My non-negotiable:** by the qualifier, the team submits injects early, writes like professionals,
and never touches a scored service without logging it.

---

## 🟢 The Coach

> "I'm training humans, most of whom have never done this. Pedagogy wins seasons."

**What I see:** A brand-new team, a big pile of advanced material, and a natural temptation to dump it
all on them at once. That's how you lose people in September. Beginners need **early wins, visible
progress, and psychological safety** far more than they need more content.

**How this changed the plan:**
- **Tiered checklists** (Tier 1 → 2 → 3) so a nervous beginner can *see* themselves leveling up.
  Progress you can see is the single biggest retention lever I have.
- **Spaced repetition built into every week** — we re-drill prior skills, because a skill learned once
  in September is gone by December otherwise.
- **The bench trains as equals.** Alternates (10–12 total) run the same checklists; the starting 8 is
  earned by checklist + scrimmage performance, decided late, so everyone stays invested.
- **Practices are facilitator-guided**, so a session runs well even if the lead coach is out. That's
  what the module template is for.

**My non-negotiable:** nobody sits and watches. Every session, every member has hands on a keyboard.

---

## 🟡 The Former Technical Team Lead

> "The floor is chaos. Winning is a communication problem more than a technical one."

**What I see:** Your [`team-roles.md`](../CCDC-main-Matt_2026/CCDC-main/competition-tools/team-roles.md)
is a good start — it defines roles and a comms plan. But roles on paper collapse the moment three
things break at once and nobody knows who owns the decision.

**How this changed the plan:**
- **Roles are practiced, not just assigned.** From Phase 3 on, the team runs with the same role
  structure every scrimmage so it becomes second nature.
- A trained **comms protocol**: how you call out an incident, how the captain triages competing
  fires, how you hand off a box, how you avoid two people fighting the same red-team session in
  opposite directions.
- The captain trains to **not touch keyboards** — to coordinate, watch the clock, own the injects
  relationship, and keep the team calm. That's the hardest role and the least practiced.
- A drilled **"first 30 minutes"** runbook, because the opening tempo sets the whole day.

**My non-negotiable:** by the qualifier the team has a captain who runs the floor and a comms habit
that survives contact with the red team.

---

## Combined Gap Summary

| Gap the council found | Where the program closes it |
|---|---|
| Reference material assumes an already-fast defender | Phases 0–1 build the fundamentals and speed first |
| Powerful scripts, no trained judgment to run them safely | Phase 1 teaches manual-first + verify + rollback |
| Injects & professionalism treated as secondary | Phase 3+ trains injects as a graded first-class workstream |
| Roles/comms exist on paper but aren't drilled | Phases 3–4 practice the same roles every scrimmage |
| No way to measure who is ready | Tiered rubric + capstone scrimmage ([`02-readiness-rubric.md`](02-readiness-rubric.md)) |
| No progression / practice regimen | The whole season plan ([`01-master-plan.md`](01-master-plan.md)) |
| Some repo scripts are risky or inconsistent in beginner hands | Flagged as backlog ([`06-repo-gaps-backlog.md`](06-repo-gaps-backlog.md)) |
