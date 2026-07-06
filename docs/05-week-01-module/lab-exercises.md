# Week 1 — Lab Exercises: Reach the Lab & the Git Workflow

Work through these with the facilitator, at your own keyboard. Nothing here is graded yet — the goal
is to do each step once with help, so you can do it alone this weekend. If something breaks, say so;
things breaking is normal.

**Prereqs:** repo access, lab credentials, and a terminal (macOS/Linux terminal, or WSL/PowerShell on
Windows).

---

## Exercise 1 — Clone the repository

The repo is our source of truth for scripts, runbooks, and this training program.

```bash
git clone https://github.com/DrGopher9/ATCCCyberLegends.git
cd ATCCCyberLegends
ls
```

You should see `CCDC_2026/`, `CCDC-main-Matt_2026/`, `docs/`, and `README.md`.

**Read the root [`README.md`](../../README.md).** Note the rule in bold: **do not push directly to
`main`.** We always work on a branch. You'll practice that in Exercise 4.

---

## Exercise 2 — Pull the latest before you start

Always start a session with the current version so you're not working on stale files:

```bash
git pull origin main
```

Habit for the whole season: **pull before every lab.**

---

## Exercise 3 — Tour the training docs

```bash
ls docs
```

Open and skim:
- [`docs/README.md`](../README.md) — how the program works
- [`docs/01-master-plan.md`](../01-master-plan.md) — the season you're starting
- [`docs/02-readiness-rubric.md`](../02-readiness-rubric.md) — what you must be able to do to be ready

Find **your** first two rubric items: `T1-G1` and `T1-G2`. That's what this week proves.

---

## Exercise 4 — Make a change on a branch (never on `main`)

This is the workflow you'll use every time you touch the repo.

```bash
# 1. Make a branch named for you and what you're doing
git checkout -b week1-<yourname>

# 2. Create a scratch file to practice with
echo "My name is <yourname>. Week 1 done." > docs/scratch-<yourname>.txt

# 3. Stage and commit it
git add docs/scratch-<yourname>.txt
git commit -m "Week 1 practice: add scratch file for <yourname>"

# 4. Push YOUR BRANCH (not main)
git push origin week1-<yourname>
```

Then open a pull request on GitHub (the facilitator will show you where). **Never** run
`git push origin main`. If you ever see yourself typing that — stop.

> Why so strict? On a team repo, a bad push to `main` breaks everyone's environment. Branches keep
> your mistakes yours until they're reviewed.

---

## Exercise 5 — Reach the lab and find the systems

Connect to the replica lab (the facilitator provides the method and credentials — VPN/console/SSH as
configured).

Once connected, confirm you can reach a system and see what's running:

```bash
# On a Linux box in the lab:
whoami            # who am I logged in as?
hostname          # which box is this?
ip a              # what's my IP / network?
ss -tlnp          # what services are listening here?
```

Using the topology table in [`../07-competition-reference.md`](../07-competition-reference.md), find and
note where these live (there are **11 VMs**):
- The **two firewalls** (Palo Alto `172.20.242.254`, Cisco FTD `172.20.240.254`) and the **VyOS router**
- The **Windows AD/DNS** server (`172.20.240.102`) and **Windows Web** (`.101`) / **FTP** (`.104`)
- The **E-Commerce** Ubuntu box (`172.20.242.30`)
- The **Email/Webmail** Fedora box (`172.20.242.40`)
- **Splunk** (`172.20.242.20`)

Notice the network splits into two segments — Linux boxes behind Palo Alto (`172.20.242.x`), Windows
boxes behind Cisco FTD (`172.20.240.x`). You don't need to *do* anything to them yet. Just know they
exist and where they sit.

---

## Exercise 6 — Read the rules, write down three penalties

Open [`Claude.md`](../../CCDC-main-Matt_2026/CCDC-main/Claude.md) §3 (Non-Negotiable Rules). Write
down **three specific actions that would cost your team points or get you disqualified.** Keep this —
it's your `T1-G2` check in the assessment.

---

## Done?
You've hit every objective if you: cloned + pulled the repo, made a change on a branch (not `main`),
reached the lab and found the systems, and can name three rule violations. Practice Exercises 4 and 5
again solo this weekend until they're quick — that's [`homework.md`](homework.md).
