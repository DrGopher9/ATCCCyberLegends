# Readiness Rubric — What "Competition-Ready" Means

Two gates decide readiness: **tiered individual checklists** (below) and the **capstone team
scrimmage** (bottom). A member is *individually ready* when they pass Tiers 1–3 for their role. The
*team* is ready when it hits the capstone thresholds in a dress-rehearsal scrimmage.

Every rubric item has an ID (e.g. `T1-L4`) so modules and assessments can reference it directly.

**How to assess:** a coach or a peer watches the member *perform* the item — not describe it — under a
time budget. Mark ✅ pass / 🔁 needs another rep. Track per member in a simple sheet (name × item).

---

## Tier 1 — Universal Fundamentals (exit Phase 0)

Everyone, regardless of role. If you can't do these, you can't defend anything.

| ID | Item | Evidence of mastery |
|---|---|---|
| T1-G1 | Reach the lab, clone/pull the repo, work on a branch | Does it unaided in < 5 min |
| T1-G2 | State the CCDC rules of engagement and 3 things that cause point loss/DQ | Explains from memory |
| T1-L1 | Linux: navigate FS, manage users, read/set permissions | Creates user, fixes a permission, finds a file |
| T1-L2 | Linux: inspect processes and network listeners (`ps`, `ss`) | Finds what's listening on a port |
| T1-L3 | Linux: start/stop/status a service, read its logs (`systemctl`, `journalctl`) | Recovers a stopped service |
| T1-L4 | Linux: inspect `/etc/passwd`, sudoers, crontabs | Spots an out-of-place entry |
| T1-W1 | Windows: manage local users/groups, services | Disables an account, restarts a service |
| T1-W2 | Windows: open Event Viewer, find the Security log, run a basic PowerShell cmdlet | Finds failed logons |
| T1-N1 | Networking: explain IP/subnet/port/DNS; identify the lab's key services | Draws/labels the topology |

**Tier 1 checkpoint = Phase 0 exit gate.**

---

## Tier 2 — Defensive Core (exit Phase 1)

Everyone. The universal defensive reflexes.

| ID | Item | Evidence of mastery |
|---|---|---|
| T2-C1 | **Credential sweep** (Linux): rotate root + all user passwords, kill unknown accounts, audit sudoers | Whole box swept in a time budget |
| T2-C2 | **Credential sweep** (Windows): rotate Administrator, audit Domain/local admins, disable unknown accounts | Same, on Windows |
| T2-C3 | Find and remove unauthorized SSH keys across all users | Finds a planted key |
| T2-C4 | Write a host firewall rule by hand (allow scored service, deny rest) **without breaking the service** | Service still scores after |
| T2-C5 | Run a repo hardening script **and explain what it did and how to roll it back** | Explains + reverses one change |
| T2-C6 | **Verify a scored service works** after any change (curl/port/login test) | Confirms up before moving on |
| T2-S1 | Splunk: confirm a host's forwarder is reporting; run the failed-login search | Sees live data |
| T2-S2 | Splunk: read a dashboard and identify an anomaly | Points to the spike |
| T2-I1 | Run the basic IR cycle: detect → contain → evict → document one intrusion | Completes all four steps |
| T2-I2 | Keep a change-log entry for every change made during a drill | Log matches actions |

**Tier 2 checkpoint = Phase 1 exit gate.**

---

## Tier 3 — Specialty Mastery (exit Phase 2)

Role-specific. Each member passes the track for the box they own. Backups pass a lighter version of
their backup role's track (see cross-training in [`03-team-roles-and-comms.md`](03-team-roles-and-comms.md)).

### T3-AD — Windows AD / DNS / DHCP
| ID | Item |
|---|---|
| T3-AD1 | Harden AD without breaking authentication for scored services |
| T3-AD2 | Audit Domain Admins, GPOs, and scheduled tasks; remove a planted persistence |
| T3-AD3 | Keep DNS/DHCP scored while hardening |
| T3-AD4 | Detect Kerberoasting / mass failed logons in Splunk |

### T3-EC — E-Commerce (Ubuntu web/app/DB)
| ID | Item |
|---|---|
| T3-EC1 | Harden the web/app stack without breaking the scored site (verify with a real request) |
| T3-EC2 | Find and remove a web shell / unauthorized file |
| T3-EC3 | Secure the database and its credentials |
| T3-EC4 | Detect web exploitation attempts in logs/Splunk |

### T3-EM — Email + Webmail (Fedora)
| ID | Item |
|---|---|
| T3-EM1 | Keep SMTP/IMAP/webmail scored while hardening |
| T3-EM2 | Rotate mail credentials and remove unauthorized mailboxes/aliases |
| T3-EM3 | Harden the webmail app; verify login still works |
| T3-EM4 | Detect mail-service abuse / auth attacks |

### T3-FW — Palo Alto Firewall
| ID | Item |
|---|---|
| T3-FW1 | Read and back up the config; explain the zones/interfaces |
| T3-FW2 | Write a policy that protects services **without blocking the scoring engine** |
| T3-FW3 | Enable logging and spot malicious traffic |
| T3-FW4 | Restore config from backup fast |

### T3-SP — Splunk SIEM
| ID | Item |
|---|---|
| T3-SP1 | Confirm all forwarders reporting; fix a broken one |
| T3-SP2 | Build/adjust a detection search for a live attack |
| T3-SP3 | Keep Splunk itself hardened and scored |
| T3-SP4 | Be the team's eyes: call out an incident from the dashboard in real time |

**Tier 3 checkpoint = Phase 2 exit gate.**

---

## Capstone — Team Scrimmage Thresholds (exit Phase 4)

Measured in a **dress-rehearsal scrimmage under qualifier conditions** (Week 24), scored on
[`templates/scrimmage-scorecard.md`](templates/scrimmage-scorecard.md). The team is competition-ready
when it hits **all** of these in a single scrimmage:

| Dimension | Threshold | Why |
|---|---|---|
| **Scored-service uptime** | ≥ 90% across all scored services for the full window | Uptime is the point floor |
| **No self-inflicted outages** | Zero scored services taken down *by the team's own changes* | Blue Team's non-negotiable |
| **Injects on time** | ≥ 90% of injects submitted before deadline, to White-Team quality | Where the point spread lives |
| **Red-team footholds evicted** | Every foothold the red team establishes is detected and evicted, and reported | Red Teamer's non-negotiable |
| **First 30 minutes** | Credential sweep + persistence sweep + firewall up on all boxes within 30 min | Sets the day's tempo |
| **Documentation** | Clean change-log; incident reports filed; nothing touched without logging | White Team rewards it |
| **Communication** | Captain runs the floor; comms protocol held under pressure; professional tone | Tech Lead's non-negotiable |

> **Set exact uptime/inject percentages against the current MN/Midwest scoring model** once confirmed
> from the team packet. The values above are the coaching targets; adjust to the real engine if it
> differs.

**Green light to compete:** every member has passed Tiers 1–3 for their role, every role has a
cross-trained backup, and the team has hit the capstone thresholds in at least one dress rehearsal.
