# Readiness Rubric — What "Competition-Ready" Means

Two gates decide readiness: **tiered individual checklists** (below) and the **capstone team
scrimmage** (bottom). A member is *individually ready* when they pass Tiers 1–3 for their role. The
*team* is ready when it hits the capstone thresholds in a dress-rehearsal scrimmage.

Every rubric item has an ID (e.g. `T1-L4`) so modules and assessments can reference it directly.

**How to assess:** a coach or a peer watches the member *perform* the item — not describe it — under a
time budget. Mark ✅ pass / 🔁 needs another rep. Track per member in a simple sheet (name × item).

**Where the points are** (from [`07-competition-reference.md`](07-competition-reference.md), the
packet's scoring model): functional-service **uptime 35–50%**, **inject completion 35–50%**, and
**exploitation/IR reports 10–20%**. Injects are worth as much as uptime — the rubric weights all three,
not just defense. Scored services are **HTTP, HTTPS, SMTP, POP3, DNS** (POP3 authenticates against AD
usernames; FTP may also be scored).

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
| T2-I3 | Write a scorable **incident report**: source/dest IP, timeline, passwords cracked, what was affected, remediation | Report meets the packet's IR contents (see [`07`](07-competition-reference.md)) — exploitation, not misconfiguration |

**Tier 2 checkpoint = Phase 1 exit gate.**

---

## Tier 3 — Specialty Mastery (exit Phase 2)

Role-specific. Each member passes the track for the box(es) they own. Tracks map to the **actual 11-VM
topology** in [`07-competition-reference.md`](07-competition-reference.md). With 8 competitors and more
boxes than people, some members own two (e.g. Web + FTP). Backups pass a lighter version of their
backup role's track (see cross-training in [`03-team-roles-and-comms.md`](03-team-roles-and-comms.md)).

### T3-AD — Windows AD / DNS (Server 2019, `172.20.240.102`)
| ID | Item |
|---|---|
| T3-AD1 | Harden AD without breaking authentication (**POP3/mail auth uses AD accounts** — don't break it) |
| T3-AD2 | Audit Domain Admins, GPOs, and scheduled tasks; remove a planted persistence |
| T3-AD3 | Keep **DNS** scored while hardening |
| T3-AD4 | Detect Kerberoasting / mass failed logons in Splunk |

### T3-WEB — Windows Web + FTP (Server 2019 IIS `…101`, Server 2022 FTP `…104`)
| ID | Item |
|---|---|
| T3-WEB1 | Keep **HTTP/HTTPS** (IIS) scored while hardening; verify with a real request |
| T3-WEB2 | Secure the FTP server; find and remove unauthorized files/accounts |
| T3-WEB3 | Find and remove a web shell / unauthorized IIS handler |
| T3-WEB4 | Detect web/FTP exploitation attempts in logs/Splunk |

### T3-EC — E-Commerce (Ubuntu Server 24.04, `172.20.242.30`)
| ID | Item |
|---|---|
| T3-EC1 | Harden the web/app stack without breaking the scored site (verify with a real request) |
| T3-EC2 | Find and remove a web shell / unauthorized file |
| T3-EC3 | Secure the database and its credentials |
| T3-EC4 | Detect web exploitation attempts in logs/Splunk |

### T3-EM — Email / Webmail (Fedora 42, `172.20.242.40`)
| ID | Item |
|---|---|
| T3-EM1 | Keep **SMTP and POP3** scored while hardening (POP3 auths against AD usernames) |
| T3-EM2 | Rotate mail credentials and remove unauthorized mailboxes/aliases |
| T3-EM3 | Harden the webmail app; verify login still works |
| T3-EM4 | Detect mail-service abuse / auth attacks |

### T3-NET — Firewalls + Router (Palo Alto, Cisco FTD, VyOS)
| ID | Item |
|---|---|
| T3-NET1 | Read and back up **all three** configs (PA, FTD, VyOS); explain the zones/interfaces |
| T3-NET2 | Write policy that protects services **without blocking the scoring engine**; **keep ICMP up except the PA core port** |
| T3-NET3 | Enable logging on both firewalls and spot malicious traffic |
| T3-NET4 | Restore a firewall/router config from backup fast |

### T3-SP — Splunk SIEM (Oracle Linux 9.2 / Splunk 10.0.2, `172.20.242.20`)
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
| **First 30 minutes** | Credential sweep + persistence sweep + firewall up on all boxes within 30 min | Sets the tempo of a 7-hr day |
| **Documentation** | Clean change-log; incident reports filed to packet spec; nothing touched without logging | IR reports are a scored 10–20% |
| **Communication** | Captain runs the floor; comms protocol held under pressure; professional tone | Tech Lead's non-negotiable |

> The packet weights **uptime 35–50% · injects 35–50% · IR 10–20%** (see
> [`07-competition-reference.md`](07-competition-reference.md)). The 90% figures above are coaching
> targets, not the scoring engine's — model scrimmages on a **7-hour single day (9am–4pm CST)** and
> adjust to the real 2027 numbers when that packet is published.

**Green light to compete:** every member has passed Tiers 1–3 for their role, every role has a
cross-trained backup, and the team has hit the capstone thresholds in at least one dress rehearsal.
