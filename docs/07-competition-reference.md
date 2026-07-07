# Competition Reference — Ground Truth from the Team Packet

**This is the single source of truth for what the competition actually is.** Other docs reference it
instead of restating facts. Sourced from `CCDC_2026/2026MWCCDCQTeamPack.pdf` (identical copy at
`CCDC-main-Matt_2026/CCDC-main/MWCC DCQ Team Pack.pdf`).

> ⚠️ **This is the 2026 packet.** Our target is the **2027** MN qualifier — the 2027 packet isn't out
> yet. CCDC environments are stable year to year but **versions, IPs, and exact dates will change.**
> When the 2027 MN packet drops, re-read it and update this file. Treat everything here as "current
> best reference," not gospel.

---

## Format & schedule

- **One-day competition.** Active scoring **9:00am–4:00pm CST** (~7 hours), then debrief.
- 2026 MN qualifier was **Jan 31, 2026** (Minnesota & Indiana). Expect the **2027 MN qualifier in late
  January 2027** — confirm from the 2027 packet.
- **Welcome inject** released ~1 hr before start; teams log into NISE and respond to signal ready.
  A survey (part 1) is also released during the Welcome window.
- **Drop flag at 9am** — only then can teams access the competition environment. Before that, teams
  only have the NISE/Team Portal.
- **Regional (if we win state):** *Erich J. Spengler Midwest Regional CCDC* — 2026 was March 20–21 at
  **Purdue University Northwest, Hammond Campus.** Expect **~March 2027.** Winner advances to NCCDC.

**Training implication:** our scrimmages should model a **~7-hour single day**, not a multi-day event.
The first 30 minutes matter enormously in a 7-hour window.

---

## Scoring model (know where the points are)

| Component | Weight | Notes |
|---|---|---|
| **Functional services uptime** | **35–50%** | Measured by the scoring engine; must be up *and* serving correct content |
| **Inject / business task completion** | **35–50%** | Varying points by importance/complexity; hard deadlines |
| **Exploitation & Incident Response** | **10–20%** | IR reports you submit; focus on *exploitation events, not misconfiguration* |

Exact percentages are set by the White Team. **Points are lost** by: SLA violations (services down),
using recovery services (VM scrubs), and successful Red Team penetrations.

**Training implication:** injects are worth **as much as uptime.** A team that only defends and
ignores injects leaves half the points on the table. This is why injects are a graded, first-class
workstream from Phase 3 on.

---

## Scored functional services

Named in the packet (precise scored set is delineated via the Team Portal at game time):

| Service | What's tested | Likely host |
|---|---|---|
| **HTTP** | Fetch a specific page; content must match expected | Server 2019 Web (IIS) and/or Ubuntu Ecom |
| **HTTPS** | Same, over SSL | Server 2019 Web and/or Ubuntu Ecom |
| **SMTP** | Send/receive mail via a valid account | Fedora Webmail |
| **POP3** | POP3 against the system **using Active Directory usernames** | Fedora Webmail (auth tied to AD) |
| **DNS** | Lookups against the DNS server | Server 2019 AD/DNS |

> **POP3 authenticates against AD usernames** — mail and AD are coupled. Breaking AD accounts can
> break mail scoring. FTP (Server 2022) exists and may be scored — confirm on the Team Portal.
> Service ≠ just "port open": content/function is checked.

---

## Topology — 11 VMs, two firewalls, one router

Teams get **11 VMs: 6 servers, 2 workstations, Palo Alto + Cisco FTD firewalls, and a VyOS router.**
No snapshot/revert access (see rules). Two internal segments, each behind its own firewall.

### Segment A — behind **Palo Alto** (inside `172.20.242.0/24`)
| VM | Name | OS / Version | Default creds | Internal IP |
|---|---|---|---|---|
| 1 | **Ubuntu Ecom** | Ubuntu Server 24.04.3 | `sysadmin:changeme` | 172.20.242.30 |
| 2 | **Fedora Webmail** | Fedora 42 | `sysadmin:changeme` | 172.20.242.40 |
| 3 | **Splunk** | Oracle Linux 9.2 / Splunk 10.0.2 | `root:changemenow`, `sysadmin:changemenow`, `admin:changeme` | 172.20.242.20 |
| 4 | **Ubuntu Wks** | Ubuntu Desktop 24.04.3 | `sysadmin:changeme` | DHCP |

### Segment B — behind **Cisco FTD** (inside `172.20.240.0/24`)
| VM | Name | OS / Version | Default creds | Internal IP |
|---|---|---|---|---|
| 5 | **Server 2019 AD/DNS** | Windows Server 2019 Std | `administrator:!Password123` | 172.20.240.102 |
| 6 | **Server 2019 Web** | Windows Server 2019 Std | `administrator:!Password123` | 172.20.240.101 |
| 7 | **Server 2022 FTP** | Windows Server 2022 Std | `administrator:!Password123` | 172.20.240.104 |
| 8 | **Windows 11 Wks** | Windows 11 24H2 | `administrator:!Password123`, `UserOne:ChangeMe123` | 172.20.240.100 |

### Network devices
| VM | Name | Version | Default creds | Interfaces |
|---|---|---|---|---|
| 9 | **Palo Alto** | PAN-OS 11.0.2 | `admin:Changeme123` | outside 172.16.101.254/24 · inside 172.20.242.254/24 · **mgmt 172.20.242.150** |
| 10 | **Cisco FTD** | 7.2.9 | `admin:!Changeme123` | outside 172.16.102.254/24 · inside 172.20.240.254/24 · **mgmt 172.20.240.200** |
| 11 | **VyOS Router** | 1.4.3 | `vyos:changeme` | external 172.31.2x.2/29 (team) · net1 172.16.101.1/24 (→PA) · net2 172.16.102.1/24 (→FTD) |

**Access notes:** Palo Alto GUI via browser `https://172.20.242.150` (use the Ubuntu Wks). Cisco FTD
GUI via `https://172.20.240.200` (use the Windows 11 Wks, `https://172.20.102.254/#/login` per packet).

**Public IPs:** each service has a public IP in the team's pool `172.25.(20+team#).0/24`. Do **not**
move a service to a different public IP unless an inject directs it.

> Every VM ships with a **known default credential** (above). That is exactly why the **first-30-minute
> credential sweep** is drilled until it's reflex — the Red Team has these too.

---

## Load-bearing rules (the ones that cost points or DQ)

**Instant DQ:**
- Any offensive activity against other teams, Black/White/Red Team, or global assets (port scans,
  vuln scans, unauthorized connection attempts).
- Entering another team's network/workspace.
- Outside assistance from non-team members (advisers included) during play.
- Prohibited devices/media in the room; inappropriate internet content.

**Point loss / careful handling:**
- **Anything that interferes with the scoring engine is the team's fault** — a too-aggressive firewall
  rule, IDS/IPS action, or block that hits the scoring checks loses *your* points.
- **Keep ICMP up on all devices EXCEPT the Palo Alto core port.** The scoring engine relies on it.
- **No snapshot/revert.** Only a cold boot from the console (doesn't reset config). Tech Support can
  scrub a VM but it's **limited to 3 per event and carries a penalty** (request via inject). → Don't
  break things you can't fix; **back up configs before hardening.**
- **Passwords:** admin/root/sysadmin accounts are **not used for scoring** — change them freely,
  no notification. **Other** account password changes may need to follow White Team guidelines
  (POP3/mail auth uses AD accounts — be careful there).
- Recovery-service usage and successful Red Team penetrations lose points.

**Incident Reports (the IR / 10–20% component):**
- Submit an IR for **each Red Team incident you detect.** Must contain: **source & destination IPs, a
  timeline of activity, any passwords cracked, what was affected, and a remediation plan.**
- Scored on **clarity, thoroughness, accuracy.** Focus on **exploitation events, not
  misconfiguration.**
- **Frivolous/excessive communication can be scored negatively** — quality over quantity.

**Operational / logistics:**
- **Inject responses must be submitted as PDF** attachments in NISE.
- NISE/Team Portal shows service status + injects; **all times are CST.**
- **Printed reference materials are allowed** (books, checklists) — print the in-competition kit.
- The team **GitHub repo is reachable during play via the web proxy _only if_ its URL is submitted to
  the State Director before the event.** Do this in the taper (Phase 5).
- No contact with the Red Team during competition hours.
- **Team Captain** is the designated liaison to competition staff.
- Team: **up to 12 on the roster, up to 8 compete** (min 4), **max 2 graduate students.**

---

## What this corrected in our plan
- Scored services fixed to **HTTP, HTTPS, SMTP, POP3, DNS** (was "SMTP/IMAP").
- Topology fixed to **11 VMs, Palo Alto + Cisco FTD + VyOS** (repo `Claude.md` had only Palo Alto and
  wrong subnets — flagged in [`06-repo-gaps-backlog.md`](06-repo-gaps-backlog.md)).
- Scoring weights (uptime / injects / IR all material) baked into the [rubric](02-readiness-rubric.md).
- Scrimmages modeled on a **7-hour single day.**
- IR report contents and the "exploitation not misconfiguration / don't over-report" nuance added.
- Specialty tracks realigned to the **actual boxes** in [`03-team-roles-and-comms.md`](03-team-roles-and-comms.md).
