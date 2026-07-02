# 📘 CLAUDE.md — CCDC Blue Team Defensive Repository

## 1. Purpose of This Repository

This repository exists to support a **Collegiate Cyber Defense Competition (CCDC) Blue Team**.
Its goal is to provide **repeatable, safe, and scorable defensive tooling** for:

- Securing enterprise services
- Maintaining service uptime
- Responding to Red Team activity
- Completing White Team business injects
- Producing judge-ready documentation

⚠️ **Defensive-only repository.** Offensive tooling or exploitation is prohibited.

---

## 2. Competition Context

This repository assumes participation in a **Midwest Invitational / National CCDC-style event** with:

- Live Red Team
- Live scoring engine
- Business + technical injects
- Strict rules of engagement

Breaking these assumptions can cause **point loss or disqualification**.

---

## 3. Non-Negotiable Rules

### 🚫 Forbidden
- Attacking or scanning other teams
- Attacking Red Team infrastructure
- DoS or traffic flooding
- Blocking scoring engine traffic
- IP allowlists that break public access
- Changing IPs/hostnames without inject approval
- Closed-source or trial software

### ✅ Allowed
- Patching and hardening
- Host-based firewalls
- Logging and monitoring
- Credential rotation
- Incident response
- Service migrations (public IP + function preserved)

---

## 4. Assumed Network Topology

### Firewall
- Palo Alto VM (PAN‑OS 11.x)
- Internal: 172.20.240.254/24
- User: 172.20.242.254/24
- Public: 172.20.241.254/24
- Management: https://172.20.242.150

### Typical Servers
| Role | OS | Network |
|---|---|---|
| AD / DNS / DHCP | Windows Server 2019 | User |
| Web | Ubuntu | User |
| DNS / NTP | Debian | Internal |
| E‑Commerce | CentOS 7 | Public |
| Webmail / Apps | Fedora | Public |
| SIEM | Splunk | Public |

---

## 5. Repository Design Rules

All scripts and configs must be:

- Defensive-first
- Testable
- Reversible
- Logged
- Documented

Every change must include **verification steps**.

---

## 6. Standard Deliverables

### Business Memo Template
Used for injects (firewalls, banners, NTP):

Executive Summary  
Technical Implementation  
Security Rationale  
Validation Evidence  

---

### Scripts
- PowerShell (.ps1)
- Bash (.sh)

Must include:
- Comments
- Logging
- Idempotency
- Safe defaults

---

### Detection Content
- Splunk SPL
- Windows Event IDs
- Linux auditd rules
- Sigma rules

---

## 7. Common Inject Categories

### Login Banners
- Legal warning language
- Windows, Linux, Firewall
- Must not block access

### Time Synchronization
- One internal stratum 2/3 source
- External NTP Pool
- ACLs or authentication
- Consistent timestamps

### Host-Based Firewalls
- Windows Defender Firewall
- iptables / nftables
- Allow required services only
- Preserve scoring access

---

## 8. Incident Response Expectations

Incident reports should include:

- Timeline
- Source/Destination IPs
- Affected systems
- Credentials impacted
- Remediation
- Prevention steps

---

## 9. Safe Assumptions

Claude may assume:
- Internet access is allowed but monitored
- Public documentation is permitted
- Availability matters as much as security

Claude must not assume:
- Systems are clean
- Defaults are secure
- Snapshots are available

---

## 10. Golden Rule

**If a change might break scoring, validate before applying.**

---

## 11. TL;DR

- Blue Team only
- Uptime matters
- Documentation is scored
- Every change must be defensible
- When unsure, ask White Team
