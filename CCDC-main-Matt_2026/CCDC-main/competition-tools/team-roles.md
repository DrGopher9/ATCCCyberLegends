# CCDC Team Roles & Organization

## Team Structure

### Option A: System-Based (Recommended for 6-8 members)

| Role | Primary Systems | Backup For |
|------|-----------------|------------|
| **Team Captain** | Coordination, Injects, White Team | Everything |
| **Windows Lead** | Windows AD, DNS, DHCP | Firewall |
| **Linux Lead 1** | E-Commerce (Ubuntu), Splunk | Email |
| **Linux Lead 2** | Email Server, Webmail (Fedora) | E-Commerce |
| **Network Lead** | Firewall, Network Monitoring | Windows |
| **Splunk/Monitor** | Splunk SIEM, All Dashboards | Linux |

### Option B: Function-Based (For smaller teams)

| Role | Responsibilities |
|------|------------------|
| **Captain** | Injects, coordination, documentation |
| **Hardening** | Run hardening scripts on all systems |
| **Monitoring** | Watch Splunk, respond to alerts |
| **Incident Response** | Handle active attacks |

---

## Role Responsibilities

### Team Captain
- [ ] Primary White Team contact
- [ ] Receive and delegate injects
- [ ] Track overall progress
- [ ] Make critical decisions
- [ ] Manage time
- [ ] Keep team calm under pressure

**DO NOT**: Get hands-on with systems unless emergency

### Windows Lead
- [ ] Harden Windows AD server
- [ ] Manage AD users and groups
- [ ] Monitor Windows security events
- [ ] Handle Windows-specific injects
- [ ] Maintain DNS/DHCP services

**Priority Services**: AD Authentication, DNS, DHCP

### Linux Leads
- [ ] Harden assigned Linux systems
- [ ] Monitor SSH and web services
- [ ] Handle Linux-specific injects
- [ ] Maintain web applications

**Priority Services**: Web (HTTP/HTTPS), Email (SMTP/IMAP)

### Network Lead
- [ ] Harden firewall
- [ ] Monitor network traffic
- [ ] Block malicious IPs
- [ ] Maintain network connectivity
- [ ] Troubleshoot connectivity issues

**Priority**: Don't break network access!

### Splunk/Monitoring Lead
- [ ] Deploy forwarders to all systems
- [ ] Monitor dashboards continuously
- [ ] Alert team to suspicious activity
- [ ] Create ad-hoc searches as needed
- [ ] Document incidents

**Priority**: Be the team's eyes

---

## Communication Plan

### During Competition

1. **Slack/Discord Channel** (if allowed)
   - #general - Team coordination
   - #alerts - Security alerts only
   - #injects - Inject tracking

2. **Verbal Communication**
   - Announce when starting major changes
   - Announce when completing tasks
   - Announce any service disruption
   - Call out active attacks

3. **Status Updates**
   - Every 30 minutes: Quick status round
   - "Windows: Green, no issues"
   - "Linux: Yellow, investigating SSH attempts"

### Code Words

| Code | Meaning |
|------|---------|
| **RED TEAM ACTIVE** | Active attack detected |
| **SERVICE DOWN** | Scored service is down |
| **INJECT** | New inject received |
| **NEED HELP** | Requesting assistance |
| **ALL CLEAR** | Situation resolved |

---

## Escalation Procedures

### Level 1: Team Member Handles
- Failed login attempts
- Minor configuration issues
- Routine injects

### Level 2: Lead Involvement
- Service disruption
- Suspected compromise
- Complex injects
- Multiple simultaneous issues

### Level 3: Captain Decision
- Major service outage
- Confirmed breach
- Resource conflicts
- White Team interaction needed

---

## Shift Schedule (8-hour competition)

| Time | Activity |
|------|----------|
| 0:00-0:15 | Initial hardening (ALL HANDS) |
| 0:15-0:30 | Credential rotation (ALL HANDS) |
| 0:30-1:00 | Complete hardening, deploy forwarders |
| 1:00-2:00 | Monitoring begins, handle injects |
| 2:00-4:00 | Normal operations, 30-min check-ins |
| 4:00-4:15 | **BREAK** - Rotate one at a time |
| 4:15-6:00 | Normal operations |
| 6:00-7:00 | Increased vigilance (red team push) |
| 7:00-8:00 | Final defense, documentation |

---

## Handoff Checklist

When handing off a system:

- [ ] Current status (any active issues?)
- [ ] Recent changes made
- [ ] Pending tasks
- [ ] Known vulnerabilities not yet addressed
- [ ] Current password (if changed)

---

## Pre-Competition Checklist

### Week Before
- [ ] Practice with scripts on lab systems
- [ ] Assign roles and backups
- [ ] Review inject templates
- [ ] Study common attack patterns
- [ ] Test team communication

### Day Before
- [ ] Rest well
- [ ] Prepare supplies (snacks, water, caffeine)
- [ ] Print quick reference cards
- [ ] Charge laptops
- [ ] Test VPN/remote access (if applicable)

### Competition Morning
- [ ] Arrive early
- [ ] Set up workstations
- [ ] Test network connectivity
- [ ] Review roles one more time
- [ ] **Stay calm, work together**

---

## Golden Rules

1. **Don't break services** - Uptime is points
2. **Document everything** - For injects and troubleshooting
3. **Communicate** - No silent heroes
4. **Prioritize** - Scored services first
5. **Stay calm** - Panic causes mistakes
6. **Trust your teammates** - You can't do it alone
7. **Have fun** - It's a learning experience
