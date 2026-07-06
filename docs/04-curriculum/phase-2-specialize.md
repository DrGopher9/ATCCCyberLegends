# Phase 2 — Specialize + Threat-Informed (Weeks 12–15, Oct)

**Goal:** each member takes a specialty box, learns it cold, and defends it against the red team
attacking it **live in the lab.**

**Council lens:** the Red Teamer owns this phase. Every module opens with an attack so students feel
the threat before they memorize the defense. Everyone keeps the Core sharp via weekly warm-ups.

**Specialty tracks (actual boxes — see [`07-competition-reference.md`](../07-competition-reference.md)):**
Windows AD/DNS (Server 2019) · Windows Web/FTP (IIS + Server 2022) · E-Commerce (Ubuntu) ·
Email/Webmail (Fedora, SMTP/POP3) · Network (Palo Alto + Cisco FTD + VyOS) · Splunk SIEM. Map to roles
in [`03-team-roles-and-comms.md`](../03-team-roles-and-comms.md) and rubric tracks in
[`02-readiness-rubric.md`](../02-readiness-rubric.md).

**Exit gate:** each member passes their **Tier-3 specialty track** in
[`02-readiness-rubric.md`](../02-readiness-rubric.md).

## Weeks

| Wk | Focus | Lab spine |
|---|---|---|
| 12 | Deep-dive your box: services, scored components, normal state, failure modes | Document your box's baseline; break & recover each scored service |
| 13 | **Red team attacks your box**; you observe & detect | Watch the attack live, then find it in Splunk/logs |
| 14 | Harden + monitor against those attacks; write detections | Defend against exactly what you just saw; verify service stays up |
| 15 | **Persistence hunting** + Tier-3 checkpoint | Find & evict planted persistence on your box; specialty assessment |

## Teaching notes
- The attack-first ordering is the whole point — resist the urge to teach defenses in the abstract.
- Cross-training starts informally: sit each specialist with their backup during Week 12 baselining.
- Keep Core warm: every session's warm-up is a Tier-2 skill under time pressure.

## Resources
- [`red-team-playbook.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/red-team-playbook.md)
- [`persistence-hunting.md`](../../CCDC-main-Matt_2026/CCDC-main/competition-tools/persistence-hunting.md)
- Per-box scripts under `CCDC_2026/Windows/`, `CCDC_2026/Linux/`, `CCDC_2026/Firewall/`, and the
  service runbooks in `CCDC-main-Matt_2026/CCDC-main/` (`fedora-webmail/`, `ecomm-ubuntu/`,
  `email-server/`, `firewall/`, `splunk-siem/`)
