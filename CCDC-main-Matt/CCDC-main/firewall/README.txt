================================================================================
CCDC PALO ALTO FIREWALL HARDENING GUIDE
PAN-OS 11.x
================================================================================

FIREWALL ACCESS:
  Web GUI: https://172.20.242.150
  SSH:     ssh admin@172.20.242.150

================================================================================
QUICK START
================================================================================

1. Review the master runbook:
   cat scripts/00-FIREWALL-RUNBOOK.sh

2. SSH to firewall and run reconnaissance:
   ssh admin@172.20.242.150

3. Follow the phase-by-phase hardening in the runbook

================================================================================
SCRIPT REFERENCE
================================================================================

| Script                        | Purpose                              |
|-------------------------------|--------------------------------------|
| 00-FIREWALL-RUNBOOK.sh        | Master runbook - start here          |
| 00-panos-recon.sh             | Reconnaissance commands              |
| 01-panos-backup.sh            | Backup configuration                 |
| 02-panos-admin-harden.sh      | Admin account hardening              |
| 03-panos-security-policy.sh   | Security policy rules                |
| 04-panos-zone-harden.sh       | Zone protection profiles             |
| 05-panos-logging.sh           | Syslog/SIEM configuration            |
| 06-panos-threat-prevention.sh | Threat prevention profiles           |
| 07-panos-incident-response.sh | Incident response commands           |

================================================================================
FIRST 15 MINUTES PRIORITY ORDER
================================================================================

1. BACKUP CONFIG (before anything!)
   save config to ccdc-backup

2. CHANGE ADMIN PASSWORD
   set mgt-config users admin password

3. REMOVE UNKNOWN ADMINS
   delete mgt-config users <suspicious>

4. CHECK FOR "ANY-ANY-ALLOW" RULES
   show running security-policy

5. ENSURE SCORING ENGINE ACCESS
   Create explicit allow rule at TOP

6. DISABLE DANGEROUS RULES
   set rulebase security rules <rule> disabled yes

7. ENABLE ZONE PROTECTION
   Apply flood/scan protection to untrust zone

8. UPDATE THREAT SIGNATURES
   request threat upgrade install version latest

================================================================================
NETWORK TOPOLOGY
================================================================================

Firewall Interfaces:
  Internal: 172.20.240.254/24 → DNS/NTP Server
  User:     172.20.242.254/24 → AD, Web Servers
  Public:   172.20.241.254/24 → E-Commerce, Mail, Splunk
  Untrust:  External/Internet

Zones:
  internal → Internal network
  user     → User/Server network
  public   → DMZ/Public services
  untrust  → Internet/External

================================================================================
CRITICAL REMINDERS
================================================================================

1. ALWAYS backup before changes
2. NEVER block scoring engine traffic
3. Keep one session open while testing changes
4. Document all admin credential changes
5. Check for "any-any-allow" rules immediately
6. Apply security profiles to allow rules
7. Enable logging on all rules

================================================================================
COMMON PAN-OS COMMANDS
================================================================================

OPERATIONAL MODE:
  show system info              # System information
  show admins all               # List admin accounts
  show running security-policy  # Current rules
  show session all              # Active sessions
  show session meter            # Session statistics
  show log threat               # Threat logs
  show log traffic              # Traffic logs
  show config diff              # Uncommitted changes

CONFIGURATION MODE:
  configure                     # Enter config mode
  commit                        # Apply changes
  exit                         # Exit config mode
  validate full                # Check config validity

EMERGENCY COMMANDS:
  clear session all filter source <IP>    # Kill sessions
  request restart system                   # Reboot firewall

================================================================================
BLOCK AN IP - QUICK REFERENCE
================================================================================

configure
set address attacker-ip ip-netmask <IP>/32
set rulebase security rules block-attacker from any to any
set rulebase security rules block-attacker source attacker-ip
set rulebase security rules block-attacker destination any
set rulebase security rules block-attacker action deny
set rulebase security rules block-attacker log-end yes
move rulebase security rules block-attacker top
commit

================================================================================
RESTORE CONFIGURATION
================================================================================

# List saved configs
show config saved

# Load backup
configure
load config from ccdc-backup-before-hardening
commit

================================================================================
SPLUNK INTEGRATION
================================================================================

Splunk Server: (check 172.20.241.x network)

Configure syslog:
  Device > Server Profiles > Syslog > Add
  - Server: <splunk-ip>
  - Port: 514
  - Transport: UDP

Apply to log forwarding profile and attach to rules.

Splunk searches:
  index=* sourcetype="pan:traffic"
  index=* sourcetype="pan:threat"
  index=* sourcetype="pan:system"

================================================================================
