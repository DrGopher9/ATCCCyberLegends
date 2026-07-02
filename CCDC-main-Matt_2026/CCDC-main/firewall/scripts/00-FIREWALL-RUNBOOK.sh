#!/bin/bash
###############################################################################
# 00-FIREWALL-RUNBOOK.sh - CCDC Firewall First 15 Minutes Runbook
# Target: Palo Alto VM (PAN-OS 11.x)
#
# This runbook guides you through critical firewall hardening steps.
# Management IP: 172.20.242.150
###############################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

banner() {
    echo ""
    echo -e "${BLUE}============================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}============================================${NC}"
    echo ""
}

banner "CCDC PALO ALTO FIREWALL - FIRST 15 MINUTES"

cat << 'RUNBOOK'
================================================================================
PALO ALTO FIREWALL HARDENING RUNBOOK
================================================================================

ACCESS:
  Web GUI: https://172.20.242.150
  SSH:     ssh admin@172.20.242.150

================================================================================
PHASE 1: RECONNAISSANCE (Minute 0-2)
================================================================================

Connect to firewall and run these commands:

  show system info                    # System version and status
  show admins all                     # List all admin accounts
  show running security-policy        # Current firewall rules
  show zone                          # Zone configuration
  mailq                              # (just kidding, check session meter)
  show session meter                 # Active session count

LOOK FOR:
  [ ] Unknown admin accounts
  [ ] "any-any-allow" rules
  [ ] Disabled security profiles
  [ ] Open management access

================================================================================
PHASE 2: BACKUP (Minute 2-4) - CRITICAL!
================================================================================

BEFORE ANY CHANGES, backup the configuration:

  # In config mode
  configure
  save config to ccdc-backup-before-hardening

  # Verify
  exit
  show config saved

OR via Web GUI:
  Device > Setup > Operations > Export named configuration snapshot

================================================================================
PHASE 3: ADMIN ACCESS (Minute 4-8) - CRITICAL!
================================================================================

1. CHANGE ADMIN PASSWORD:
   configure
   set mgt-config users admin password
   commit

2. REMOVE UNKNOWN ADMINS:
   delete mgt-config users <suspicious-user>
   commit

3. CREATE BACKUP ADMIN:
   set mgt-config users ccdc-admin password
   set mgt-config users ccdc-admin permissions role-based superuser yes
   commit

4. RESTRICT MANAGEMENT ACCESS:
   set deviceconfig system permitted-ip 172.20.242.0/24
   commit

5. DISABLE HTTP/TELNET:
   set deviceconfig system service disable-http yes
   set deviceconfig system service disable-telnet yes
   commit

RECORD NEW PASSWORDS:
  admin: ____________________
  ccdc-admin: ____________________

================================================================================
PHASE 4: SECURITY POLICIES (Minute 8-12) - CRITICAL!
================================================================================

1. IDENTIFY DANGEROUS RULES:
   show running security-policy
   # Look for source=any, dest=any, app=any, action=allow

2. ENSURE SCORING ENGINE ACCESS:
   # Create explicit allow for scoring engine at TOP of policy
   # Get scoring engine IP from White Team!

3. DISABLE/DELETE DANGEROUS RULES:
   configure
   set rulebase security rules <bad-rule> disabled yes
   commit

4. CREATE EXPLICIT DENY RULE AT BOTTOM:
   set rulebase security rules deny-all from any to any
   set rulebase security rules deny-all source any
   set rulebase security rules deny-all destination any
   set rulebase security rules deny-all action deny
   set rulebase security rules deny-all log-end yes
   move rulebase security rules deny-all bottom
   commit

================================================================================
PHASE 5: ZONE PROTECTION (Minute 12-14)
================================================================================

Enable zone protection for external zones:

  configure
  set network profiles zone-protection-profile external-protection flood tcp-syn enable yes
  set network profiles zone-protection-profile external-protection scan tcp-port enable yes
  set network profiles zone-protection-profile external-protection scan tcp-port action block-ip
  set zone untrust network zone-protection-profile external-protection
  commit

================================================================================
PHASE 6: THREAT PREVENTION (Minute 14-15)
================================================================================

1. UPDATE THREAT SIGNATURES:
   request threat upgrade check
   request threat upgrade download latest
   request threat upgrade install version latest

2. APPLY SECURITY PROFILES TO ALLOW RULES:
   configure
   set rulebase security rules allow-web-public profile-setting profiles virus default
   set rulebase security rules allow-web-public profile-setting profiles spyware default
   set rulebase security rules allow-web-public profile-setting profiles vulnerability default
   commit

================================================================================
POST-HARDENING VERIFICATION
================================================================================

[ ] Can access firewall from new session
[ ] Scoring engine traffic is allowed
[ ] Web services are reachable
[ ] Mail services are reachable
[ ] No unauthorized admin accounts
[ ] Dangerous rules disabled/deleted
[ ] Zone protection enabled
[ ] Threat prevention active

================================================================================
QUICK REFERENCE COMMANDS
================================================================================

Block an IP:
  configure
  set address blocked-ip ip-netmask <IP>/32
  <add to block rule and commit>

Kill sessions from IP:
  clear session all filter source <IP>

View threats:
  show log threat

View active sessions:
  show session all

Restore config:
  configure
  load config from ccdc-backup-before-hardening
  commit

================================================================================
RUNBOOK

echo ""
echo "============================================"
echo "SCRIPT REFERENCE"
echo "============================================"
echo ""
echo "Detailed scripts available in this directory:"
echo ""
echo "  00-panos-recon.sh          - Reconnaissance commands"
echo "  01-panos-backup.sh         - Backup procedures"
echo "  02-panos-admin-harden.sh   - Admin account hardening"
echo "  03-panos-security-policy.sh - Security policy hardening"
echo "  04-panos-zone-harden.sh    - Zone protection"
echo "  05-panos-logging.sh        - SIEM/logging configuration"
echo "  06-panos-threat-prevention.sh - Threat prevention"
echo "  07-panos-incident-response.sh - IR commands"
echo ""
echo "============================================"
echo "Good luck! Watch the logs for Red Team activity."
echo "============================================"
