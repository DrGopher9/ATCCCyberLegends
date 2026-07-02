#!/bin/bash
###############################################################################
# 07-panos-incident-response.sh - Firewall Incident Response
# Target: Palo Alto VM (PAN-OS 11.x)
# Purpose: Quick response actions for security incidents
###############################################################################

cat << 'IR_COMMANDS'
================================================================================
PALO ALTO INCIDENT RESPONSE COMMANDS
Run these commands in PAN-OS CLI (operational mode unless noted)
================================================================================

#=============================================================================
# EMERGENCY: BLOCK AN IP ADDRESS IMMEDIATELY
#=============================================================================

# Option 1: Create EDL (External Dynamic List) for blocked IPs
# In config mode:
configure
set address blocked-attacker-1 ip-netmask <ATTACKER-IP>/32
set rulebase security rules block-attackers from any to any
set rulebase security rules block-attackers source blocked-attacker-1
set rulebase security rules block-attackers destination any
set rulebase security rules block-attackers action deny
set rulebase security rules block-attackers log-end yes
move rulebase security rules block-attackers top
commit

# Option 2: Add to existing block rule (if you have one)
configure
set address blocked-ip-<timestamp> ip-netmask <ATTACKER-IP>/32
set address-group blocked-attackers static <add-new-address>
commit

#=============================================================================
# EMERGENCY: KILL ALL SESSIONS FROM AN IP
#=============================================================================

# Clear all sessions from attacker IP
clear session all filter source <ATTACKER-IP>

# Clear sessions to a specific destination
clear session all filter destination <TARGET-IP>

# Clear sessions for a specific application
clear session all filter application ssh

#=============================================================================
# EMERGENCY: DISABLE A SECURITY RULE
#=============================================================================

configure
set rulebase security rules <rule-name> disabled yes
commit

#=============================================================================
# VIEW ACTIVE ATTACKS
#=============================================================================

# Show current threat events
show log threat

# Show threat statistics
show threat statistics

# Show active sessions with threats
show session all filter threat

# Show top attackers by session count
show session meter

# Real-time session monitoring
show session info

#=============================================================================
# INVESTIGATE SUSPICIOUS TRAFFIC
#=============================================================================

# Show all sessions from specific IP
show session all filter source <IP>

# Show all sessions to specific destination
show session all filter destination <IP>

# Show sessions by application
show session all filter application <app-name>

# Show sessions by port
show session all filter destination-port <port>

# Show sessions by zone
show session all filter from-zone untrust

# Detailed session info
show session id <session-id>

#=============================================================================
# CHECK FOR POLICY VIOLATIONS
#=============================================================================

# Show denied traffic
show log traffic last 50 filter ( action eq deny )

# Show allowed traffic to critical servers
show log traffic last 50 filter ( destination eq <critical-server-ip> )

# Show all traffic from untrust zone
show log traffic last 50 filter ( from eq untrust )

#=============================================================================
# CHECK FOR CONFIGURATION CHANGES
#=============================================================================

# Show recent configuration changes
show log config last 50

# Show uncommitted changes
show config diff

# Show who made changes
show log config last 20 filter ( admin neq "" )

#=============================================================================
# CAPTURE PACKETS FOR ANALYSIS
#=============================================================================

# Start packet capture
debug dataplane packet-diag set capture stage receive file rx.pcap
debug dataplane packet-diag set filter match source <IP>
debug dataplane packet-diag set capture on

# Stop capture
debug dataplane packet-diag set capture off

# Export capture
scp export debug-filter-pcap from rx.pcap to <scp-server>:/path/

#=============================================================================
# EMERGENCY: RESTORE PREVIOUS CONFIG
#=============================================================================

# List saved configurations
show config saved

# Load previous config
configure
load config from ccdc-backup-before-hardening

# Commit to restore
commit

#=============================================================================
# EMERGENCY: FACTORY RESET (LAST RESORT)
#=============================================================================

# WARNING: This will erase all configuration!
# Only use if completely compromised
# request system private-data-reset

#=============================================================================
# CHECK SYSTEM INTEGRITY
#=============================================================================

# Check system resources
show system resources

# Check for unusual processes
show system software status

# Check disk usage
show system disk-space

# Show management sessions
show admins

# Check running config hash
show config running | hash

#=============================================================================
# BLOCK SPECIFIC THREATS
#=============================================================================

# If you identify a specific threat ID, you can override the action
configure
set profiles vulnerability <profile-name> rules custom-block threat-name <threat-id>
set profiles vulnerability <profile-name> rules custom-block action reset-both
commit

#=============================================================================
# QUARANTINE A ZONE
#=============================================================================

# Emergency - block ALL traffic from a compromised zone
configure
set rulebase security rules quarantine-zone from <compromised-zone> to any
set rulebase security rules quarantine-zone source any
set rulebase security rules quarantine-zone destination any
set rulebase security rules quarantine-zone action deny
set rulebase security rules quarantine-zone log-end yes
move rulebase security rules quarantine-zone top
commit

# Remember to allow scoring engine traffic!

COMMANDS_END
================================================================================
IR_COMMANDS

echo ""
echo "============================================"
echo "INCIDENT RESPONSE QUICK REFERENCE"
echo "============================================"
echo ""
echo "BLOCK AN IP:"
echo "  configure"
echo "  set address bad-ip ip-netmask <IP>/32"
echo "  <add to block rule>"
echo "  commit"
echo ""
echo "KILL SESSIONS:"
echo "  clear session all filter source <IP>"
echo ""
echo "VIEW THREATS:"
echo "  show log threat"
echo "  show threat statistics"
echo ""
echo "VIEW SESSIONS:"
echo "  show session all filter source <IP>"
echo "  show session meter"
echo ""
echo "RESTORE CONFIG:"
echo "  configure"
echo "  load config from <saved-name>"
echo "  commit"
echo ""
echo "============================================"
