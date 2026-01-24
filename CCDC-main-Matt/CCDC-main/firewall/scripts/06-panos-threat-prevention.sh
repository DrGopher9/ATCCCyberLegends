#!/bin/bash
###############################################################################
# 06-panos-threat-prevention.sh - Threat Prevention Configuration
# Target: Palo Alto VM (PAN-OS 11.x)
# Purpose: Enable and configure threat prevention features
###############################################################################

cat << 'THREAT_COMMANDS'
================================================================================
PALO ALTO THREAT PREVENTION CONFIGURATION
Run these commands in PAN-OS CLI (configuration mode)
================================================================================

#=============================================================================
# STEP 1: CHECK CURRENT THREAT PREVENTION STATUS
#=============================================================================

# Operational mode - check threat statistics
show threat statistics

# Check current threat prevention profiles
show running security-profile-group

# Check threat signature version
show system info | match threat-version

# Check for updates
request threat upgrade check

#=============================================================================
# STEP 2: UPDATE THREAT SIGNATURES
#=============================================================================

# Check for available updates
request threat upgrade check

# Download latest threat signatures
request threat upgrade download latest

# Install threat signatures
request threat upgrade install version latest

# Verify update
show system info | match threat-version

#=============================================================================
# STEP 3: CREATE ANTIVIRUS PROFILE
#=============================================================================

configure

# Create strict antivirus profile
set profiles virus ccdc-antivirus decoder ftp action reset-both
set profiles virus ccdc-antivirus decoder ftp wildfire-action reset-both
set profiles virus ccdc-antivirus decoder http action reset-both
set profiles virus ccdc-antivirus decoder http wildfire-action reset-both
set profiles virus ccdc-antivirus decoder http2 action reset-both
set profiles virus ccdc-antivirus decoder imap action reset-both
set profiles virus ccdc-antivirus decoder pop3 action reset-both
set profiles virus ccdc-antivirus decoder smb action reset-both
set profiles virus ccdc-antivirus decoder smtp action reset-both

#=============================================================================
# STEP 4: CREATE ANTI-SPYWARE PROFILE
#=============================================================================

# Create anti-spyware profile (blocks command-and-control traffic)
set profiles spyware ccdc-antispyware botnet-domains action block
set profiles spyware ccdc-antispyware botnet-domains packet-capture disable

# DNS sinkhole for C2 domains
set profiles spyware ccdc-antispyware botnet-domains dns-sinkhole enable yes
set profiles spyware ccdc-antispyware botnet-domains dns-sinkhole ipv4-address 72.5.65.111
set profiles spyware ccdc-antispyware botnet-domains dns-sinkhole ipv6-address 2600:5200::1

# Block all spyware severity levels
set profiles spyware ccdc-antispyware rules critical-spyware threat-name any
set profiles spyware ccdc-antispyware rules critical-spyware category spyware
set profiles spyware ccdc-antispyware rules critical-spyware severity critical
set profiles spyware ccdc-antispyware rules critical-spyware action reset-both

set profiles spyware ccdc-antispyware rules high-spyware threat-name any
set profiles spyware ccdc-antispyware rules high-spyware severity high
set profiles spyware ccdc-antispyware rules high-spyware action reset-both

set profiles spyware ccdc-antispyware rules medium-spyware threat-name any
set profiles spyware ccdc-antispyware rules medium-spyware severity medium
set profiles spyware ccdc-antispyware rules medium-spyware action reset-both

#=============================================================================
# STEP 5: CREATE VULNERABILITY PROTECTION PROFILE
#=============================================================================

# Create vulnerability protection profile
set profiles vulnerability ccdc-vulnerability rules critical-vulns threat-name any
set profiles vulnerability ccdc-vulnerability rules critical-vulns category any
set profiles vulnerability ccdc-vulnerability rules critical-vulns severity critical
set profiles vulnerability ccdc-vulnerability rules critical-vulns action reset-both

set profiles vulnerability ccdc-vulnerability rules high-vulns threat-name any
set profiles vulnerability ccdc-vulnerability rules high-vulns severity high
set profiles vulnerability ccdc-vulnerability rules high-vulns action reset-both

set profiles vulnerability ccdc-vulnerability rules medium-vulns threat-name any
set profiles vulnerability ccdc-vulnerability rules medium-vulns severity medium
set profiles vulnerability ccdc-vulnerability rules medium-vulns action reset-both

# Block brute force attempts
set profiles vulnerability ccdc-vulnerability rules brute-force threat-name any
set profiles vulnerability ccdc-vulnerability rules brute-force category brute-force
set profiles vulnerability ccdc-vulnerability rules brute-force action reset-both

#=============================================================================
# STEP 6: CREATE URL FILTERING PROFILE
#=============================================================================

# Create URL filtering profile
set profiles url-filtering ccdc-url-filter action block category malware
set profiles url-filtering ccdc-url-filter action block category phishing
set profiles url-filtering ccdc-url-filter action block category command-and-control
set profiles url-filtering ccdc-url-filter action block category hacking
set profiles url-filtering ccdc-url-filter action block category proxy-avoidance-and-anonymizers

# Log URL access
set profiles url-filtering ccdc-url-filter log-container-page-only no

#=============================================================================
# STEP 7: CREATE FILE BLOCKING PROFILE
#=============================================================================

# Block dangerous file types
set profiles file-blocking ccdc-file-blocking rules block-executables application any
set profiles file-blocking ccdc-file-blocking rules block-executables file-type exe
set profiles file-blocking ccdc-file-blocking rules block-executables direction both
set profiles file-blocking ccdc-file-blocking rules block-executables action block

set profiles file-blocking ccdc-file-blocking rules block-scripts application any
set profiles file-blocking ccdc-file-blocking rules block-scripts file-type [ bat cmd ps1 vbs js ]
set profiles file-blocking ccdc-file-blocking rules block-scripts direction both
set profiles file-blocking ccdc-file-blocking rules block-scripts action block

#=============================================================================
# STEP 8: CREATE SECURITY PROFILE GROUP
#=============================================================================

# Create profile group with all threat prevention
set profile-group ccdc-threat-prevention virus ccdc-antivirus
set profile-group ccdc-threat-prevention spyware ccdc-antispyware
set profile-group ccdc-threat-prevention vulnerability ccdc-vulnerability
set profile-group ccdc-threat-prevention url-filtering ccdc-url-filter
set profile-group ccdc-threat-prevention file-blocking ccdc-file-blocking

#=============================================================================
# STEP 9: APPLY SECURITY PROFILES TO RULES
#=============================================================================

# Apply to inbound rules
set rulebase security rules allow-web-public profile-setting group ccdc-threat-prevention
set rulebase security rules allow-smtp-public profile-setting group ccdc-threat-prevention
set rulebase security rules allow-mail-access profile-setting group ccdc-threat-prevention

# Apply to outbound rules
set rulebase security rules outbound-web profile-setting group ccdc-threat-prevention

#=============================================================================
# STEP 10: CONFIGURE DDOS PROTECTION
#=============================================================================

# Enable DoS protection profile
set profiles dos-protection ccdc-dos flood tcp-syn enable yes
set profiles dos-protection ccdc-dos flood tcp-syn red alarm-rate 10000
set profiles dos-protection ccdc-dos flood tcp-syn red activate-rate 10000
set profiles dos-protection ccdc-dos flood tcp-syn red maximal-rate 40000

set profiles dos-protection ccdc-dos flood udp enable yes
set profiles dos-protection ccdc-dos flood udp red alarm-rate 10000
set profiles dos-protection ccdc-dos flood udp red activate-rate 10000

set profiles dos-protection ccdc-dos flood icmp enable yes
set profiles dos-protection ccdc-dos flood icmp red alarm-rate 1000
set profiles dos-protection ccdc-dos flood icmp red activate-rate 1000

# Create DoS protection policy
set rulebase dos rules protect-public-servers from untrust to public
set rulebase dos rules protect-public-servers source any
set rulebase dos rules protect-public-servers destination public-servers
set rulebase dos rules protect-public-servers protection aggregate ccdc-dos

#=============================================================================
# STEP 11: COMMIT AND VERIFY
#=============================================================================

# Validate
validate full

# Commit
commit

# Verify (operational mode)
exit

# Check threat statistics
show threat statistics

# Check for active threats
show threat id all

# Monitor threat logs
show log threat last 20

THREAT_COMMANDS

echo ""
echo "============================================"
echo "THREAT PREVENTION CHECKLIST"
echo "============================================"
echo ""
echo "[ ] Update threat signatures to latest"
echo "[ ] Create antivirus profile"
echo "[ ] Create anti-spyware profile with DNS sinkhole"
echo "[ ] Create vulnerability protection profile"
echo "[ ] Create URL filtering profile"
echo "[ ] Create file blocking profile"
echo "[ ] Create security profile group"
echo "[ ] Apply profiles to security rules"
echo "[ ] Configure DoS protection"
echo "[ ] Commit and verify"
echo ""
echo "MONITORING:"
echo "show threat statistics"
echo "show log threat"
echo ""
