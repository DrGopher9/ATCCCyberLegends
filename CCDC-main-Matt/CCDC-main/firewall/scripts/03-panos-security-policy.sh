#!/bin/bash
###############################################################################
# 03-panos-security-policy.sh - Security Policy Hardening
# Target: Palo Alto VM (PAN-OS 11.x)
# Purpose: Harden security policies to block attacks while allowing scoring
###############################################################################

cat << 'POLICY_COMMANDS'
================================================================================
PALO ALTO SECURITY POLICY HARDENING
Run these commands in PAN-OS CLI (configuration mode)
================================================================================

Based on the network topology:
- Internal: 172.20.240.0/24 (DNS/NTP Server)
- User: 172.20.242.0/24 (AD/DNS/DHCP, Web Server)
- Public: 172.20.241.0/24 (E-Commerce, Webmail, Splunk)

#=============================================================================
# STEP 1: REVIEW CURRENT POLICIES
#=============================================================================

# In operational mode:
show running security-policy

# Check for dangerous rules:
# - source=any, destination=any, action=allow
# - application=any with action=allow
# - Disabled security profiles

# Check rule hit counts (see which rules are used)
show rule-hit-count vsys vsys1 security

#=============================================================================
# STEP 2: CREATE SECURITY ZONES (if not exists)
#=============================================================================

configure

# Create zones for each network segment
set zone internal network layer3 ethernet1/1
set zone user network layer3 ethernet1/2
set zone public network layer3 ethernet1/3
set zone untrust network layer3 ethernet1/4

# Verify zones
show zone

#=============================================================================
# STEP 3: CREATE ADDRESS OBJECTS
#=============================================================================

# Internal servers
set address internal-dns ip-netmask 172.20.240.0/24
set address user-network ip-netmask 172.20.242.0/24
set address public-servers ip-netmask 172.20.241.0/24

# Scoring engine (adjust IP as needed)
set address scoring-engine ip-netmask <SCORING-ENGINE-IP>/32

# Create address groups
set address-group ccdc-servers static [ internal-dns user-network public-servers ]

#=============================================================================
# STEP 4: ALLOW SCORING ENGINE TRAFFIC (CRITICAL!)
#=============================================================================

# Allow scoring engine to reach all scored services
# IMPORTANT: Get scoring engine IPs from White Team

set rulebase security rules allow-scoring-engine from untrust to public
set rulebase security rules allow-scoring-engine source scoring-engine
set rulebase security rules allow-scoring-engine destination public-servers
set rulebase security rules allow-scoring-engine application any
set rulebase security rules allow-scoring-engine service any
set rulebase security rules allow-scoring-engine action allow
set rulebase security rules allow-scoring-engine log-start yes
set rulebase security rules allow-scoring-engine log-end yes

# Move to top of rulebase
move rulebase security rules allow-scoring-engine top

#=============================================================================
# STEP 5: ALLOW ESSENTIAL SERVICES TO PUBLIC ZONE
#=============================================================================

# Allow HTTP/HTTPS to public web servers (E-Commerce, Webmail)
set rulebase security rules allow-web-public from untrust to public
set rulebase security rules allow-web-public source any
set rulebase security rules allow-web-public destination public-servers
set rulebase security rules allow-web-public application [ web-browsing ssl ]
set rulebase security rules allow-web-public service application-default
set rulebase security rules allow-web-public action allow
set rulebase security rules allow-web-public log-end yes

# Allow SMTP to mail server
set rulebase security rules allow-smtp-public from untrust to public
set rulebase security rules allow-smtp-public source any
set rulebase security rules allow-smtp-public destination <mail-server-ip>
set rulebase security rules allow-smtp-public application smtp
set rulebase security rules allow-smtp-public service application-default
set rulebase security rules allow-smtp-public action allow
set rulebase security rules allow-smtp-public log-end yes

# Allow IMAP/POP3 to mail server
set rulebase security rules allow-mail-access from untrust to public
set rulebase security rules allow-mail-access source any
set rulebase security rules allow-mail-access destination <mail-server-ip>
set rulebase security rules allow-mail-access application [ imap imaps pop3 pop3s ]
set rulebase security rules allow-mail-access service application-default
set rulebase security rules allow-mail-access action allow
set rulebase security rules allow-mail-access log-end yes

#=============================================================================
# STEP 6: INTERNAL ZONE POLICIES
#=============================================================================

# Allow internal DNS queries
set rulebase security rules allow-dns-internal from [ user public ] to internal
set rulebase security rules allow-dns-internal source any
set rulebase security rules allow-dns-internal destination internal-dns
set rulebase security rules allow-dns-internal application dns
set rulebase security rules allow-dns-internal service application-default
set rulebase security rules allow-dns-internal action allow

# Allow NTP
set rulebase security rules allow-ntp from any to internal
set rulebase security rules allow-ntp source any
set rulebase security rules allow-ntp destination internal-dns
set rulebase security rules allow-ntp application ntp
set rulebase security rules allow-ntp service application-default
set rulebase security rules allow-ntp action allow

#=============================================================================
# STEP 7: BLOCK DANGEROUS TRAFFIC
#=============================================================================

# Block common attack ports from untrust
set rulebase security rules block-dangerous from untrust to any
set rulebase security rules block-dangerous source any
set rulebase security rules block-dangerous destination any
set rulebase security rules block-dangerous application [ telnet ssh rdp vnc-base smb ]
set rulebase security rules block-dangerous service any
set rulebase security rules block-dangerous action deny
set rulebase security rules block-dangerous log-end yes

# Block outbound to known bad ports (C2 channels)
set rulebase security rules block-outbound-suspicious from any to untrust
set rulebase security rules block-outbound-suspicious source any
set rulebase security rules block-outbound-suspicious destination any
set rulebase security rules block-outbound-suspicious service [ tcp/4444 tcp/5555 tcp/6666 tcp/31337 ]
set rulebase security rules block-outbound-suspicious action deny
set rulebase security rules block-outbound-suspicious log-end yes

#=============================================================================
# STEP 8: APPLY SECURITY PROFILES TO RULES
#=============================================================================

# Create a security profile group for CCDC
set profile-group ccdc-protection virus default
set profile-group ccdc-protection spyware default
set profile-group ccdc-protection vulnerability default
set profile-group ccdc-protection url-filtering default

# Apply to allow rules
set rulebase security rules allow-web-public profile-setting group ccdc-protection
set rulebase security rules allow-smtp-public profile-setting group ccdc-protection
set rulebase security rules allow-mail-access profile-setting group ccdc-protection

#=============================================================================
# STEP 9: CREATE EXPLICIT DENY RULE (Last Rule)
#=============================================================================

# Deny and log all other traffic (important for visibility)
set rulebase security rules deny-all from any to any
set rulebase security rules deny-all source any
set rulebase security rules deny-all destination any
set rulebase security rules deny-all application any
set rulebase security rules deny-all service any
set rulebase security rules deny-all action deny
set rulebase security rules deny-all log-end yes

# Move deny-all to bottom
move rulebase security rules deny-all bottom

#=============================================================================
# STEP 10: DISABLE/DELETE DANGEROUS RULES
#=============================================================================

# Disable any "any-any-allow" rules
set rulebase security rules <rule-name> disabled yes

# Or delete them entirely
delete rulebase security rules <dangerous-rule-name>

#=============================================================================
# STEP 11: COMMIT AND VERIFY
#=============================================================================

# Validate configuration
validate full

# Commit changes
commit

# Verify policies (operational mode)
exit
show running security-policy

# Monitor traffic
show session all filter destination <server-ip>

POLICY_COMMANDS

echo ""
echo "============================================"
echo "SECURITY POLICY CHECKLIST"
echo "============================================"
echo ""
echo "[ ] Review current policies for 'any-any-allow'"
echo "[ ] Create scoring engine allow rule at TOP"
echo "[ ] Allow HTTP/HTTPS to public servers"
echo "[ ] Allow SMTP/IMAP to mail server"
echo "[ ] Allow DNS/NTP to internal servers"
echo "[ ] Block dangerous protocols from untrust"
echo "[ ] Apply security profiles to allow rules"
echo "[ ] Create explicit deny-all at bottom"
echo "[ ] Disable/delete overly permissive rules"
echo "[ ] Commit and test"
echo ""
echo "CRITICAL: Always keep scoring engine traffic allowed!"
