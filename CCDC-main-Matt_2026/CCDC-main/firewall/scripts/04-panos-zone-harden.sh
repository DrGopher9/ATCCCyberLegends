#!/bin/bash
###############################################################################
# 04-panos-zone-harden.sh - Zone and Interface Hardening
# Target: Palo Alto VM (PAN-OS 11.x)
# Purpose: Harden zones, interfaces, and network settings
###############################################################################

cat << 'ZONE_COMMANDS'
================================================================================
PALO ALTO ZONE AND INTERFACE HARDENING
Run these commands in PAN-OS CLI (configuration mode)
================================================================================

Network Topology Reference:
- Internal Zone: 172.20.240.254/24 (to DNS/NTP)
- User Zone: 172.20.242.254/24 (to AD, Web servers)
- Public Zone: 172.20.241.254/24 (to E-Commerce, Mail, Splunk)
- Management: 172.20.242.150 (Web GUI access)

#=============================================================================
# STEP 1: REVIEW CURRENT ZONE CONFIGURATION
#=============================================================================

# Operational mode
show zone

# Show interfaces
show interface all

# Show routing
show routing route

#=============================================================================
# STEP 2: CONFIGURE ZONE PROTECTION PROFILES
#=============================================================================

configure

# Create zone protection profile for external-facing zones
set network profiles zone-protection-profile external-protection flood tcp-syn enable yes
set network profiles zone-protection-profile external-protection flood tcp-syn alert-rate 10000
set network profiles zone-protection-profile external-protection flood tcp-syn activate-rate 10000
set network profiles zone-protection-profile external-protection flood tcp-syn maximal-rate 40000

set network profiles zone-protection-profile external-protection flood udp enable yes
set network profiles zone-protection-profile external-protection flood udp alert-rate 10000
set network profiles zone-protection-profile external-protection flood udp activate-rate 10000
set network profiles zone-protection-profile external-protection flood udp maximal-rate 40000

set network profiles zone-protection-profile external-protection flood icmp enable yes
set network profiles zone-protection-profile external-protection flood icmp alert-rate 1000
set network profiles zone-protection-profile external-protection flood icmp activate-rate 1000
set network profiles zone-protection-profile external-protection flood icmp maximal-rate 5000

# Enable reconnaissance protection
set network profiles zone-protection-profile external-protection scan tcp-port enable yes
set network profiles zone-protection-profile external-protection scan tcp-port action block-ip
set network profiles zone-protection-profile external-protection scan tcp-port interval 10
set network profiles zone-protection-profile external-protection scan tcp-port threshold 100

set network profiles zone-protection-profile external-protection scan udp-port enable yes
set network profiles zone-protection-profile external-protection scan udp-port action block-ip

set network profiles zone-protection-profile external-protection scan host-sweep enable yes
set network profiles zone-protection-profile external-protection scan host-sweep action block-ip

# Packet-based attack protection
set network profiles zone-protection-profile external-protection packet-based-attack-protection zone spoofed-ip-address drop yes
set network profiles zone-protection-profile external-protection packet-based-attack-protection zone ip malformed-packet drop yes
set network profiles zone-protection-profile external-protection packet-based-attack-protection zone tcp-reject-non-syn yes

#=============================================================================
# STEP 3: APPLY ZONE PROTECTION TO ZONES
#=============================================================================

# Apply to untrust zone (external facing)
set zone untrust network zone-protection-profile external-protection

# Apply to public zone
set zone public network zone-protection-profile external-protection

#=============================================================================
# STEP 4: CONFIGURE INTERFACE MANAGEMENT PROFILES
#=============================================================================

# Create restrictive management profile for internal interfaces
set network profiles interface-management-profile internal-mgmt ping yes
set network profiles interface-management-profile internal-mgmt ssh yes
set network profiles interface-management-profile internal-mgmt https yes
set network profiles interface-management-profile internal-mgmt permitted-ip 172.20.242.0/24

# Create profile with NO management access for external interfaces
set network profiles interface-management-profile no-mgmt ping no
set network profiles interface-management-profile no-mgmt ssh no
set network profiles interface-management-profile no-mgmt https no
set network profiles interface-management-profile no-mgmt http no
set network profiles interface-management-profile no-mgmt telnet no
set network profiles interface-management-profile no-mgmt snmp no

# Apply management profiles to interfaces
set network interface ethernet ethernet1/1 layer3 interface-management-profile internal-mgmt
set network interface ethernet ethernet1/4 layer3 interface-management-profile no-mgmt

#=============================================================================
# STEP 5: ENABLE ZONE LOG SETTINGS
#=============================================================================

# Enable logging for zone (helps with forensics)
set zone untrust log-setting default
set zone public log-setting default
set zone user log-setting default
set zone internal log-setting default

#=============================================================================
# STEP 6: CONFIGURE ANTI-SPOOFING
#=============================================================================

# Enable strict IP checking on interfaces (prevents IP spoofing)
# This ensures traffic entering an interface has a valid source for that zone

# The zone protection profile above includes spoofed-ip-address drop

#=============================================================================
# STEP 7: INTERFACE-SPECIFIC HARDENING
#=============================================================================

# Disable unused interfaces
# set network interface ethernet ethernet1/5 comment "DISABLED"
# set network interface ethernet ethernet1/5 link-state down

# Verify interface status
show interface all

#=============================================================================
# STEP 8: CONFIGURE DHCP/DNS SETTINGS IF APPLICABLE
#=============================================================================

# If firewall provides DNS proxy, ensure it points to internal DNS
set network dns-proxy <proxy-name> interface ethernet1/2
set network dns-proxy <proxy-name> primary 172.20.240.x
set network dns-proxy <proxy-name> secondary 8.8.8.8

#=============================================================================
# STEP 9: COMMIT AND VERIFY
#=============================================================================

# Validate
validate full

# Commit
commit

# Verify (operational mode)
exit

# Check zone protection
show zone-protection zone untrust

# Check interfaces
show interface all

# Monitor for attacks
show counter global filter category zone-protection

ZONE_COMMANDS

echo ""
echo "============================================"
echo "ZONE HARDENING CHECKLIST"
echo "============================================"
echo ""
echo "[ ] Create zone protection profile with:"
echo "    - SYN flood protection"
echo "    - UDP flood protection"
echo "    - ICMP flood protection"
echo "    - Port scan detection"
echo "    - Host sweep detection"
echo "    - Spoofed IP protection"
echo "[ ] Apply zone protection to untrust and public zones"
echo "[ ] Configure management profiles"
echo "[ ] Disable management on external interfaces"
echo "[ ] Enable zone logging"
echo "[ ] Disable unused interfaces"
echo "[ ] Commit and verify"
echo ""
