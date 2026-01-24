#!/bin/bash
###############################################################################
# 00-panos-recon.sh - Palo Alto Firewall Reconnaissance
# Target: Palo Alto VM (PAN-OS 11.x)
# Purpose: Gather firewall configuration and state information
#
# USAGE: Run commands via SSH or paste into PAN-OS CLI
# SSH: ssh admin@172.20.242.150
###############################################################################

# This script outputs PAN-OS CLI commands to run on the firewall
# Copy/paste these commands or run via SSH

cat << 'PANOS_COMMANDS'
================================================================================
PALO ALTO FIREWALL RECONNAISSANCE COMMANDS
Run these commands in the PAN-OS CLI (SSH or console)
================================================================================

#=============================================================================
# SYSTEM INFORMATION
#=============================================================================

# Show system info and version
show system info

# Show high availability status
show high-availability state

# Show system resources
show system resources

# Show system disk space
show system disk-space

# Show management interface config
show interface management

# Show licenses
show system license

#=============================================================================
# ADMINISTRATOR ACCOUNTS
#=============================================================================

# Show all administrator accounts
show admins all

# Show current admin sessions
show admins

# Show admin roles
show admin-roles all

#=============================================================================
# NETWORK CONFIGURATION
#=============================================================================

# Show all interfaces
show interface all

# Show interface hardware
show interface hardware

# Show routing table
show routing route

# Show virtual routers
show routing summary

# Show zones
show zone

#=============================================================================
# SECURITY POLICIES
#=============================================================================

# Show security policy rules (running config)
show running security-policy

# Show NAT policies
show running nat-policy

# Show policy hit counts (which rules are being used)
show rule-hit-count vsys vsys1 security

#=============================================================================
# OBJECTS
#=============================================================================

# Show address objects
show object address

# Show service objects
show object service

# Show address groups
show object address-group

#=============================================================================
# CURRENT SESSIONS
#=============================================================================

# Show session summary
show session info

# Show all active sessions (can be large!)
show session all

# Show session count by application
show session meter

#=============================================================================
# THREAT AND LOGGING
#=============================================================================

# Show threat statistics
show threat statistics

# Show security profiles in use
show running security-profile-group

# Show log settings
show logging-status

# Show syslog server config
show log-collector detail

#=============================================================================
# CONFIGURATION STATUS
#=============================================================================

# Show if there are uncommitted changes
show config diff

# Show last commit
show jobs all

#=============================================================================
# QUICK SECURITY CHECKS
#=============================================================================

# Check for overly permissive rules (any-any)
# Look for: source=any, destination=any, application=any, action=allow

# Check management access
show management-server interface

# Check which IPs can access management
show device management

PANOS_COMMANDS

echo ""
echo "============================================"
echo "HOW TO USE THESE COMMANDS"
echo "============================================"
echo ""
echo "1. SSH to the firewall:"
echo "   ssh admin@172.20.242.150"
echo ""
echo "2. Enter operational mode (should be default)"
echo ""
echo "3. Copy and paste commands above"
echo ""
echo "4. Save output for analysis"
echo ""
echo "KEY THINGS TO LOOK FOR:"
echo "- Any 'any-any-allow' rules"
echo "- Unknown admin accounts"
echo "- Open management access"
echo "- Disabled security profiles"
echo "- Misconfigured zones"
