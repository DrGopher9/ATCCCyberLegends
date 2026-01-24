#!/bin/bash
###############################################################################
# 02-panos-admin-harden.sh - Palo Alto Admin Account Hardening
# Target: Palo Alto VM (PAN-OS 11.x)
# Purpose: Secure administrator accounts and access
###############################################################################

cat << 'ADMIN_COMMANDS'
================================================================================
PALO ALTO ADMIN ACCOUNT HARDENING
Run these commands in PAN-OS CLI (configuration mode)
================================================================================

#=============================================================================
# STEP 1: AUDIT CURRENT ADMINS
#=============================================================================

# Show all administrator accounts
show admins all

# Show current logged-in admins
show admins

# Look for:
# - Unknown admin accounts
# - Accounts with superuser role
# - Accounts without authentication profiles

#=============================================================================
# STEP 2: CHANGE DEFAULT ADMIN PASSWORD
#=============================================================================

# Enter configuration mode
configure

# Change admin password (CRITICAL - do this first!)
set mgt-config users admin password

# You'll be prompted for new password
# Use strong password: Mix of upper, lower, numbers, special chars
# Record this password securely!

#=============================================================================
# STEP 3: REMOVE UNAUTHORIZED ADMIN ACCOUNTS
#=============================================================================

# Delete suspicious admin account
delete mgt-config users <suspicious-username>

# Example:
# delete mgt-config users hacker
# delete mgt-config users backdoor

#=============================================================================
# STEP 4: CREATE NEW ADMIN ACCOUNT (Backup Access)
#=============================================================================

# Create a new superuser admin (as backup)
set mgt-config users ccdc-admin password
set mgt-config users ccdc-admin permissions role-based superuser yes

# Create a read-only admin for monitoring
set mgt-config users ccdc-readonly password
set mgt-config users ccdc-readonly permissions role-based superreader yes

#=============================================================================
# STEP 5: CONFIGURE ADMIN LOCKOUT POLICY
#=============================================================================

# Set failed login attempts before lockout
set deviceconfig setting management admin-lockout failed-attempts 5

# Set lockout duration (minutes)
set deviceconfig setting management admin-lockout lockout-time 30

#=============================================================================
# STEP 6: RESTRICT MANAGEMENT ACCESS BY IP
#=============================================================================

# Allow only specific IPs to access management interface
set deviceconfig system permitted-ip <your-management-ip>

# Example - allow only internal management network:
set deviceconfig system permitted-ip 172.20.242.0/24

# CAUTION: Make sure you include YOUR IP or you'll lock yourself out!

#=============================================================================
# STEP 7: CONFIGURE IDLE TIMEOUT
#=============================================================================

# Set admin session idle timeout (minutes)
set deviceconfig setting management idle-timeout 10

#=============================================================================
# STEP 8: DISABLE UNUSED MANAGEMENT SERVICES
#=============================================================================

# Disable HTTP (force HTTPS only)
set deviceconfig system service disable-http yes

# Disable Telnet (force SSH only)
set deviceconfig system service disable-telnet yes

# Disable SNMP if not needed
set deviceconfig system service disable-snmp yes

# Disable HTTP OCSP if not needed
set deviceconfig system service disable-http-ocsp yes

#=============================================================================
# STEP 9: COMMIT CHANGES
#=============================================================================

# Validate configuration
validate full

# Commit changes
commit

# If commit fails, show error details
show jobs all

#=============================================================================
# STEP 10: VERIFY CHANGES
#=============================================================================

# Exit config mode
exit

# Verify admin accounts
show admins all

# Verify management settings
show system setting management

# Test login with new credentials in separate session!

ADMIN_COMMANDS

echo ""
echo "============================================"
echo "ADMIN HARDENING CHECKLIST"
echo "============================================"
echo ""
echo "[ ] Change default admin password"
echo "[ ] Remove unknown admin accounts"
echo "[ ] Create backup admin account"
echo "[ ] Configure lockout policy"
echo "[ ] Restrict management access by IP"
echo "[ ] Set idle timeout"
echo "[ ] Disable HTTP and Telnet"
echo "[ ] Commit changes"
echo "[ ] Test login with new credentials"
echo ""
echo "CRITICAL: Keep current session open while testing new credentials!"
echo ""
echo "CREDENTIAL RECORDING:"
echo "============================================"
echo "Admin Username: admin"
echo "Admin Password: ____________________"
echo ""
echo "Backup Username: ccdc-admin"
echo "Backup Password: ____________________"
echo ""
echo "Management IP: 172.20.242.150"
echo "============================================"
