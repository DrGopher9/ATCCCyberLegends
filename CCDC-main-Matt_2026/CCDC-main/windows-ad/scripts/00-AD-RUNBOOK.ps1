<#
.SYNOPSIS
    CCDC Windows AD Server - First 15 Minutes Runbook
.DESCRIPTION
    Master runbook for hardening Windows AD/DNS/DHCP server
.NOTES
    Target: Windows Server 2019 (AD/DNS/DHCP)
    Network: 172.20.242.x (User zone)
#>

Write-Host @"

================================================================================
  CCDC WINDOWS AD SERVER - FIRST 15 MINUTES RUNBOOK
================================================================================

  Server Roles: Active Directory, DNS, DHCP
  Network: User Zone (172.20.242.x)

================================================================================
  SCRIPT EXECUTION ORDER
================================================================================

  PHASE 1: RECONNAISSANCE (Minute 0-2)
  ------------------------------------
  .\00-AD-Recon.ps1

  - Reviews all AD users and groups
  - Lists Domain Admins
  - Shows scheduled tasks and services
  - Checks DNS and DHCP configuration
  - Output: C:\CCDC-Logs\AD_Recon_*.txt


  PHASE 2: BACKUP (Minute 2-4) - CRITICAL!
  ----------------------------------------
  .\01-AD-Backup.ps1

  - Exports AD users, groups, OUs
  - Backs up GPOs
  - Backs up DNS zones
  - Backs up DHCP configuration
  - Output: C:\CCDC-Backups\


  PHASE 3: USER AUDIT (Minute 4-6)
  --------------------------------
  .\02-AD-User-Audit.ps1

  - Identifies suspicious users
  - Lists privileged accounts
  - Finds stale accounts
  - Option to disable/remove users


  PHASE 4: CREDENTIAL ROTATION (Minute 6-10) - CRITICAL!
  ------------------------------------------------------
  .\03-AD-Credential-Rotation.ps1

  - Changes Administrator password
  - Changes Domain Admin passwords
  - Handles service accounts
  - Options for krbtgt reset
  - Output: C:\CCDC-Logs\CREDENTIALS_*.txt


  PHASE 5: AD HARDENING (Minute 10-12)
  ------------------------------------
  .\04-AD-Hardening.ps1

  - Disables LLMNR, NetBIOS, WPAD
  - Enables SMB signing
  - Disables SMBv1
  - Configures NTLM restrictions
  - Enables audit policy
  - Enables Windows Firewall


  PHASE 6: GPO SECURITY (Minute 12-14)
  ------------------------------------
  .\05-GPO-Security.ps1

  - Creates security GPO
  - Configures password policy
  - Sets account lockout
  - Output: Apply-GPO-Settings.ps1


  PHASE 7: DNS/DHCP HARDENING (Minute 14-16)
  ------------------------------------------
  .\06-DNS-Hardening.ps1
  .\07-DHCP-Hardening.ps1

  - Secures DNS zone transfers
  - Configures DNS forwarders
  - Enables DNS logging
  - Secures DHCP options
  - Enables DHCP audit logging


  PHASE 8: LOGGING (Minute 16-18)
  -------------------------------
  .\08-Windows-Logging.ps1

  - Enables advanced audit policy
  - Increases event log sizes
  - Enables PowerShell logging
  - Creates monitoring scripts


  INCIDENT RESPONSE (As Needed)
  -----------------------------
  .\09-Windows-Incident-Response.ps1

  - Disable accounts
  - Reset passwords
  - Block IPs
  - Kill sessions
  - Check persistence

================================================================================
  QUICK REFERENCE COMMANDS
================================================================================

  # Check Domain Admins
  Get-ADGroupMember -Identity "Domain Admins"

  # Disable user
  Disable-ADAccount -Identity <username>

  # Reset password
  Set-ADAccountPassword -Identity <username> -Reset

  # Check logged on users
  query user

  # Force GPO update
  gpupdate /force

  # Check security log
  Get-WinEvent -LogName Security -MaxEvents 50

================================================================================
  CRITICAL REMINDERS
================================================================================

  [!] BACKUP before making changes
  [!] Change Administrator password FIRST
  [!] Remove unknown users from Domain Admins
  [!] Keep a session open while testing changes
  [!] Document all credential changes
  [!] Test AD services after hardening

================================================================================

"@

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "Scripts available in: $scriptDir" -ForegroundColor Yellow
Write-Host ""

$response = Read-Host "Run scripts in guided mode? (y/N)"
if ($response -eq "y") {
    Write-Host "`n[*] Starting guided execution..." -ForegroundColor Cyan

    # Phase 1
    Write-Host "`n=== PHASE 1: RECONNAISSANCE ===" -ForegroundColor Yellow
    $run = Read-Host "Run 00-AD-Recon.ps1? (Y/n)"
    if ($run -ne "n") {
        & "$scriptDir\00-AD-Recon.ps1"
    }

    # Phase 2
    Write-Host "`n=== PHASE 2: BACKUP ===" -ForegroundColor Yellow
    $run = Read-Host "Run 01-AD-Backup.ps1? (Y/n)"
    if ($run -ne "n") {
        & "$scriptDir\01-AD-Backup.ps1"
    }

    # Phase 3
    Write-Host "`n=== PHASE 3: USER AUDIT ===" -ForegroundColor Yellow
    $run = Read-Host "Run 02-AD-User-Audit.ps1? (Y/n)"
    if ($run -ne "n") {
        & "$scriptDir\02-AD-User-Audit.ps1"
    }

    # Phase 4
    Write-Host "`n=== PHASE 4: CREDENTIAL ROTATION ===" -ForegroundColor Yellow
    $run = Read-Host "Run 03-AD-Credential-Rotation.ps1? (Y/n)"
    if ($run -ne "n") {
        & "$scriptDir\03-AD-Credential-Rotation.ps1"
    }

    # Phase 5
    Write-Host "`n=== PHASE 5: AD HARDENING ===" -ForegroundColor Yellow
    $run = Read-Host "Run 04-AD-Hardening.ps1? (Y/n)"
    if ($run -ne "n") {
        & "$scriptDir\04-AD-Hardening.ps1"
    }

    # Phase 6
    Write-Host "`n=== PHASE 6: GPO SECURITY ===" -ForegroundColor Yellow
    $run = Read-Host "Run 05-GPO-Security.ps1? (Y/n)"
    if ($run -ne "n") {
        & "$scriptDir\05-GPO-Security.ps1"
    }

    # Phase 7
    Write-Host "`n=== PHASE 7: DNS/DHCP HARDENING ===" -ForegroundColor Yellow
    $run = Read-Host "Run 06-DNS-Hardening.ps1? (Y/n)"
    if ($run -ne "n") {
        & "$scriptDir\06-DNS-Hardening.ps1"
    }
    $run = Read-Host "Run 07-DHCP-Hardening.ps1? (Y/n)"
    if ($run -ne "n") {
        & "$scriptDir\07-DHCP-Hardening.ps1"
    }

    # Phase 8
    Write-Host "`n=== PHASE 8: LOGGING ===" -ForegroundColor Yellow
    $run = Read-Host "Run 08-Windows-Logging.ps1? (Y/n)"
    if ($run -ne "n") {
        & "$scriptDir\08-Windows-Logging.ps1"
    }

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "  Guided Execution Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Verify AD authentication works"
    Write-Host "  2. Test DNS resolution"
    Write-Host "  3. Verify DHCP leases"
    Write-Host "  4. Run gpupdate /force on clients"
    Write-Host "  5. Monitor C:\CCDC-Logs for alerts"
    Write-Host ""
}
