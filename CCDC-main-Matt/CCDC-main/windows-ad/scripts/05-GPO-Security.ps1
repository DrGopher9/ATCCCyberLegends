<#
.SYNOPSIS
    CCDC GPO Security Configuration Script
.DESCRIPTION
    Creates and configures security-focused Group Policy Objects
.NOTES
    Target: Windows Server 2019 (AD/DNS/DHCP)
    Run as: Domain Administrator
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory
Import-Module GroupPolicy

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CCDC GPO Security Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$domain = (Get-ADDomain).DNSRoot
$domainDN = (Get-ADDomain).DistinguishedName

#region Audit Existing GPOs
Write-Host "[*] Current GPOs in domain:" -ForegroundColor Yellow
Get-GPO -All | Format-Table DisplayName, GpoStatus, ModificationTime -AutoSize
Write-Host ""

$response = Read-Host "Review GPOs before creating new ones? (y/N)"
if ($response -eq "y") {
    Get-GPO -All | ForEach-Object {
        Write-Host "`n=== $($_.DisplayName) ===" -ForegroundColor Cyan
        Get-GPOReport -Name $_.DisplayName -ReportType Xml |
            Select-String -Pattern "<q\d+:Name>|<q\d+:State>" |
            ForEach-Object { $_.Line.Trim() }
    }
}
#endregion

#region Create CCDC Security GPO
Write-Host "`n[*] Creating CCDC Security GPO..." -ForegroundColor Yellow

$gpoName = "CCDC-Security-Baseline"
$existingGPO = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue

if ($existingGPO) {
    Write-Host "[!] GPO '$gpoName' already exists" -ForegroundColor Yellow
    $response = Read-Host "Delete and recreate? (y/N)"
    if ($response -eq "y") {
        Remove-GPO -Name $gpoName
        $existingGPO = $null
    }
}

if (!$existingGPO) {
    $gpo = New-GPO -Name $gpoName -Comment "CCDC Security Baseline GPO"
    Write-Host "[+] Created GPO: $gpoName" -ForegroundColor Green

    # Link to domain
    New-GPLink -Name $gpoName -Target $domainDN -LinkEnabled Yes -ErrorAction SilentlyContinue
    Write-Host "[+] Linked to domain root" -ForegroundColor Green
}
#endregion

#region Configure Password Policy via GPO
Write-Host "`n[*] Configuring Password Policy..." -ForegroundColor Yellow
Write-Host "    (Applied via Default Domain Policy)" -ForegroundColor Gray

$response = Read-Host "Update password policy in Default Domain Policy? (y/N)"
if ($response -eq "y") {
    try {
        # These settings go in Default Domain Policy
        Set-ADDefaultDomainPasswordPolicy -Identity $domain `
            -MinPasswordLength 12 `
            -PasswordHistoryCount 24 `
            -MaxPasswordAge "90.00:00:00" `
            -MinPasswordAge "1.00:00:00" `
            -ComplexityEnabled $true `
            -ReversibleEncryptionEnabled $false

        Write-Host "[+] Password policy updated:" -ForegroundColor Green
        Write-Host "    - Minimum length: 12"
        Write-Host "    - History: 24 passwords"
        Write-Host "    - Max age: 90 days"
        Write-Host "    - Complexity: Required"
    } catch {
        Write-Host "[-] Failed to update password policy: $_" -ForegroundColor Red
    }
}
#endregion

#region Configure Account Lockout
Write-Host "`n[*] Configuring Account Lockout Policy..." -ForegroundColor Yellow

$response = Read-Host "Configure account lockout? (y/N)"
if ($response -eq "y") {
    try {
        Set-ADDefaultDomainPasswordPolicy -Identity $domain `
            -LockoutDuration "00:30:00" `
            -LockoutObservationWindow "00:30:00" `
            -LockoutThreshold 5

        Write-Host "[+] Account lockout configured:" -ForegroundColor Green
        Write-Host "    - Threshold: 5 bad attempts"
        Write-Host "    - Duration: 30 minutes"
        Write-Host "    - Observation window: 30 minutes"
    } catch {
        Write-Host "[-] Failed to configure lockout: $_" -ForegroundColor Red
    }
}
#endregion

#region Create Security Settings Script
Write-Host "`n[*] Creating GPO configuration script..." -ForegroundColor Yellow

# Since some settings require LGPO or direct registry/secedit manipulation,
# we'll create a helper script
$gpoScript = @'

# Run these commands on a DC to apply additional GPO settings
# Some settings require secedit or direct registry modification

# ============================================
# User Rights Assignment (via secedit)
# ============================================

# Export current security settings
secedit /export /cfg C:\CCDC-Logs\secpol_backup.cfg

# Key settings to verify/modify in security policy:
# - SeInteractiveLogonRight (Log on locally)
# - SeRemoteInteractiveLogonRight (RDP access)
# - SeNetworkLogonRight (Access from network)
# - SeDenyNetworkLogonRight (Deny network access)
# - SeDebugPrivilege (should be Administrators only)

# ============================================
# Additional Security Registry Settings
# ============================================

# Disable anonymous SID enumeration
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f

# Disable remote registry enumeration
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg" /v RemoteAccessDescription /t REG_SZ /d "" /f

# Clear virtual memory pagefile at shutdown
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f

# Require Ctrl+Alt+Del for logon
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCAD /t REG_DWORD /d 0 /f

# Don't display last username
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DontDisplayLastUserName /t REG_DWORD /d 1 /f

# Disable autorun
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f

# ============================================
# Windows Defender Settings
# ============================================

# Enable real-time protection
Set-MpPreference -DisableRealtimeMonitoring $false

# Enable cloud-delivered protection
Set-MpPreference -MAPSReporting Advanced

# Enable automatic sample submission
Set-MpPreference -SubmitSamplesConsent SendAllSamples

# Enable PUA protection
Set-MpPreference -PUAProtection Enabled

# ============================================
# Apply settings
# ============================================
gpupdate /force

'@

$gpoScript | Out-File "C:\CCDC-Logs\Apply-GPO-Settings.ps1"
Write-Host "[+] Additional GPO settings script saved to: C:\CCDC-Logs\Apply-GPO-Settings.ps1" -ForegroundColor Green
#endregion

#region Restricted Groups GPO
Write-Host "`n[*] Configuring Restricted Groups..." -ForegroundColor Yellow
Write-Host "    (Controls local Administrator group membership)" -ForegroundColor Gray

$response = Read-Host "Configure Restricted Groups GPO? (y/N)"
if ($response -eq "y") {
    $restrictedGpoName = "CCDC-Restricted-Groups"

    try {
        $restrictedGpo = New-GPO -Name $restrictedGpoName -Comment "CCDC Restricted Groups"

        # Note: Restricted Groups requires GPO Preferences or LGPO tool
        # This creates the GPO but settings must be configured via GUI or LGPO

        Write-Host "[+] Created GPO: $restrictedGpoName" -ForegroundColor Green
        Write-Host "[!] Configure via GPMC:" -ForegroundColor Yellow
        Write-Host "    Computer Config > Policies > Windows Settings > Security Settings > Restricted Groups"
        Write-Host "    Add 'Administrators' group and specify members"
    } catch {
        Write-Host "[-] Failed to create Restricted Groups GPO: $_" -ForegroundColor Red
    }
}
#endregion

#region AppLocker GPO
Write-Host "`n[*] AppLocker Configuration..." -ForegroundColor Yellow
Write-Host "    (Application whitelisting)" -ForegroundColor Gray

$response = Read-Host "Create AppLocker GPO? (y/N)"
if ($response -eq "y") {
    $applockerGpoName = "CCDC-AppLocker"

    try {
        $applockerGpo = New-GPO -Name $applockerGpoName -Comment "CCDC AppLocker Policy"

        Write-Host "[+] Created GPO: $applockerGpoName" -ForegroundColor Green
        Write-Host "[!] Configure via GPMC:" -ForegroundColor Yellow
        Write-Host "    Computer Config > Policies > Windows Settings > Security Settings > Application Control Policies"
        Write-Host ""
        Write-Host "    Default Rules (recommended):" -ForegroundColor Cyan
        Write-Host "    - Allow Administrators to run all executables"
        Write-Host "    - Allow users to run executables from Windows folder"
        Write-Host "    - Allow users to run executables from Program Files"
    } catch {
        Write-Host "[-] Failed to create AppLocker GPO: $_" -ForegroundColor Red
    }
}
#endregion

#region Force GPO Update
Write-Host "`n[*] Forcing Group Policy update..." -ForegroundColor Yellow
Invoke-GPUpdate -Force
Write-Host "[+] Group Policy update triggered" -ForegroundColor Green
#endregion

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  GPO Configuration Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Created/Modified GPOs:" -ForegroundColor Yellow
Get-GPO -All | Where-Object {$_.DisplayName -like "CCDC*"} |
    Format-Table DisplayName, CreationTime -AutoSize
Write-Host ""
Write-Host "NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Review GPOs in GPMC (gpmc.msc)"
Write-Host "  2. Run C:\CCDC-Logs\Apply-GPO-Settings.ps1"
Write-Host "  3. Configure Restricted Groups in GPMC"
Write-Host "  4. Configure AppLocker rules if needed"
Write-Host "  5. Run 'gpupdate /force' on all machines"
Write-Host ""
