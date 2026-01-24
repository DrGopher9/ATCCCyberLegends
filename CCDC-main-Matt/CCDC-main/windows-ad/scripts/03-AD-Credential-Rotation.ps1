<#
.SYNOPSIS
    CCDC AD Credential Rotation Script
.DESCRIPTION
    Changes passwords for privileged accounts systematically
.NOTES
    Target: Windows Server 2019 (AD/DNS/DHCP)
    Run as: Domain Administrator
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"
Import-Module ActiveDirectory

$CredentialFile = "C:\CCDC-Logs\CREDENTIALS_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
New-Item -ItemType Directory -Force -Path "C:\CCDC-Logs" | Out-Null

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CCDC AD Credential Rotation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Credentials will be saved to: $CredentialFile" -ForegroundColor Yellow
Write-Host ""

# Initialize credential file
@"
============================================
CCDC CREDENTIAL ROTATION - $(Get-Date)
Server: $env:COMPUTERNAME
Domain: $env:USERDNSDOMAIN
============================================
KEEP THIS FILE SECURE - DELETE AFTER RECORDING

"@ | Out-File $CredentialFile

function Generate-SecurePassword {
    param([int]$Length = 16)
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%"
    $password = ""
    $random = New-Object System.Random
    for ($i = 0; $i -lt $Length; $i++) {
        $password += $chars[$random.Next(0, $chars.Length)]
    }
    return $password
}

function Change-ADUserPassword {
    param(
        [string]$Username,
        [string]$NewPassword
    )

    try {
        $securePassword = ConvertTo-SecureString $NewPassword -AsPlainText -Force
        Set-ADAccountPassword -Identity $Username -NewPassword $securePassword -Reset
        Set-ADUser -Identity $Username -ChangePasswordAtLogon $false
        return $true
    } catch {
        Write-Host "[-] Failed to change password for $Username : $_" -ForegroundColor Red
        return $false
    }
}

#region Domain Administrator Password
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  DOMAIN ADMINISTRATOR" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$response = Read-Host "Change Administrator password? (y/N)"
if ($response -eq "y") {
    $newPass = Generate-SecurePassword
    if (Change-ADUserPassword -Username "Administrator" -NewPassword $newPass) {
        Write-Host "[+] Administrator password changed" -ForegroundColor Green

        # Save to credential file
        @"
DOMAIN ADMINISTRATOR
Username: Administrator
Password: $newPass

"@ | Out-File $CredentialFile -Append
    }
}
#endregion

#region Domain Admins Members
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  DOMAIN ADMINS MEMBERS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Where-Object { $_.objectClass -eq "user" -and $_.SamAccountName -ne "Administrator" }

if ($domainAdmins) {
    Write-Host "Domain Admin accounts found:" -ForegroundColor Yellow
    $domainAdmins | ForEach-Object { Write-Host "  - $($_.SamAccountName)" }
    Write-Host ""

    foreach ($admin in $domainAdmins) {
        $response = Read-Host "Change password for '$($admin.SamAccountName)'? (y/N/skip-all)"

        if ($response -eq "skip-all") { break }

        if ($response -eq "y") {
            $newPass = Generate-SecurePassword
            if (Change-ADUserPassword -Username $admin.SamAccountName -NewPassword $newPass) {
                Write-Host "[+] $($admin.SamAccountName) password changed" -ForegroundColor Green

                @"
DOMAIN ADMIN: $($admin.SamAccountName)
Username: $($admin.SamAccountName)
Password: $newPass

"@ | Out-File $CredentialFile -Append
            }
        }
    }
} else {
    Write-Host "No additional Domain Admins found." -ForegroundColor Gray
}
#endregion

#region Service Accounts
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SERVICE ACCOUNTS (with SPNs)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$serviceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, Description

if ($serviceAccounts) {
    Write-Host "Service accounts with SPNs (Kerberoastable):" -ForegroundColor Yellow
    $serviceAccounts | ForEach-Object {
        Write-Host "  - $($_.SamAccountName): $($_.ServicePrincipalName -join ', ')"
    }
    Write-Host ""
    Write-Host "[!] WARNING: Changing service account passwords may break services!" -ForegroundColor Red
    Write-Host "[!] Verify service dependencies before changing!" -ForegroundColor Red
    Write-Host ""

    foreach ($svc in $serviceAccounts) {
        $response = Read-Host "Change password for service account '$($svc.SamAccountName)'? (y/N/skip-all)"

        if ($response -eq "skip-all") { break }

        if ($response -eq "y") {
            $newPass = Generate-SecurePassword
            if (Change-ADUserPassword -Username $svc.SamAccountName -NewPassword $newPass) {
                Write-Host "[+] $($svc.SamAccountName) password changed" -ForegroundColor Green
                Write-Host "[!] Update service configurations with new password!" -ForegroundColor Yellow

                @"
SERVICE ACCOUNT: $($svc.SamAccountName)
Username: $($svc.SamAccountName)
Password: $newPass
SPNs: $($svc.ServicePrincipalName -join ', ')
NOTE: Update service configurations!

"@ | Out-File $CredentialFile -Append
            }
        }
    }
} else {
    Write-Host "No service accounts with SPNs found." -ForegroundColor Gray
}
#endregion

#region Local Administrator
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  LOCAL ADMINISTRATOR" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$response = Read-Host "Change local Administrator password? (y/N)"
if ($response -eq "y") {
    $newPass = Generate-SecurePassword
    try {
        $securePassword = ConvertTo-SecureString $newPass -AsPlainText -Force
        Set-LocalUser -Name "Administrator" -Password $securePassword
        Write-Host "[+] Local Administrator password changed" -ForegroundColor Green

        @"
LOCAL ADMINISTRATOR (on $env:COMPUTERNAME)
Username: .\Administrator
Password: $newPass

"@ | Out-File $CredentialFile -Append
    } catch {
        Write-Host "[-] Failed to change local Administrator password: $_" -ForegroundColor Red
    }
}
#endregion

#region DSRM Password
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  DSRM PASSWORD (Directory Services Restore Mode)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[!] DSRM password is used for AD recovery. Consider changing it." -ForegroundColor Yellow
$response = Read-Host "Change DSRM password? (y/N)"
if ($response -eq "y") {
    $newPass = Generate-SecurePassword

    # Create a file with the password for ntdsutil
    $dsrmScript = @"
set dsrm password
reset password on server null
$newPass
$newPass
quit
quit
"@

    Write-Host "[*] To change DSRM password, run:" -ForegroundColor Yellow
    Write-Host "    ntdsutil" -ForegroundColor Gray
    Write-Host "    set dsrm password" -ForegroundColor Gray
    Write-Host "    reset password on server null" -ForegroundColor Gray
    Write-Host "    <enter password>" -ForegroundColor Gray
    Write-Host ""
    Write-Host "New DSRM Password: $newPass" -ForegroundColor Green

    @"
DSRM PASSWORD (Directory Services Restore Mode)
Password: $newPass
NOTE: Change manually using ntdsutil if not auto-set

"@ | Out-File $CredentialFile -Append
}
#endregion

#region krbtgt Password
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  KRBTGT PASSWORD (Golden Ticket Mitigation)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[!] Changing krbtgt invalidates all Kerberos tickets!" -ForegroundColor Yellow
Write-Host "[!] All users will need to re-authenticate." -ForegroundColor Yellow
Write-Host "[!] Must be changed TWICE with 10+ hour gap for full effect." -ForegroundColor Yellow
Write-Host ""

$response = Read-Host "Reset krbtgt password? (y/N)"
if ($response -eq "y") {
    try {
        $newPass = Generate-SecurePassword -Length 32
        $securePassword = ConvertTo-SecureString $newPass -AsPlainText -Force
        Set-ADAccountPassword -Identity "krbtgt" -NewPassword $securePassword -Reset
        Write-Host "[+] krbtgt password reset (1st time)" -ForegroundColor Green
        Write-Host "[!] Reset again in 10+ hours for Golden Ticket mitigation" -ForegroundColor Yellow

        @"
KRBTGT PASSWORD RESET
Time: $(Get-Date)
NOTE: Reset again in 10+ hours for full Golden Ticket mitigation
Password: [Not recorded - auto-generated]

"@ | Out-File $CredentialFile -Append
    } catch {
        Write-Host "[-] Failed to reset krbtgt: $_" -ForegroundColor Red
    }
}
#endregion

# Set credential file permissions
$acl = Get-Acl $CredentialFile
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")
$acl.SetAccessRule($rule)
Set-Acl $CredentialFile $acl

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Credential Rotation Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Credentials saved to: $CredentialFile" -ForegroundColor Yellow
Write-Host ""
Write-Host "IMPORTANT:" -ForegroundColor Red
Write-Host "  1. Record credentials securely"
Write-Host "  2. Delete $CredentialFile after recording"
Write-Host "  3. Update service configurations if service accounts changed"
Write-Host "  4. Test authentication with new credentials"
Write-Host ""
