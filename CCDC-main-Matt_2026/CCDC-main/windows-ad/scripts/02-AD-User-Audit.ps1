<#
.SYNOPSIS
    CCDC AD User Audit and Cleanup Script
.DESCRIPTION
    Audits all AD users, identifies suspicious accounts, and provides cleanup options
.NOTES
    Target: Windows Server 2019 (AD/DNS/DHCP)
    Run as: Domain Administrator
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"
Import-Module ActiveDirectory

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CCDC AD User Audit" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

#region Known Good Users
# Add known competition users here
$KnownGoodUsers = @(
    "Administrator",
    "krbtgt",
    "Guest"
    # Add your known users here
)

$KnownGoodGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Domain Users",
    "Domain Computers"
)
#endregion

#region Audit Functions
function Get-PrivilegedUsers {
    Write-Host "`n[*] Checking privileged users..." -ForegroundColor Yellow

    $privilegedGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "Print Operators"
    )

    $privilegedUsers = @()

    foreach ($group in $privilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -Recursive
            foreach ($member in $members) {
                if ($member.objectClass -eq "user") {
                    $privilegedUsers += [PSCustomObject]@{
                        Username = $member.SamAccountName
                        Name = $member.Name
                        Group = $group
                    }
                }
            }
        } catch {
            # Group doesn't exist
        }
    }

    return $privilegedUsers | Sort-Object Username -Unique
}

function Get-SuspiciousUsers {
    Write-Host "[*] Checking for suspicious users..." -ForegroundColor Yellow

    $suspicious = @()

    # Get all enabled users
    $users = Get-ADUser -Filter {Enabled -eq $true} -Properties *

    foreach ($user in $users) {
        $flags = @()

        # Check for password never expires
        if ($user.PasswordNeverExpires) {
            $flags += "PasswordNeverExpires"
        }

        # Check for password not required
        if ($user.PasswordNotRequired) {
            $flags += "PasswordNotRequired"
        }

        # Check for recent creation (within 7 days)
        if ($user.Created -gt (Get-Date).AddDays(-7)) {
            $flags += "RecentlyCreated"
        }

        # Check for adminCount but not in admin groups
        if ($user.AdminCount -eq 1) {
            $flags += "AdminCount=1"
        }

        # Check for SPN (Kerberoastable)
        if ($user.ServicePrincipalName) {
            $flags += "HasSPN"
        }

        # Check for suspicious names
        $suspiciousNames = @("admin", "test", "temp", "backdoor", "hack", "shell", "system")
        foreach ($name in $suspiciousNames) {
            if ($user.SamAccountName -like "*$name*" -and $user.SamAccountName -ne "Administrator") {
                $flags += "SuspiciousName"
                break
            }
        }

        if ($flags.Count -gt 0) {
            $suspicious += [PSCustomObject]@{
                Username = $user.SamAccountName
                Name = $user.Name
                Created = $user.Created
                LastLogon = $user.LastLogonDate
                Flags = ($flags -join ", ")
            }
        }
    }

    return $suspicious
}

function Get-StaleUsers {
    Write-Host "[*] Checking for stale users..." -ForegroundColor Yellow

    $staleDate = (Get-Date).AddDays(-90)

    Get-ADUser -Filter {Enabled -eq $true -and LastLogonDate -lt $staleDate} -Properties LastLogonDate |
        Select-Object SamAccountName, Name, LastLogonDate |
        Sort-Object LastLogonDate
}
#endregion

#region Display Results
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PRIVILEGED USERS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$privileged = Get-PrivilegedUsers
$privileged | Format-Table -AutoSize

Write-Host ""
Write-Host "========================================" -ForegroundColor Red
Write-Host "  SUSPICIOUS USERS (Review Carefully!)" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red

$suspicious = Get-SuspiciousUsers
if ($suspicious) {
    $suspicious | Format-Table -AutoSize
} else {
    Write-Host "No suspicious users found." -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "  STALE USERS (No login > 90 days)" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow

$stale = Get-StaleUsers
if ($stale) {
    $stale | Format-Table -AutoSize
} else {
    Write-Host "No stale users found." -ForegroundColor Green
}
#endregion

#region Interactive Cleanup
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CLEANUP OPTIONS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Disable suspicious user
$response = Read-Host "Disable a suspicious user? (Enter username or 'skip')"
if ($response -ne "skip" -and $response -ne "") {
    try {
        Disable-ADAccount -Identity $response
        Write-Host "[+] Disabled user: $response" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to disable user: $_" -ForegroundColor Red
    }
}

# Remove user from Domain Admins
$response = Read-Host "Remove user from Domain Admins? (Enter username or 'skip')"
if ($response -ne "skip" -and $response -ne "") {
    try {
        Remove-ADGroupMember -Identity "Domain Admins" -Members $response -Confirm:$false
        Write-Host "[+] Removed $response from Domain Admins" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to remove user: $_" -ForegroundColor Red
    }
}

# Force password change at next logon
$response = Read-Host "Force password change for a user? (Enter username or 'skip')"
if ($response -ne "skip" -and $response -ne "") {
    try {
        Set-ADUser -Identity $response -ChangePasswordAtLogon $true
        Write-Host "[+] $response must change password at next logon" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed: $_" -ForegroundColor Red
    }
}
#endregion

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  User Audit Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "RECOMMENDED ACTIONS:" -ForegroundColor Yellow
Write-Host "  1. Remove unknown users from Domain Admins"
Write-Host "  2. Disable suspicious accounts"
Write-Host "  3. Reset passwords for privileged accounts"
Write-Host "  4. Review service accounts (SPNs)"
Write-Host "  5. Disable stale accounts"
Write-Host ""
