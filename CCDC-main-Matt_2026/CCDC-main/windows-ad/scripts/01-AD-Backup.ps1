<#
.SYNOPSIS
    CCDC Windows AD Backup Script
.DESCRIPTION
    Creates backup of AD, GPOs, DNS, DHCP before hardening
    Run this BEFORE making any changes!
.NOTES
    Target: Windows Server 2019 (AD/DNS/DHCP)
    Run as: Domain Administrator
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"
$BackupRoot = "C:\CCDC-Backups"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupDir = "$BackupRoot\$Timestamp"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CCDC AD Server Backup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Create backup directories
Write-Host "[*] Creating backup directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path "$BackupDir\AD" | Out-Null
New-Item -ItemType Directory -Force -Path "$BackupDir\GPO" | Out-Null
New-Item -ItemType Directory -Force -Path "$BackupDir\DNS" | Out-Null
New-Item -ItemType Directory -Force -Path "$BackupDir\DHCP" | Out-Null
New-Item -ItemType Directory -Force -Path "$BackupDir\Registry" | Out-Null
New-Item -ItemType Directory -Force -Path "$BackupDir\Users" | Out-Null

Write-Host "[+] Backup directory: $BackupDir" -ForegroundColor Green

# Backup AD Users and Groups
Write-Host "`n[*] Backing up AD Users and Groups..." -ForegroundColor Yellow
try {
    Import-Module ActiveDirectory

    # Export all users
    Get-ADUser -Filter * -Properties * |
        Export-Csv "$BackupDir\AD\AllUsers.csv" -NoTypeInformation

    # Export all groups
    Get-ADGroup -Filter * -Properties * |
        Export-Csv "$BackupDir\AD\AllGroups.csv" -NoTypeInformation

    # Export group memberships
    Get-ADGroup -Filter * | ForEach-Object {
        $group = $_
        Get-ADGroupMember -Identity $group -Recursive 2>$null | ForEach-Object {
            [PSCustomObject]@{
                GroupName = $group.Name
                MemberName = $_.Name
                MemberSamAccountName = $_.SamAccountName
                MemberType = $_.objectClass
            }
        }
    } | Export-Csv "$BackupDir\AD\GroupMemberships.csv" -NoTypeInformation

    # Export OUs
    Get-ADOrganizationalUnit -Filter * -Properties * |
        Export-Csv "$BackupDir\AD\OUs.csv" -NoTypeInformation

    # Export computers
    Get-ADComputer -Filter * -Properties * |
        Export-Csv "$BackupDir\AD\Computers.csv" -NoTypeInformation

    Write-Host "[+] AD objects exported" -ForegroundColor Green
} catch {
    Write-Host "[-] Error backing up AD: $_" -ForegroundColor Red
}

# Backup GPOs
Write-Host "`n[*] Backing up Group Policy Objects..." -ForegroundColor Yellow
try {
    Import-Module GroupPolicy

    # Backup all GPOs
    Get-GPO -All | ForEach-Object {
        $gpo = $_
        try {
            Backup-GPO -Guid $gpo.Id -Path "$BackupDir\GPO" -Comment "CCDC Backup $Timestamp"
            Write-Host "    [+] Backed up: $($gpo.DisplayName)" -ForegroundColor Gray
        } catch {
            Write-Host "    [-] Failed: $($gpo.DisplayName)" -ForegroundColor Red
        }
    }

    # Export GPO list
    Get-GPO -All | Export-Csv "$BackupDir\GPO\GPO_List.csv" -NoTypeInformation

    # Export GPO links
    Get-ADOrganizationalUnit -Filter * | ForEach-Object {
        $ou = $_
        (Get-GPInheritance -Target $ou.DistinguishedName).GpoLinks
    } | Export-Csv "$BackupDir\GPO\GPO_Links.csv" -NoTypeInformation

    Write-Host "[+] GPOs backed up" -ForegroundColor Green
} catch {
    Write-Host "[-] Error backing up GPOs: $_" -ForegroundColor Red
}

# Backup DNS
Write-Host "`n[*] Backing up DNS configuration..." -ForegroundColor Yellow
try {
    Import-Module DnsServer

    # Export DNS zones info
    Get-DnsServerZone | Export-Csv "$BackupDir\DNS\Zones.csv" -NoTypeInformation

    # Export each zone
    Get-DnsServerZone | Where-Object {$_.ZoneType -ne 'Forwarder'} | ForEach-Object {
        $zone = $_
        try {
            Export-DnsServerZone -Name $zone.ZoneName -FileName "$($zone.ZoneName).dns.txt"
            Copy-Item "C:\Windows\System32\dns\$($zone.ZoneName).dns.txt" "$BackupDir\DNS\" -ErrorAction SilentlyContinue
            Write-Host "    [+] Exported zone: $($zone.ZoneName)" -ForegroundColor Gray
        } catch {
            # Alternative: export records
            Get-DnsServerResourceRecord -ZoneName $zone.ZoneName |
                Export-Csv "$BackupDir\DNS\$($zone.ZoneName)_records.csv" -NoTypeInformation
        }
    }

    # Export forwarders
    Get-DnsServerForwarder | Out-File "$BackupDir\DNS\Forwarders.txt"

    Write-Host "[+] DNS backed up" -ForegroundColor Green
} catch {
    Write-Host "[-] DNS backup failed (may not be installed): $_" -ForegroundColor Yellow
}

# Backup DHCP
Write-Host "`n[*] Backing up DHCP configuration..." -ForegroundColor Yellow
try {
    Import-Module DhcpServer

    # Full DHCP backup
    Backup-DhcpServer -Path "$BackupDir\DHCP"

    # Export scopes
    Get-DhcpServerv4Scope | Export-Csv "$BackupDir\DHCP\Scopes.csv" -NoTypeInformation

    # Export leases
    Get-DhcpServerv4Scope | ForEach-Object {
        Get-DhcpServerv4Lease -ScopeId $_.ScopeId
    } | Export-Csv "$BackupDir\DHCP\Leases.csv" -NoTypeInformation

    # Export reservations
    Get-DhcpServerv4Scope | ForEach-Object {
        Get-DhcpServerv4Reservation -ScopeId $_.ScopeId
    } | Export-Csv "$BackupDir\DHCP\Reservations.csv" -NoTypeInformation

    Write-Host "[+] DHCP backed up" -ForegroundColor Green
} catch {
    Write-Host "[-] DHCP backup failed (may not be installed): $_" -ForegroundColor Yellow
}

# Backup Local Users
Write-Host "`n[*] Backing up local user information..." -ForegroundColor Yellow
try {
    Get-LocalUser | Export-Csv "$BackupDir\Users\LocalUsers.csv" -NoTypeInformation
    Get-LocalGroup | Export-Csv "$BackupDir\Users\LocalGroups.csv" -NoTypeInformation
    Get-LocalGroupMember -Group "Administrators" |
        Export-Csv "$BackupDir\Users\LocalAdmins.csv" -NoTypeInformation
    Write-Host "[+] Local users backed up" -ForegroundColor Green
} catch {
    Write-Host "[-] Local user backup failed: $_" -ForegroundColor Red
}

# Backup Registry Keys
Write-Host "`n[*] Backing up critical registry keys..." -ForegroundColor Yellow
try {
    reg export "HKLM\SYSTEM\CurrentControlSet\Services" "$BackupDir\Registry\Services.reg" /y 2>$null
    reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "$BackupDir\Registry\Winlogon.reg" /y 2>$null
    reg export "HKLM\SOFTWARE\Policies" "$BackupDir\Registry\Policies.reg" /y 2>$null
    Write-Host "[+] Registry backed up" -ForegroundColor Green
} catch {
    Write-Host "[-] Registry backup failed: $_" -ForegroundColor Red
}

# Backup Scheduled Tasks
Write-Host "`n[*] Backing up scheduled tasks..." -ForegroundColor Yellow
try {
    Get-ScheduledTask | Export-Csv "$BackupDir\ScheduledTasks.csv" -NoTypeInformation
    Write-Host "[+] Scheduled tasks backed up" -ForegroundColor Green
} catch {
    Write-Host "[-] Scheduled tasks backup failed: $_" -ForegroundColor Red
}

# Create System State backup (if wbadmin available)
Write-Host "`n[*] Creating System State backup..." -ForegroundColor Yellow
Write-Host "    This may take several minutes..." -ForegroundColor Gray
try {
    $wbadminResult = wbadmin start systemstatebackup -backupTarget:$BackupRoot -quiet 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] System State backed up" -ForegroundColor Green
    } else {
        Write-Host "[-] System State backup failed (non-critical)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[-] wbadmin not available" -ForegroundColor Yellow
}

# Create manifest
Write-Host "`n[*] Creating backup manifest..." -ForegroundColor Yellow
$manifest = @"
CCDC Windows AD Server Backup Manifest
======================================
Created: $(Get-Date)
Server: $env:COMPUTERNAME
Domain: $env:USERDNSDOMAIN
Backup Location: $BackupDir

Contents:
---------
AD/             - Active Directory users, groups, OUs, computers
GPO/            - Group Policy Objects
DNS/            - DNS zones and records
DHCP/           - DHCP configuration and leases
Registry/       - Critical registry keys
Users/          - Local user accounts

RESTORE INSTRUCTIONS:
--------------------
1. AD Objects:
   - Users/Groups can be recreated from CSV exports
   - Use ADUC or PowerShell to restore

2. GPOs:
   Import-GPO -BackupId <GUID> -Path "$BackupDir\GPO" -TargetName <GPOName>

3. DNS:
   - Reimport zones from backup files
   - dnscmd /zoneadd <zone> /primary /file <file>

4. DHCP:
   Restore-DhcpServer -Path "$BackupDir\DHCP"

5. System State:
   wbadmin start systemstaterecovery -version:<version>

"@

$manifest | Out-File "$BackupDir\MANIFEST.txt"
Write-Host "[+] Manifest created" -ForegroundColor Green

# Summary
$backupSize = (Get-ChildItem $BackupDir -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Backup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Location: $BackupDir" -ForegroundColor Yellow
Write-Host "Size: $([math]::Round($backupSize, 2)) MB" -ForegroundColor Yellow
Write-Host ""
Write-Host "Contents:" -ForegroundColor Cyan
Get-ChildItem $BackupDir -Directory | ForEach-Object {
    Write-Host "  - $($_.Name)" -ForegroundColor Gray
}
Write-Host ""
Write-Host "IMPORTANT: Verify backup before making changes!" -ForegroundColor Red
