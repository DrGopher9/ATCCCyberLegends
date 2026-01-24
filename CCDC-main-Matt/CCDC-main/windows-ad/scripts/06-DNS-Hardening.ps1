<#
.SYNOPSIS
    CCDC DNS Server Hardening Script
.DESCRIPTION
    Hardens Windows DNS Server configuration
.NOTES
    Target: Windows Server 2019 with DNS role
    Run as: Domain Administrator
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"
Import-Module DnsServer

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CCDC DNS Server Hardening" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

#region Current Configuration
Write-Host "[*] Current DNS Configuration:" -ForegroundColor Yellow
Write-Host ""

Write-Host "DNS Zones:" -ForegroundColor Cyan
Get-DnsServerZone | Format-Table ZoneName, ZoneType, IsDsIntegrated, DynamicUpdate -AutoSize

Write-Host "Forwarders:" -ForegroundColor Cyan
$forwarders = Get-DnsServerForwarder
$forwarders.IPAddress | ForEach-Object { Write-Host "  $_" }

Write-Host "`nRecursion:" -ForegroundColor Cyan
$recursion = Get-DnsServerRecursion
Write-Host "  Enabled: $($recursion.Enable)"
Write-Host "  Timeout: $($recursion.Timeout)"
#endregion

#region Secure Zone Transfers
Write-Host "`n[*] Securing zone transfers..." -ForegroundColor Yellow

Get-DnsServerZone | Where-Object {$_.ZoneType -eq 'Primary'} | ForEach-Object {
    $zone = $_

    # Disable zone transfer to any server
    Set-DnsServerPrimaryZone -Name $zone.ZoneName -SecureSecondaries NoTransfer

    Write-Host "    [+] Zone transfers disabled for: $($zone.ZoneName)" -ForegroundColor Green
}
#endregion

#region Secure Dynamic Updates
Write-Host "`n[*] Securing dynamic updates..." -ForegroundColor Yellow

Get-DnsServerZone | Where-Object {$_.ZoneType -eq 'Primary' -and $_.IsDsIntegrated -eq $true} | ForEach-Object {
    $zone = $_

    # Set to Secure Only (requires AD authentication)
    Set-DnsServerPrimaryZone -Name $zone.ZoneName -DynamicUpdate Secure

    Write-Host "    [+] Secure dynamic updates for: $($zone.ZoneName)" -ForegroundColor Green
}
#endregion

#region Configure Forwarders
Write-Host "`n[*] Configuring DNS forwarders..." -ForegroundColor Yellow
Write-Host "    Current forwarders: $($forwarders.IPAddress -join ', ')"
Write-Host ""
Write-Host "    Recommended public DNS servers:" -ForegroundColor Cyan
Write-Host "      - 8.8.8.8 (Google)"
Write-Host "      - 8.8.4.4 (Google)"
Write-Host "      - 1.1.1.1 (Cloudflare)"
Write-Host "      - 9.9.9.9 (Quad9 - blocks malware)"
Write-Host ""

$response = Read-Host "Update forwarders to use secure DNS? (y/N)"
if ($response -eq "y") {
    try {
        # Remove existing forwarders
        Set-DnsServerForwarder -IPAddress @()

        # Add secure forwarders (Quad9 blocks known malware domains)
        Add-DnsServerForwarder -IPAddress "9.9.9.9"
        Add-DnsServerForwarder -IPAddress "1.1.1.1"
        Add-DnsServerForwarder -IPAddress "8.8.8.8"

        Write-Host "    [+] Forwarders updated: 9.9.9.9, 1.1.1.1, 8.8.8.8" -ForegroundColor Green
    } catch {
        Write-Host "    [-] Failed to update forwarders: $_" -ForegroundColor Red
    }
}
#endregion

#region Disable Recursion (if not needed)
Write-Host "`n[*] DNS Recursion configuration..." -ForegroundColor Yellow
Write-Host "    Recursion allows the server to query other DNS servers"
Write-Host "    Disable if this is an internal-only DNS server"
Write-Host ""

$response = Read-Host "Disable recursion? (y/N) [Keep enabled if internet resolution needed]"
if ($response -eq "y") {
    try {
        Set-DnsServerRecursion -Enable $false
        Write-Host "    [+] Recursion disabled" -ForegroundColor Green
    } catch {
        Write-Host "    [-] Failed to disable recursion: $_" -ForegroundColor Red
    }
} else {
    # At least secure recursion
    Set-DnsServerRecursion -SecureResponse $true
    Write-Host "    [+] Secure response enabled for recursion" -ForegroundColor Green
}
#endregion

#region Socket Pool
Write-Host "`n[*] Configuring socket pool (DNS cache poisoning protection)..." -ForegroundColor Yellow
try {
    # Larger socket pool makes cache poisoning harder
    dnscmd /config /socketpoolsize 10000
    Write-Host "    [+] Socket pool size set to 10000" -ForegroundColor Green
} catch {
    Write-Host "    [-] Failed to set socket pool: $_" -ForegroundColor Red
}
#endregion

#region Cache Locking
Write-Host "`n[*] Enabling cache locking..." -ForegroundColor Yellow
try {
    # Prevents cache records from being overwritten
    Set-DnsServerCache -LockingPercent 100
    Write-Host "    [+] Cache locking set to 100%" -ForegroundColor Green
} catch {
    Write-Host "    [-] Failed to enable cache locking: $_" -ForegroundColor Red
}
#endregion

#region Root Hints Security
Write-Host "`n[*] Verifying root hints..." -ForegroundColor Yellow
try {
    $rootHints = Get-DnsServerRootHint
    Write-Host "    Root hint servers: $($rootHints.Count)"

    # Verify root hints are valid (should be the standard root servers)
    $validRoots = @("a.root-servers.net", "b.root-servers.net", "c.root-servers.net")
    $hasValid = $rootHints | Where-Object {$validRoots -contains $_.NameServer.RecordData.NameServer}

    if ($hasValid.Count -gt 0) {
        Write-Host "    [+] Root hints appear valid" -ForegroundColor Green
    } else {
        Write-Host "    [!] Root hints may be modified - verify manually" -ForegroundColor Yellow
    }
} catch {
    Write-Host "    [-] Could not verify root hints" -ForegroundColor Yellow
}
#endregion

#region DNS Logging
Write-Host "`n[*] Configuring DNS logging..." -ForegroundColor Yellow

$response = Read-Host "Enable enhanced DNS logging? (y/N)"
if ($response -eq "y") {
    try {
        # Enable DNS debug logging
        $logPath = "C:\CCDC-Logs\DNS"
        New-Item -ItemType Directory -Force -Path $logPath | Out-Null

        Set-DnsServerDiagnostics -All $true
        Set-DnsServerDiagnostics -LogFilePath "$logPath\dns.log" -MaxMBFileSize 500

        Write-Host "    [+] DNS logging enabled: $logPath\dns.log" -ForegroundColor Green
    } catch {
        Write-Host "    [-] Failed to configure DNS logging: $_" -ForegroundColor Red
    }
}
#endregion

#region DNS Scavenging
Write-Host "`n[*] Configuring DNS scavenging..." -ForegroundColor Yellow
Write-Host "    (Removes stale DNS records automatically)"

$response = Read-Host "Enable DNS scavenging? (y/N)"
if ($response -eq "y") {
    try {
        # Enable scavenging on server
        Set-DnsServerScavenging -ScavengingState $true -RefreshInterval 7.00:00:00 -NoRefreshInterval 7.00:00:00

        # Enable aging on zones
        Get-DnsServerZone | Where-Object {$_.IsDsIntegrated -eq $true} | ForEach-Object {
            Set-DnsServerZoneAging -Name $_.ZoneName -Aging $true -RefreshInterval 7.00:00:00 -NoRefreshInterval 7.00:00:00
            Write-Host "    [+] Aging enabled for: $($_.ZoneName)" -ForegroundColor Green
        }
    } catch {
        Write-Host "    [-] Failed to configure scavenging: $_" -ForegroundColor Red
    }
}
#endregion

#region Check for Suspicious Records
Write-Host "`n[*] Checking for suspicious DNS records..." -ForegroundColor Yellow

Get-DnsServerZone | Where-Object {$_.ZoneType -eq 'Primary'} | ForEach-Object {
    $zone = $_
    Write-Host "    Checking zone: $($zone.ZoneName)" -ForegroundColor Gray

    # Look for suspicious record types
    $suspiciousTypes = @('TXT', 'NULL', 'HINFO')
    foreach ($type in $suspiciousTypes) {
        $records = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -RRType $type -ErrorAction SilentlyContinue
        if ($records) {
            Write-Host "    [!] Found $($records.Count) $type records - review for data exfiltration" -ForegroundColor Yellow
        }
    }

    # Look for records with very short TTLs (possible C2)
    $shortTTL = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName |
        Where-Object {$_.TimeToLive.TotalSeconds -lt 60}
    if ($shortTTL) {
        Write-Host "    [!] Found $($shortTTL.Count) records with TTL < 60s" -ForegroundColor Yellow
    }
}
#endregion

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  DNS Hardening Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Applied Hardening:" -ForegroundColor Yellow
Write-Host "  [+] Zone transfers restricted"
Write-Host "  [+] Secure dynamic updates"
Write-Host "  [+] Socket pool increased"
Write-Host "  [+] Cache locking enabled"
Write-Host ""
Write-Host "VERIFICATION:" -ForegroundColor Cyan
Write-Host "  nslookup <hostname>"
Write-Host "  Resolve-DnsName -Name <hostname> -Server localhost"
Write-Host ""
