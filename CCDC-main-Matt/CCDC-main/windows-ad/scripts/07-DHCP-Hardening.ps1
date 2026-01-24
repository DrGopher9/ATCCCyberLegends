<#
.SYNOPSIS
    CCDC DHCP Server Hardening Script
.DESCRIPTION
    Hardens Windows DHCP Server configuration
.NOTES
    Target: Windows Server 2019 with DHCP role
    Run as: Domain Administrator
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"
Import-Module DhcpServer

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CCDC DHCP Server Hardening" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

#region Current Configuration
Write-Host "[*] Current DHCP Configuration:" -ForegroundColor Yellow
Write-Host ""

Write-Host "DHCP Scopes:" -ForegroundColor Cyan
Get-DhcpServerv4Scope | Format-Table ScopeId, Name, State, StartRange, EndRange, SubnetMask -AutoSize

Write-Host "`nScope Options:" -ForegroundColor Cyan
Get-DhcpServerv4Scope | ForEach-Object {
    Write-Host "  Scope: $($_.ScopeId)" -ForegroundColor Gray
    Get-DhcpServerv4OptionValue -ScopeId $_.ScopeId | Format-Table OptionId, Name, Value -AutoSize
}

Write-Host "Server Options:" -ForegroundColor Cyan
Get-DhcpServerv4OptionValue | Format-Table OptionId, Name, Value -AutoSize

Write-Host "`nActive Leases:" -ForegroundColor Cyan
$totalLeases = 0
Get-DhcpServerv4Scope | ForEach-Object {
    $leases = Get-DhcpServerv4Lease -ScopeId $_.ScopeId
    $totalLeases += $leases.Count
    Write-Host "  Scope $($_.ScopeId): $($leases.Count) leases"
}
Write-Host "  Total: $totalLeases leases"
#endregion

#region Audit DHCP Administrators
Write-Host "`n[*] DHCP Administrators:" -ForegroundColor Yellow
try {
    Get-DhcpServerSecurityGroup | Format-Table Name, MemberCount
} catch {
    Write-Host "  Could not enumerate DHCP security groups" -ForegroundColor Gray
}
#endregion

#region Enable DHCP Audit Logging
Write-Host "`n[*] Enabling DHCP audit logging..." -ForegroundColor Yellow
try {
    $logPath = "C:\CCDC-Logs\DHCP"
    New-Item -ItemType Directory -Force -Path $logPath | Out-Null

    Set-DhcpServerAuditLog -Enable $true -Path $logPath

    Write-Host "    [+] DHCP audit logging enabled: $logPath" -ForegroundColor Green
} catch {
    Write-Host "    [-] Failed to enable audit logging: $_" -ForegroundColor Red
}
#endregion

#region Review Scope Settings
Write-Host "`n[*] Reviewing scope security settings..." -ForegroundColor Yellow

Get-DhcpServerv4Scope | ForEach-Object {
    $scope = $_
    Write-Host "`n  Scope: $($scope.ScopeId) ($($scope.Name))" -ForegroundColor Cyan

    # Check lease duration
    if ($scope.LeaseDuration.TotalDays -gt 7) {
        Write-Host "    [!] Lease duration > 7 days ($($scope.LeaseDuration.TotalDays) days)" -ForegroundColor Yellow
    } else {
        Write-Host "    [+] Lease duration: $($scope.LeaseDuration)" -ForegroundColor Green
    }

    # Check for reservations
    $reservations = Get-DhcpServerv4Reservation -ScopeId $scope.ScopeId
    Write-Host "    Reservations: $($reservations.Count)"

    # Check exclusion ranges
    $exclusions = Get-DhcpServerv4ExclusionRange -ScopeId $scope.ScopeId
    Write-Host "    Exclusion ranges: $($exclusions.Count)"
}
#endregion

#region Shorten Lease Duration
Write-Host "`n[*] Lease duration configuration..." -ForegroundColor Yellow
Write-Host "    Shorter leases = faster detection of rogue devices"
Write-Host ""

$response = Read-Host "Set lease duration to 1 day for all scopes? (y/N)"
if ($response -eq "y") {
    Get-DhcpServerv4Scope | ForEach-Object {
        try {
            Set-DhcpServerv4Scope -ScopeId $_.ScopeId -LeaseDuration "1.00:00:00"
            Write-Host "    [+] Lease set to 1 day: $($_.ScopeId)" -ForegroundColor Green
        } catch {
            Write-Host "    [-] Failed for scope $($_.ScopeId): $_" -ForegroundColor Red
        }
    }
}
#endregion

#region MAC Address Filtering
Write-Host "`n[*] MAC Address Filtering..." -ForegroundColor Yellow
Write-Host "    You can create filters to allow/deny specific MAC addresses"
Write-Host ""

# Show existing filters
$filters = Get-DhcpServerv4Filter
if ($filters) {
    Write-Host "  Existing filters:" -ForegroundColor Cyan
    $filters | Format-Table MacAddress, List, Description
} else {
    Write-Host "  No MAC filters configured" -ForegroundColor Gray
}

$response = Read-Host "Enable MAC filtering? (y/N) [Careful - can block legitimate devices]"
if ($response -eq "y") {
    try {
        Set-DhcpServerv4FilterList -Allow $true -Deny $true
        Write-Host "    [+] MAC filtering enabled (Allow and Deny lists active)" -ForegroundColor Green
        Write-Host "    [!] Add allowed MACs: Add-DhcpServerv4Filter -MacAddress <MAC> -List Allow" -ForegroundColor Yellow
    } catch {
        Write-Host "    [-] Failed to enable MAC filtering: $_" -ForegroundColor Red
    }
}
#endregion

#region Review DHCP Options
Write-Host "`n[*] Reviewing DHCP options for suspicious entries..." -ForegroundColor Yellow

# Check DNS servers option
$dnsOption = Get-DhcpServerv4OptionValue -OptionId 6 -ErrorAction SilentlyContinue
if ($dnsOption) {
    Write-Host "  DNS Servers (Option 6): $($dnsOption.Value -join ', ')" -ForegroundColor Cyan
}

# Check router/gateway option
$routerOption = Get-DhcpServerv4OptionValue -OptionId 3 -ErrorAction SilentlyContinue
if ($routerOption) {
    Write-Host "  Router (Option 3): $($routerOption.Value -join ', ')" -ForegroundColor Cyan
}

# Check for WPAD option (can be used for attacks)
$wpadOption = Get-DhcpServerv4OptionValue -OptionId 252 -ErrorAction SilentlyContinue
if ($wpadOption) {
    Write-Host "  [!] WPAD (Option 252) is set: $($wpadOption.Value)" -ForegroundColor Yellow
    $response = Read-Host "Remove WPAD option? (y/N)"
    if ($response -eq "y") {
        Remove-DhcpServerv4OptionValue -OptionId 252
        Write-Host "    [+] WPAD option removed" -ForegroundColor Green
    }
}

# Check for suspicious options
$suspiciousOptions = @(66, 67, 150, 252)  # TFTP, bootfile, etc.
foreach ($optId in $suspiciousOptions) {
    $opt = Get-DhcpServerv4OptionValue -OptionId $optId -ErrorAction SilentlyContinue
    if ($opt) {
        Write-Host "  [!] Option $optId is set - verify this is needed" -ForegroundColor Yellow
    }
}
#endregion

#region Conflict Detection
Write-Host "`n[*] Configuring conflict detection..." -ForegroundColor Yellow
try {
    Set-DhcpServerSetting -ConflictDetectionAttempts 2
    Write-Host "    [+] Conflict detection set to 2 attempts" -ForegroundColor Green
} catch {
    Write-Host "    [-] Failed to configure conflict detection: $_" -ForegroundColor Red
}
#endregion

#region DNS Dynamic Update
Write-Host "`n[*] Configuring DNS dynamic update settings..." -ForegroundColor Yellow
try {
    Set-DhcpServerv4DnsSetting -DynamicUpdates Always -DeleteDnsRRonLeaseExpiry $true
    Write-Host "    [+] DNS updates: Always, cleanup on expiry" -ForegroundColor Green
} catch {
    Write-Host "    [-] Failed to configure DNS settings: $_" -ForegroundColor Red
}
#endregion

#region Check for Rogue DHCP
Write-Host "`n[*] Checking for rogue DHCP servers..." -ForegroundColor Yellow
Write-Host "    (Manual check - run from a client PC)" -ForegroundColor Gray
Write-Host ""
Write-Host "    On a client, run:" -ForegroundColor Cyan
Write-Host '    $results = @()'
Write-Host '    1..5 | ForEach-Object {'
Write-Host '        ipconfig /release | Out-Null'
Write-Host '        Start-Sleep 1'
Write-Host '        ipconfig /renew | Out-Null'
Write-Host '        $results += (ipconfig /all | Select-String "DHCP Server")'
Write-Host '    }'
Write-Host '    $results | Sort-Object -Unique'
Write-Host ""
Write-Host "    Multiple different DHCP servers = potential rogue" -ForegroundColor Yellow
#endregion

#region Export Lease List
Write-Host "`n[*] Exporting current lease list..." -ForegroundColor Yellow
try {
    $exportPath = "C:\CCDC-Logs\DHCP_Leases_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

    Get-DhcpServerv4Scope | ForEach-Object {
        Get-DhcpServerv4Lease -ScopeId $_.ScopeId
    } | Export-Csv $exportPath -NoTypeInformation

    Write-Host "    [+] Leases exported to: $exportPath" -ForegroundColor Green
} catch {
    Write-Host "    [-] Failed to export leases: $_" -ForegroundColor Red
}
#endregion

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  DHCP Hardening Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Applied Hardening:" -ForegroundColor Yellow
Write-Host "  [+] Audit logging enabled"
Write-Host "  [+] Conflict detection configured"
Write-Host "  [+] DNS dynamic updates configured"
Write-Host ""
Write-Host "MONITORING COMMANDS:" -ForegroundColor Cyan
Write-Host "  Get-DhcpServerv4Lease -ScopeId <scope>  # View leases"
Write-Host "  Get-DhcpServerv4Statistics             # View statistics"
Write-Host '  Get-EventLog -LogName "DhcpSrvLog"     # View DHCP events'
Write-Host ""
