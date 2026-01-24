<#
.SYNOPSIS
    CCDC Windows Logging and Monitoring Script
.DESCRIPTION
    Configures enhanced logging and creates monitoring tools
.NOTES
    Target: Windows Server 2019 (AD/DNS/DHCP)
    Run as: Domain Administrator
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"
$LogPath = "C:\CCDC-Logs"
New-Item -ItemType Directory -Force -Path $LogPath | Out-Null

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CCDC Windows Logging Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

#region Enable Advanced Audit Policy
Write-Host "[*] Configuring Advanced Audit Policy..." -ForegroundColor Yellow

# Account Logon
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

# Account Management
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

# Logon/Logoff
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable

# Object Access
auditpol /set /subcategory:"File System" /failure:enable
auditpol /set /subcategory:"Registry" /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:enable

# Policy Change
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable

# Privilege Use
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

# System
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

Write-Host "[+] Advanced Audit Policy configured" -ForegroundColor Green

# Export current policy
auditpol /get /category:* > "$LogPath\AuditPolicy.txt"
Write-Host "[+] Audit policy exported to: $LogPath\AuditPolicy.txt" -ForegroundColor Green
#endregion

#region Increase Event Log Sizes
Write-Host "`n[*] Increasing event log sizes..." -ForegroundColor Yellow

$logs = @{
    "Security" = 1GB
    "System" = 256MB
    "Application" = 256MB
    "Microsoft-Windows-PowerShell/Operational" = 256MB
    "Microsoft-Windows-Sysmon/Operational" = 512MB
}

foreach ($log in $logs.GetEnumerator()) {
    try {
        $logName = $log.Key
        $size = $log.Value

        wevtutil sl $logName /ms:$size
        Write-Host "    [+] $logName : $([math]::Round($size/1MB)) MB" -ForegroundColor Green
    } catch {
        Write-Host "    [-] Failed to resize $($log.Key)" -ForegroundColor Yellow
    }
}
#endregion

#region Enable PowerShell Logging
Write-Host "`n[*] Enabling PowerShell logging..." -ForegroundColor Yellow

try {
    # Script Block Logging
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1

    # Module Logging
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "EnableModuleLogging" -Value 1

    # Transcription
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "EnableTranscripting" -Value 1
    Set-ItemProperty -Path $regPath -Name "OutputDirectory" -Value "$LogPath\PowerShell"

    New-Item -ItemType Directory -Force -Path "$LogPath\PowerShell" | Out-Null

    Write-Host "[+] PowerShell logging enabled" -ForegroundColor Green
    Write-Host "    - Script Block Logging"
    Write-Host "    - Module Logging"
    Write-Host "    - Transcription: $LogPath\PowerShell"
} catch {
    Write-Host "[-] Failed to configure PowerShell logging: $_" -ForegroundColor Red
}
#endregion

#region Configure Windows Event Forwarding
Write-Host "`n[*] Windows Event Forwarding info..." -ForegroundColor Yellow
Write-Host "    If you have a SIEM (Splunk), configure WEF or install Splunk Forwarder"
Write-Host "    Splunk Universal Forwarder: https://www.splunk.com/en_us/download/universal-forwarder.html"
Write-Host ""
#endregion

#region Create Monitoring Scripts
Write-Host "[*] Creating monitoring scripts..." -ForegroundColor Yellow

# Failed Logon Monitor
$failedLogonScript = @'
# Monitor-FailedLogons.ps1
# Run this to see failed logon attempts

param([int]$Hours = 24)

$startTime = (Get-Date).AddHours(-$Hours)

Write-Host "Failed Logon Attempts (last $Hours hours)" -ForegroundColor Cyan
Write-Host "=" * 60

Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time = $_.TimeCreated
        TargetUser = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
        SourceIP = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
        FailureReason = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'FailureReason'} | Select-Object -ExpandProperty '#text'
    }
} | Format-Table -AutoSize

# Summary by IP
Write-Host "`nTop Source IPs:" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
} | Group-Object | Sort-Object Count -Descending | Select-Object -First 10 | Format-Table Count, Name
'@

$failedLogonScript | Out-File "$LogPath\Monitor-FailedLogons.ps1"
Write-Host "    [+] Monitor-FailedLogons.ps1" -ForegroundColor Green

# Admin Activity Monitor
$adminActivityScript = @'
# Monitor-AdminActivity.ps1
# Monitor privileged account usage

param([int]$Hours = 24)

$startTime = (Get-Date).AddHours(-$Hours)

Write-Host "Privileged Account Activity (last $Hours hours)" -ForegroundColor Cyan
Write-Host "=" * 60

# Special Logon (Event 4672)
Write-Host "`nSpecial Logon Events (Admin tokens):" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4672
    StartTime = $startTime
} -MaxEvents 50 -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time = $_.TimeCreated
        User = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'} | Select-Object -ExpandProperty '#text'
    }
} | Format-Table -AutoSize

# User Account Changes (Event 4720, 4722, 4725, 4726, 4732)
Write-Host "`nUser Account Changes:" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4720,4722,4725,4726,4732,4728
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    [PSCustomObject]@{
        Time = $_.TimeCreated
        EventId = $_.Id
        Message = $_.Message.Split("`n")[0]
    }
} | Format-Table -AutoSize
'@

$adminActivityScript | Out-File "$LogPath\Monitor-AdminActivity.ps1"
Write-Host "    [+] Monitor-AdminActivity.ps1" -ForegroundColor Green

# Process Creation Monitor
$processScript = @'

# Monitor-Processes.ps1
# Monitor suspicious process creation

param([int]$Hours = 1)

$startTime = (Get-Date).AddHours(-$Hours)

# Suspicious process patterns
$suspiciousPatterns = @(
    'powershell.*-enc',
    'powershell.*downloadstring',
    'powershell.*iex',
    'cmd.*/c.*powershell',
    'certutil.*-urlcache',
    'bitsadmin.*transfer',
    'mshta.*http',
    'regsvr32.*/s.*/u',
    'rundll32.*javascript',
    'wmic.*process.*call',
    'net.*user.*add',
    'net.*localgroup.*administrators'
)

Write-Host "Suspicious Process Activity (last $Hours hours)" -ForegroundColor Cyan
Write-Host "=" * 60

Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
    StartTime = $startTime
} -ErrorAction SilentlyContinue | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $commandLine = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'CommandLine'} | Select-Object -ExpandProperty '#text'

    foreach ($pattern in $suspiciousPatterns) {
        if ($commandLine -match $pattern) {
            [PSCustomObject]@{
                Time = $_.TimeCreated
                User = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'SubjectUserName'} | Select-Object -ExpandProperty '#text'
                Process = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'NewProcessName'} | Select-Object -ExpandProperty '#text'
                CommandLine = $commandLine
            }
            break
        }
    }
} | Format-List
'@

$processScript | Out-File "$LogPath\Monitor-Processes.ps1"
Write-Host "    [+] Monitor-Processes.ps1" -ForegroundColor Green

# Quick Threat Check
$threatCheckScript = @'
# Quick-ThreatCheck.ps1
# Quick security health check

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CCDC Quick Threat Check" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Failed logons in last hour
$failedLogons = (Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue).Count
if ($failedLogons -gt 10) {
    Write-Host "[!] $failedLogons failed logons in last hour" -ForegroundColor Red
} else {
    Write-Host "[+] $failedLogons failed logons in last hour" -ForegroundColor Green
}

# New user accounts today
$newUsers = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720;StartTime=(Get-Date).Date} -ErrorAction SilentlyContinue
if ($newUsers) {
    Write-Host "[!] $($newUsers.Count) new user accounts created today" -ForegroundColor Yellow
} else {
    Write-Host "[+] No new user accounts today" -ForegroundColor Green
}

# Domain Admin changes
$daChanges = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4728,4732;StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue
if ($daChanges) {
    Write-Host "[!] $($daChanges.Count) admin group changes in 24h" -ForegroundColor Red
} else {
    Write-Host "[+] No admin group changes in 24h" -ForegroundColor Green
}

# Scheduled tasks created today
$newTasks = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational';Id=106;StartTime=(Get-Date).Date} -ErrorAction SilentlyContinue
if ($newTasks) {
    Write-Host "[!] $($newTasks.Count) new scheduled tasks today" -ForegroundColor Yellow
} else {
    Write-Host "[+] No new scheduled tasks today" -ForegroundColor Green
}

# Services started today
Write-Host "`nRecent services:" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=(Get-Date).Date} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, @{N='Service';E={$_.Properties[0].Value}} | Format-Table

# Currently logged on users
Write-Host "Logged on users:" -ForegroundColor Cyan
query user 2>$null
'@

$threatCheckScript | Out-File "$LogPath\Quick-ThreatCheck.ps1"
Write-Host "    [+] Quick-ThreatCheck.ps1" -ForegroundColor Green
#endregion

#region Enable Process Creation Logging
Write-Host "`n[*] Enabling process creation command line logging..." -ForegroundColor Yellow
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

    Write-Host "[+] Process command line logging enabled" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to enable command line logging: $_" -ForegroundColor Red
}
#endregion

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Logging Configuration Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Monitoring Scripts Created:" -ForegroundColor Yellow
Write-Host "  $LogPath\Monitor-FailedLogons.ps1"
Write-Host "  $LogPath\Monitor-AdminActivity.ps1"
Write-Host "  $LogPath\Monitor-Processes.ps1"
Write-Host "  $LogPath\Quick-ThreatCheck.ps1"
Write-Host ""
Write-Host "USAGE:" -ForegroundColor Cyan
Write-Host "  .\Quick-ThreatCheck.ps1           # Quick health check"
Write-Host "  .\Monitor-FailedLogons.ps1 -Hours 24"
Write-Host "  .\Monitor-AdminActivity.ps1 -Hours 24"
Write-Host ""
