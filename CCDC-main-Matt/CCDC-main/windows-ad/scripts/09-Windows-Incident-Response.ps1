<#
.SYNOPSIS
    CCDC Windows Incident Response Script
.DESCRIPTION
    Quick response actions for security incidents
.NOTES
    Target: Windows Server 2019 (AD/DNS/DHCP)
    Run as: Domain Administrator
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"
Import-Module ActiveDirectory

function Show-Menu {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  CCDC Windows Incident Response" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  1) Disable AD User Account"
    Write-Host "  2) Reset AD User Password"
    Write-Host "  3) Remove User from Domain Admins"
    Write-Host "  4) Kill User Sessions"
    Write-Host "  5) Block IP in Firewall"
    Write-Host "  6) Check for Suspicious Processes"
    Write-Host "  7) Check for Persistence (Tasks/Services)"
    Write-Host "  8) Export Security Events"
    Write-Host "  9) Check Active Connections"
    Write-Host " 10) Disable Suspicious Scheduled Task"
    Write-Host " 11) Quick System State Capture"
    Write-Host "  0) Exit"
    Write-Host ""
}

function Disable-SuspiciousUser {
    $username = Read-Host "Enter username to disable"
    if ($username) {
        try {
            Disable-ADAccount -Identity $username
            Write-Host "[+] Disabled AD account: $username" -ForegroundColor Green

            # Also expire password
            Set-ADUser -Identity $username -ChangePasswordAtLogon $true
            Write-Host "[+] Password change required for: $username" -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed to disable account: $_" -ForegroundColor Red
        }
    }
}

function Reset-UserPassword {
    $username = Read-Host "Enter username"
    if ($username) {
        $newPass = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 16 | ForEach-Object {[char]$_})
        try {
            $securePass = ConvertTo-SecureString $newPass -AsPlainText -Force
            Set-ADAccountPassword -Identity $username -NewPassword $securePass -Reset
            Set-ADUser -Identity $username -ChangePasswordAtLogon $false
            Write-Host "[+] Password reset for: $username" -ForegroundColor Green
            Write-Host "    New password: $newPass" -ForegroundColor Yellow
        } catch {
            Write-Host "[-] Failed to reset password: $_" -ForegroundColor Red
        }
    }
}

function Remove-FromDomainAdmins {
    Write-Host "Current Domain Admins:" -ForegroundColor Yellow
    Get-ADGroupMember -Identity "Domain Admins" | Format-Table Name, SamAccountName

    $username = Read-Host "Enter username to remove from Domain Admins"
    if ($username) {
        try {
            Remove-ADGroupMember -Identity "Domain Admins" -Members $username -Confirm:$false
            Write-Host "[+] Removed $username from Domain Admins" -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed to remove user: $_" -ForegroundColor Red
        }
    }
}

function Kill-UserSessions {
    $username = Read-Host "Enter username to kill sessions for"
    if ($username) {
        Write-Host "[*] Finding sessions for $username..." -ForegroundColor Yellow

        # Query logged on sessions
        $sessions = query user 2>$null | Select-String $username
        if ($sessions) {
            Write-Host "Found sessions:" -ForegroundColor Cyan
            $sessions

            $confirm = Read-Host "Kill all sessions? (y/N)"
            if ($confirm -eq "y") {
                query user 2>$null | Select-String $username | ForEach-Object {
                    $sessionId = ($_ -split '\s+')[2]
                    if ($sessionId -match '^\d+$') {
                        logoff $sessionId /server:localhost
                        Write-Host "[+] Logged off session: $sessionId" -ForegroundColor Green
                    }
                }
            }
        } else {
            Write-Host "No interactive sessions found for $username" -ForegroundColor Gray
        }

        # Also clear Kerberos tickets
        Write-Host "[*] To clear Kerberos tickets, run 'klist purge' in user's session" -ForegroundColor Yellow
    }
}

function Block-IPAddress {
    $ip = Read-Host "Enter IP address to block"
    if ($ip) {
        try {
            # Block inbound
            New-NetFirewallRule -DisplayName "CCDC-Block-$ip" `
                -Direction Inbound -Action Block `
                -RemoteAddress $ip `
                -Profile Any -Enabled True

            # Block outbound
            New-NetFirewallRule -DisplayName "CCDC-Block-Out-$ip" `
                -Direction Outbound -Action Block `
                -RemoteAddress $ip `
                -Profile Any -Enabled True

            Write-Host "[+] Blocked IP: $ip (inbound and outbound)" -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed to block IP: $_" -ForegroundColor Red
        }
    }
}

function Check-SuspiciousProcesses {
    Write-Host "`n[*] Checking for suspicious processes..." -ForegroundColor Yellow

    $suspiciousNames = @(
        'nc', 'ncat', 'netcat', 'mimikatz', 'procdump',
        'psexec', 'wce', 'fgdump', 'pwdump', 'gsecdump',
        'lazagne', 'rubeus', 'sharphound', 'bloodhound'
    )

    $processes = Get-Process
    $found = $false

    foreach ($proc in $processes) {
        foreach ($name in $suspiciousNames) {
            if ($proc.Name -like "*$name*" -or $proc.Path -like "*$name*") {
                Write-Host "[!] Suspicious: $($proc.Name) (PID: $($proc.Id))" -ForegroundColor Red
                Write-Host "    Path: $($proc.Path)"
                $found = $true
            }
        }
    }

    # Check for unusual parents
    Write-Host "`n[*] PowerShell processes:" -ForegroundColor Yellow
    Get-Process -Name powershell*, pwsh* 2>$null | ForEach-Object {
        Write-Host "  PID: $($_.Id) | User: $(($_ | Get-Process -IncludeUserName).UserName)" -ForegroundColor Cyan
    }

    # Check for processes with network connections
    Write-Host "`n[*] Processes with established connections:" -ForegroundColor Yellow
    Get-NetTCPConnection -State Established | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        if ($proc -and $_.RemoteAddress -notmatch '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)') {
            Write-Host "  $($proc.Name) -> $($_.RemoteAddress):$($_.RemotePort)" -ForegroundColor Yellow
        }
    }

    if (!$found) {
        Write-Host "[+] No obviously suspicious processes found" -ForegroundColor Green
    }

    $kill = Read-Host "`nEnter PID to kill (or press Enter to skip)"
    if ($kill -match '^\d+$') {
        Stop-Process -Id $kill -Force
        Write-Host "[+] Killed process: $kill" -ForegroundColor Green
    }
}

function Check-Persistence {
    Write-Host "`n[*] Checking persistence mechanisms..." -ForegroundColor Yellow

    # Scheduled Tasks
    Write-Host "`nScheduled Tasks (non-Microsoft):" -ForegroundColor Cyan
    Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"} | ForEach-Object {
        $task = $_
        $action = ($task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue)
        Write-Host "  $($task.TaskName) - $($task.State)" -ForegroundColor Yellow
        Write-Host "    Path: $($task.TaskPath)"
    }

    # Services
    Write-Host "`nNon-standard services:" -ForegroundColor Cyan
    Get-Service | Where-Object {
        $_.Status -eq 'Running' -and
        $_.DisplayName -notlike "Windows*" -and
        $_.DisplayName -notlike "Microsoft*"
    } | Format-Table Name, DisplayName, Status -AutoSize

    # Run keys
    Write-Host "`nRun registry keys:" -ForegroundColor Cyan
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            Write-Host "  $key" -ForegroundColor Gray
            Get-ItemProperty $key 2>$null | ForEach-Object {
                $_.PSObject.Properties | Where-Object {$_.Name -notlike "PS*"} | ForEach-Object {
                    Write-Host "    $($_.Name): $($_.Value)" -ForegroundColor Yellow
                }
            }
        }
    }

    # WMI subscriptions
    Write-Host "`nWMI Event Subscriptions:" -ForegroundColor Cyan
    Get-WMIObject -Namespace root\Subscription -Class __EventFilter 2>$null | ForEach-Object {
        Write-Host "  [!] Filter: $($_.Name)" -ForegroundColor Red
    }
}

function Export-SecurityEvents {
    $hours = Read-Host "Export events from last how many hours? (default: 24)"
    if (!$hours) { $hours = 24 }

    $exportPath = "C:\CCDC-Logs\SecurityEvents_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

    Write-Host "[*] Exporting security events..." -ForegroundColor Yellow

    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        StartTime = (Get-Date).AddHours(-$hours)
    } -MaxEvents 10000 | Select-Object TimeCreated, Id, LevelDisplayName, Message |
        Export-Csv $exportPath -NoTypeInformation

    Write-Host "[+] Exported to: $exportPath" -ForegroundColor Green
}

function Check-ActiveConnections {
    Write-Host "`n[*] Active Network Connections:" -ForegroundColor Yellow

    Write-Host "`nEstablished connections:" -ForegroundColor Cyan
    Get-NetTCPConnection -State Established | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalPort = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort = $_.RemotePort
            Process = $proc.Name
            PID = $_.OwningProcess
        }
    } | Format-Table -AutoSize

    Write-Host "`nListening ports:" -ForegroundColor Cyan
    Get-NetTCPConnection -State Listen | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalPort = $_.LocalPort
            Process = $proc.Name
            PID = $_.OwningProcess
        }
    } | Sort-Object LocalPort | Format-Table -AutoSize
}

function Disable-ScheduledTask {
    Write-Host "`nScheduled Tasks:" -ForegroundColor Cyan
    Get-ScheduledTask | Where-Object {$_.State -eq 'Ready' -and $_.TaskPath -notlike "\Microsoft\*"} |
        Format-Table TaskName, TaskPath, State

    $taskName = Read-Host "Enter task name to disable"
    if ($taskName) {
        try {
            Disable-ScheduledTask -TaskName $taskName
            Write-Host "[+] Disabled task: $taskName" -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed to disable task: $_" -ForegroundColor Red
        }
    }
}

function Capture-SystemState {
    $capturePath = "C:\CCDC-Logs\Capture_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -ItemType Directory -Force -Path $capturePath | Out-Null

    Write-Host "[*] Capturing system state to $capturePath..." -ForegroundColor Yellow

    # Processes
    Get-Process | Export-Csv "$capturePath\processes.csv" -NoTypeInformation
    Write-Host "    [+] Processes" -ForegroundColor Green

    # Network connections
    Get-NetTCPConnection | Export-Csv "$capturePath\connections.csv" -NoTypeInformation
    Write-Host "    [+] Network connections" -ForegroundColor Green

    # Scheduled tasks
    Get-ScheduledTask | Export-Csv "$capturePath\tasks.csv" -NoTypeInformation
    Write-Host "    [+] Scheduled tasks" -ForegroundColor Green

    # Services
    Get-Service | Export-Csv "$capturePath\services.csv" -NoTypeInformation
    Write-Host "    [+] Services" -ForegroundColor Green

    # Local users
    Get-LocalUser | Export-Csv "$capturePath\localusers.csv" -NoTypeInformation
    Write-Host "    [+] Local users" -ForegroundColor Green

    # Logged on users
    query user 2>$null | Out-File "$capturePath\loggedon.txt"
    Write-Host "    [+] Logged on users" -ForegroundColor Green

    # Recent security events
    Get-WinEvent -LogName Security -MaxEvents 500 | Export-Csv "$capturePath\security_events.csv" -NoTypeInformation
    Write-Host "    [+] Security events" -ForegroundColor Green

    Write-Host "`n[+] Capture complete: $capturePath" -ForegroundColor Green
}

# Main loop
while ($true) {
    Show-Menu
    $choice = Read-Host "Select action"

    switch ($choice) {
        "1" { Disable-SuspiciousUser }
        "2" { Reset-UserPassword }
        "3" { Remove-FromDomainAdmins }
        "4" { Kill-UserSessions }
        "5" { Block-IPAddress }
        "6" { Check-SuspiciousProcesses }
        "7" { Check-Persistence }
        "8" { Export-SecurityEvents }
        "9" { Check-ActiveConnections }
        "10" { Disable-ScheduledTask }
        "11" { Capture-SystemState }
        "0" { exit }
        default { Write-Host "Invalid option" -ForegroundColor Red }
    }

    Read-Host "`nPress Enter to continue"
}
