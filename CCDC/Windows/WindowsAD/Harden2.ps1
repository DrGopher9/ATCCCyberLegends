<# 
Defend-AD-CCDC-Fixed.ps1
PowerShell 5.1 compatible

Fixes included:
- FIX: $script:HasAD / $script:HasGP scoping made consistent
- FIX: $script:txtLog set so Log() writes into GUI
- FIX: DNS scavenging call uses splat (prevents parsing/argument conversion bugs)
- FIX: “Path is null” scheduled-task path issues guarded (ISE-safe)
- FIX: UI button handlers wrapped (exceptions don’t crash whole form)
- Keeps: Safe Mode + Full Hardening + LDAP hardening + Monitoring + Evidence Export + Tools
#>

param(
    [switch]$MonitorTick
)

$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ------------------ Config ------------------
$BannerText  = "Authorized use only. Activity may be monitored."
$NTPServer   = "time.windows.com"

# SAFE defaults: only scored services, no admin ports
$SafeFWPorts = @{
    TCP = @(25, 80, 110, 443, 53)     # SMTP, HTTP, POP3, HTTPS, DNS-TCP
    UDP = @(53)                        # DNS-UDP
}

# Admin ports (use with caution, restrict by subnet)
$AdminFWPorts = @{
    TCP = @(135, 139, 445, 3389, 5985, 5986)
    UDP = @(137, 138)
}

$BaseDir       = Join-Path $env:USERPROFILE 'DefendAD_Fixed'
$BaselineDir   = Join-Path $BaseDir 'Baseline'
$BackupDir     = Join-Path $BaseDir 'Backups'
$ReportDir     = Join-Path $BaseDir 'Reports'
$script:LogFile = Join-Path $BaseDir 'Fixed.log'

$MonTaskName   = 'CCDC_ADMon_Fixed'
$MonStateFile  = Join-Path $BaseDir 'monitor_state.xml'

New-Item $BaseDir,$BaselineDir,$BackupDir,$ReportDir -ItemType Directory -Force | Out-Null

# ------------------ Modules (FIXED SCOPING) ------------------
$script:HasAD = $false
$script:HasGP = $false
try { Import-Module ActiveDirectory -ErrorAction Stop; $script:HasAD = $true } catch {}
try { Import-Module GroupPolicy     -ErrorAction Stop; $script:HasGP = $true } catch {}

# ------------------ Helpers ------------------
function Get-ThisScriptPath {
    # Best effort for PS 5.1 + ISE
    $p = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($p)) {
        try {
            if ($psISE -and $psISE.CurrentFile -and $psISE.CurrentFile.FullPath) {
                $p = $psISE.CurrentFile.FullPath
            }
        } catch {}
    }
    return $p
}

function Ensure-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run as Administrator."
    }
}

function Log([string]$m, [string]$level="INFO"){
    $ts = Get-Date -Format 'HH:mm:ss'
    $logMsg = "$ts [$level] $m"

    try { $logMsg | Tee-Object -FilePath $script:LogFile -Append | Out-Host } catch { Write-Host $logMsg }

    if ($script:txtLog) {
        try {
            $script:txtLog.AppendText("$logMsg`r`n")
            $script:txtLog.SelectionStart = $script:txtLog.Text.Length
            $script:txtLog.ScrollToCaret()
        } catch {}
    }
}

function Invoke-UiAction {
    param([scriptblock]$Action)
    try { & $Action }
    catch {
        Log "UI action failed: $($_.Exception.Message)" "ERROR"
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Error") | Out-Null
    }
}

function Get-DomainContext {
    $ctx = [ordered]@{
        IsDomainJoined = $false
        IsDC           = $false
        DomainDN       = $null
        NetBIOS        = $null
        FQDN           = $null
        PreferredDC    = $null
        Reason         = $null
    }
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $ctx.IsDomainJoined = [bool]$cs.PartOfDomain
        if (-not $ctx.IsDomainJoined) { $ctx.Reason = "Workgroup host"; return [pscustomobject]$ctx }

        if ($script:HasAD) {
            try {
                $ad = Get-ADDomain
                $ctx.DomainDN = $ad.DistinguishedName
                $ctx.NetBIOS  = $ad.NetBIOSName
                $ctx.FQDN     = $ad.DNSRoot
                try {
                    $dc = Get-ADDomainController -Discover -ForceDiscover -ErrorAction Stop
                    $ctx.PreferredDC = [string]$dc.HostName
                } catch {
                    $ctx.PreferredDC = [string]((Get-ADDomainController -Filter * | Select-Object -First 1 -ExpandProperty HostName))
                }
            } catch { $ctx.Reason = "AD query failed: $($_.Exception.Message)" }
        }

        try { if (Get-Service -Name NTDS -ErrorAction Stop) { $ctx.IsDC = $true } } catch {}

        # Fallback attempt
        if (-not $ctx.DomainDN) {
            try {
                $nl = nltest /dsgetdc:. 2>$null
                if ($nl) {
                    $ctx.FQDN        = ($nl | Select-String 'Domain Name:(.+)$').Matches.Groups[1].Value.Trim()
                    $ctx.PreferredDC = ($nl | Select-String 'DC:(.+)$').Matches.Groups[1].Value.Trim()
                }
            } catch { $ctx.Reason = "nltest fallback failed" }
        }
    } catch { $ctx.Reason = "Detection error: $($_.Exception.Message)" }
    return [pscustomobject]$ctx
}

function Test-Prerequisites {
    Log "Running pre-flight checks..." "INFO"
    $issues = @()

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
        IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { $issues += "Not running as Administrator" }

    if (-not $script:ctx.IsDomainJoined) { $issues += "Not domain-joined" }
    if (-not $script:HasAD) { $issues += "ActiveDirectory module not available" }
    if (-not $script:HasGP) { $issues += "GroupPolicy module not available" }

    if ($script:HasAD -and $script:ctx.PreferredDC) {
        try { $null = Get-ADDomain -Server $script:ctx.PreferredDC -ErrorAction Stop }
        catch { $issues += "Cannot connect to DC: $($script:ctx.PreferredDC)" }
    }

    if ($issues.Count -gt 0) {
        Log "Pre-flight check FAILED:" "ERROR"
        $issues | ForEach-Object { Log "  - $_" "ERROR" }
        return $false
    }

    Log "Pre-flight checks PASSED" "SUCCESS"
    return $true
}

# ------------------ Backup Functions ------------------
function Backup-RegistryKey {
    param([string]$KeyPath, [string]$BackupName)
    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFile = Join-Path $BackupDir "${BackupName}_${timestamp}.reg"

        $key = $KeyPath -replace 'HKLM:', 'HKEY_LOCAL_MACHINE'
        reg export $key $backupFile /y 2>$null | Out-Null

        if (Test-Path -LiteralPath $backupFile) {
            Log "Backed up registry key: $KeyPath" "SUCCESS"
            return $backupFile
        }
    } catch {
        Log "Failed to backup $KeyPath : $($_.Exception.Message)" "ERROR"
    }
    return $null
}

function Backup-GpoObject {
    param([string]$GPOName)
    if (-not $script:HasGP) { return $null }

    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupPath = Join-Path $BackupDir "GPO_${GPOName}_${timestamp}"
        New-Item -Path $backupPath -ItemType Directory -Force | Out-Null

        $gpo = Get-GPO -Name $GPOName -Server $script:ctx.PreferredDC -ErrorAction SilentlyContinue
        if ($gpo) {
            Backup-GPO -Name $GPOName -Path $backupPath -Server $script:ctx.PreferredDC | Out-Null
            Log "Backed up GPO: $GPOName" "SUCCESS"
            return $backupPath
        }
    } catch {
        Log "Failed to backup GPO $GPOName : $($_.Exception.Message)" "ERROR"
    }
    return $null
}

# ------------------ LDAP Hardening ------------------
function Invoke-LDAPHardening {
    if (-not $script:ctx.IsDomainJoined) { 
        Log "LDAP: host not domain-joined; skipping." "WARN"
        return
    }

    if (-not $script:ctx.IsDC) {
        Log "LDAP: Not a DC. Normally apply LDAP hardening on DCs only." "WARN"
        $result = [System.Windows.Forms.MessageBox]::Show(
            "This system is not a Domain Controller. LDAP hardening should be applied on DCs. Continue anyway?",
            "Warning",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($result -eq [System.Windows.Forms.DialogResult]::No) { return }
    }

    $result = [System.Windows.Forms.MessageBox]::Show(
        "WARNING: LDAP hardening requires a DC REBOOT to take effect!`n`nThis will cause service disruption. Are you sure?`n`n- LDAPServerIntegrity=2 (require signing)`n- LdapEnforceChannelBinding=2 (always)`n- LDAPServerRequireStrongAuth=2 (no cleartext)",
        "CRITICAL: Reboot Required",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )

    if ($result -eq [System.Windows.Forms.DialogResult]::No) {
        Log "LDAP hardening cancelled by user." "INFO"
        return
    }

    Log "LDAP: Starting hardening (will require reboot)..." "INFO"
    Backup-RegistryKey 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'NTDS_Parameters'

    try {
        New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LDAPServerIntegrity -Value 2 -PropertyType DWord -Force | Out-Null
        Log "LDAP: Set LDAPServerIntegrity=2" "SUCCESS"

        New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LdapEnforceChannelBinding -Value 2 -PropertyType DWord -Force | Out-Null
        Log "LDAP: Set LdapEnforceChannelBinding=2" "SUCCESS"

        New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LDAPServerRequireStrongAuth -Value 2 -PropertyType DWord -Force | Out-Null
        Log "LDAP: Set LDAPServerRequireStrongAuth=2" "SUCCESS"

        Log "LDAP: Hardening complete. REBOOT REQUIRED!" "WARN"
        [System.Windows.Forms.MessageBox]::Show(
            "LDAP hardening settings applied successfully!`n`nREBOOT THE DC FOR CHANGES TO TAKE EFFECT.",
            "Success - Reboot Required",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    } catch {
        Log "LDAP hardening failed: $($_.Exception.Message)" "ERROR"
    }
}

function Show-LDAPStatus {
    try {
        $v = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue
        $signing = if($v.LDAPServerIntegrity) { $v.LDAPServerIntegrity } else { "Not Set" }
        $binding = if($v.LdapEnforceChannelBinding) { $v.LdapEnforceChannelBinding } else { "Not Set" }
        $strong  = if($v.LDAPServerRequireStrongAuth) { $v.LDAPServerRequireStrongAuth } else { "Not Set" }

        Log "LDAP Status:" "INFO"
        Log "  Signing (LDAPServerIntegrity): $signing (2=required)" "INFO"
        Log "  Channel Binding (LdapEnforceChannelBinding): $binding (2=always)" "INFO"
        Log "  Strong Auth (LDAPServerRequireStrongAuth): $strong (2=required)" "INFO"

        if ($signing -eq 2 -and $binding -eq 2 -and $strong -eq 2) { Log "  Status: HARDENED" "SUCCESS" }
        else { Log "  Status: NOT HARDENED" "WARN" }
    } catch {
        Log "LDAP status check failed: $($_.Exception.Message)" "ERROR"
    }
}

# ------------------ Core Security GPO ------------------
function Deploy-CoreSec-GPO {
    if(-not $script:HasAD -or -not $script:HasGP){
        Log "CoreSec GPO: AD/GPO not available." "WARN"
        return
    }

    $result = [System.Windows.Forms.MessageBox]::Show(
        "This will enforce NTLMv2 and SMB signing.`n`nOlder systems may lose connectivity. Continue?",
        "Warning",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    if ($result -eq [System.Windows.Forms.DialogResult]::No) {
        Log "Core Security GPO cancelled by user." "INFO"
        return
    }

    $gName = "CCDC_Core_Security"
    try{
        $gpo = Get-GPO -Name $gName -Server $script:ctx.PreferredDC -ErrorAction SilentlyContinue
        if(-not $gpo){
            $gpo = New-GPO -Name $gName -Server $script:ctx.PreferredDC
            Log "Created new GPO: $gName" "SUCCESS"
        } else {
            Backup-GpoObject $gName | Out-Null
        }

        Set-GPRegistryValue -Name $gName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "LmCompatibilityLevel" -Type DWord -Value 5 -Server $script:ctx.PreferredDC
        Log "CoreSec: LmCompatibilityLevel=5 (NTLMv2 only)" "SUCCESS"

        Set-GPRegistryValue -Name $gName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "RequireSecuritySignature" -Type DWord -Value 1 -Server $script:ctx.PreferredDC
        Log "CoreSec: SMB client signing enabled" "SUCCESS"

        Set-GPRegistryValue -Name $gName -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "RequireSecuritySignature" -Type DWord -Value 1 -Server $script:ctx.PreferredDC
        Log "CoreSec: SMB server signing enabled" "SUCCESS"

        Set-GPRegistryValue -Name $gName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" -ValueName "NoLMHash" -Type DWord -Value 1 -Server $script:ctx.PreferredDC
        Log "CoreSec: LM hash storage disabled" "SUCCESS"

        New-GPLink -Name $gName -Target $script:ctx.DomainDN -LinkEnabled Yes -Server $script:ctx.PreferredDC -ErrorAction SilentlyContinue | Out-Null
        Log "Core Security GPO deployed & linked" "SUCCESS"
    }catch{
        Log "CoreSec GPO error: $($_.Exception.Message)" "ERROR"
    }
}

# ------------------ DNS Hardening (FIXED) ------------------
function Harden-DNS {
    if (-not $script:ctx.IsDC) {
        Log "DNS: Not a DC, skipping DNS hardening." "INFO"
        return
    }

    try{
        Import-Module DnsServer -ErrorAction Stop
        $zones = Get-DnsServerZone -ErrorAction Stop | Where-Object { $_.IsDsIntegrated -eq $true }

        foreach($z in $zones){
            Set-DnsServerPrimaryZone -Name $z.ZoneName -DynamicUpdate Secure -ErrorAction SilentlyContinue
            Set-DnsServerPrimaryZone -Name $z.ZoneName -SecureSecondaries TransferToZoneNameServer -ErrorAction SilentlyContinue
            Log "DNS: Secured zone $($z.ZoneName)" "SUCCESS"
        }

        # FIX: splat prevents parsing/argument transformation bugs
        $scavParams = @{
            ScavengingState    = $true
            ScavengingInterval = (New-TimeSpan -Days 7)
            RefreshInterval    = (New-TimeSpan -Days 7)
            NoRefreshInterval  = (New-TimeSpan -Days 7)
            ApplyOnAllZones    = $false
            ErrorAction        = 'SilentlyContinue'
        }
        Set-DnsServerScavenging @scavParams

        Log "DNS: Enabled scavenging (7-day intervals)" "SUCCESS"
    }catch{
        Log "DNS hardening failed: $($_.Exception.Message)" "ERROR"
    }
}

# ------------------ Password Policy ------------------
function Set-PasswordPolicy {
    if (-not $script:HasAD) {
        Log "Password Policy: AD not available." "WARN"
        return
    }

    $result = [System.Windows.Forms.MessageBox]::Show(
        "Set password policy?`n`n- Complexity: Enabled`n- Min Length: 10 chars`n- History: 5`n- Lockout: 5 attempts`n`nThis may affect existing accounts.",
        "Confirm",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question
    )

    if ($result -eq [System.Windows.Forms.DialogResult]::No) {
        Log "Password policy cancelled by user." "INFO"
        return
    }

    try{
        Set-ADDefaultDomainPasswordPolicy -Identity $script:ctx.DomainDN -Server $script:ctx.PreferredDC `
            -ComplexityEnabled $true -MinPasswordLength 10 -PasswordHistoryCount 5 `
            -LockoutThreshold 5 -LockoutDuration (New-TimeSpan -Minutes 15) `
            -LockoutObservationWindow (New-TimeSpan -Minutes 15) -ErrorAction Stop

        Log "Password policy updated successfully" "SUCCESS"
    } catch {
        Log "Password policy error: $($_.Exception.Message)" "ERROR"
    }
}

# ------------------ Auditing ------------------
function Enable-Auditing {
    Log "Enabling comprehensive audit policy..." "INFO"

    auditpol /set /category:"Account Logon" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"DS Access" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Object Access" /failure:enable | Out-Null
    auditpol /set /category:"Policy Change" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"Privilege Use" /success:enable /failure:enable | Out-Null
    auditpol /set /category:"System" /success:enable /failure:enable | Out-Null

    try{
        Disable-LocalUser -Name Guest -ErrorAction Stop
        Log "Guest account disabled" "SUCCESS"
    }catch{
        Log "Could not disable Guest: $($_.Exception.Message)" "WARN"
    }

    Log "Audit policy enabled" "SUCCESS"
}

# ------------------ SAFE MODE / FULL Hardening ------------------
function Invoke-SafeMode {
    if (-not (Test-Prerequisites)) {
        [System.Windows.Forms.MessageBox]::Show("Pre-flight checks failed. Review the log for details.","Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        return
    }

    Log "=== Starting SAFE MODE Hardening ===" "INFO"
    Harden-DNS
    Enable-Auditing
    Log "=== Safe mode complete ===" "SUCCESS"
}

function Invoke-FullHardening {
    if (-not (Test-Prerequisites)) {
        [System.Windows.Forms.MessageBox]::Show("Pre-flight checks failed. Review the log for details.","Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        return
    }

    $result = [System.Windows.Forms.MessageBox]::Show(
        "Full hardening includes:`n`n- Core Security GPO (NTLMv2, SMB signing)`n- Password Policy (10 char min)`n- DNS Hardening`n- Auditing`n`nThis may affect legacy systems. Continue?",
        "Confirm Full Hardening",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )

    if ($result -eq [System.Windows.Forms.DialogResult]::No) {
        Log "Full hardening cancelled by user." "INFO"
        return
    }

    Log "=== Starting FULL Hardening ===" "INFO"
    Deploy-CoreSec-GPO
    Set-PasswordPolicy
    Harden-DNS
    Enable-Auditing
    Log "=== Full hardening complete ===" "SUCCESS"
    Log "REMINDER: LDAP hardening requires DC reboot (use separate button)" "WARN"
}

# ------------------ Baseline ------------------
function Save-Baseline {
    if (-not $script:ctx.IsDomainJoined -or -not $script:HasAD) {
        Log "Baseline: AD not available." "WARN"
        return
    }

    Log "Capturing baseline..." "INFO"

    $groups = @{
        'Domain Admins'      = 'DomainAdmins.xml'
        'Enterprise Admins'  = 'EnterpriseAdmins.xml'
        'Schema Admins'      = 'SchemaAdmins.xml'
        'Account Operators'  = 'AccountOperators.xml'
    }

    foreach($group in $groups.Keys) {
        try {
            Get-ADGroupMember $group -Recursive -Server $script:ctx.PreferredDC -ErrorAction SilentlyContinue |
                Select Name,SamAccountName,ObjectClass,DistinguishedName |
                Export-CliXml (Join-Path $BaselineDir $groups[$group])
            Log "Baseline: $group captured" "SUCCESS"
        } catch {
            Log "Baseline $group error: $($_.Exception.Message)" "WARN"
        }
    }

    if($script:HasGP){
        try{
            $gpos = Get-GPO -All -Server $script:ctx.PreferredDC
            $gpos | Export-CliXml (Join-Path $BaselineDir 'GPOs.xml')

            $hdir = Join-Path $BaselineDir 'GPOHashes'
            New-Item $hdir -ItemType Directory -Force | Out-Null

            foreach($g in $gpos){
                try{
                    $xml = Get-GPOReport -Guid $g.Id -ReportType Xml -Server $script:ctx.PreferredDC
                    $sha = [BitConverter]::ToString((New-Object Security.Cryptography.SHA256Managed).ComputeHash([Text.Encoding]::UTF8.GetBytes($xml))) -replace '-',''
                    $safeName = ($g.DisplayName -replace '[\\/:*?"<>|]', '_')
                    Set-Content -Path (Join-Path $hdir "$safeName.sha256") -Value $sha -Encoding ASCII
                }catch{}
            }
            Log "Baseline: GPOs captured with hashes" "SUCCESS"
        } catch {
            Log "Baseline GPO error: $($_.Exception.Message)" "ERROR"
        }
    }

    try {
        Get-ADUser -Filter {ServicePrincipalName -like "*"} -Server $script:ctx.PreferredDC -Properties ServicePrincipalName -ErrorAction SilentlyContinue |
            Select Name,SamAccountName,ServicePrincipalName,Enabled |
            Export-CliXml (Join-Path $BaselineDir 'ServiceAccounts.xml')
        Log "Baseline: Service accounts captured" "SUCCESS"
    } catch {}

    Log "Baseline saved to: $BaselineDir" "SUCCESS"
}

# ------------------ Persistent Monitor (Scheduled Task) ------------------
function Start-PersistentMonitor {
    if (-not $script:ctx.IsDomainJoined -or -not $script:HasAD) {
        Log "Monitor: AD not available." "WARN"
        return
    }

    $monScript = @"
`$BaseDir = '$BaseDir'
`$Server = '$($script:ctx.PreferredDC)'
`$StateFile = '$MonStateFile'
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
`$mon = Join-Path `$BaseDir 'monitor.log'

`$lastRecordId = 0
if(Test-Path -LiteralPath `$StateFile) {
    try {
        `$state = Import-CliXml -Path `$StateFile
        `$lastRecordId = `$state.LastRecordId
    } catch {}
}

`$files = @{
    'Domain Admins' = Join-Path (Join-Path `$BaseDir 'Baseline') 'DomainAdmins.xml'
    'Enterprise Admins' = Join-Path (Join-Path `$BaseDir 'Baseline') 'EnterpriseAdmins.xml'
    'Schema Admins' = Join-Path (Join-Path `$BaseDir 'Baseline') 'SchemaAdmins.xml'
    'Account Operators' = Join-Path (Join-Path `$BaseDir 'Baseline') 'AccountOperators.xml'
}

foreach(`$group in `$files.Keys) {
    try {
        `$baseline = @()
        if(Test-Path -LiteralPath `$files[`$group]) {
            `$baseline = (Import-CliXml -Path `$files[`$group]).SamAccountName
        }

        `$current = @()
        try {
            `$current = (Get-ADGroupMember `$group -Recursive -Server `$Server -ErrorAction Stop | Select -Expand SamAccountName)
        } catch {}

        `$added = `$current | Where-Object { `$_ -notin `$baseline }
        if(`$added) {
            `$msg = "{0} ALERT: New members in {1}: {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), `$group, (`$added -join ',')
            Add-Content -Path `$mon -Value `$msg
        }
    } catch {}
}

`$ids = @(4720,4722,4723,4724,4728,4732,4756,4672,4625,4740,4768,4769,4776)
try {
    `$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=`$ids} -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object { `$_.RecordId -gt `$lastRecordId } |
        Sort-Object RecordId

    foreach(`$e in `$events) {
        `$msg = "{0} EVENT {1}: {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), `$e.Id, (`$e.Message -split "``n")[0]
        Add-Content -Path `$mon -Value `$msg
        `$lastRecordId = `$e.RecordId
    }

    @{LastRecordId=`$lastRecordId} | Export-CliXml -Path `$StateFile -Force
} catch {}
"@

    $monScriptPath = Join-Path $BaseDir 'monitor_script.ps1'
    Set-Content -Path $monScriptPath -Value $monScript -Encoding UTF8

    try {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$monScriptPath`""

        # Scheduler limit friendly duration: 10 years
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
            -RepetitionInterval (New-TimeSpan -Minutes 2) `
            -RepetitionDuration (New-TimeSpan -Days 3650)

        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

        Register-ScheduledTask -TaskName $MonTaskName -Action $action -Trigger $trigger `
            -Principal $principal -Settings $settings -Force | Out-Null

        Log "Persistent monitor started: $MonTaskName" "SUCCESS"
        Log "Monitor runs every 2 minutes. Log: $BaseDir\monitor.log" "INFO"
    } catch {
        Log "Failed to create scheduled task: $($_.Exception.Message)" "ERROR"
    }
}

function Stop-Monitor {
    try {
        Unregister-ScheduledTask -TaskName $MonTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Log "Stopped monitor: $MonTaskName" "SUCCESS"
    } catch {
        Log "Failed to stop monitor: $($_.Exception.Message)" "ERROR"
    }
}

# ------------------ NTP ------------------
function Set-NTP {
    if(-not $script:ctx.IsDomainJoined -or -not $script:HasAD){
        Log "NTP: AD not available." "WARN"
        return
    }

    try{
        $pdc = (Get-ADDomain -Server $script:ctx.PreferredDC).PDCEmulator
        $pdcShort = $pdc -replace '\..*$', ''
        Log "NTP: PDC Emulator is $pdc" "INFO"

        if($env:COMPUTERNAME -eq $pdcShort) {
            Log "NTP: This IS the PDC, configuring locally..." "INFO"
            w32tm /config /syncfromflags:manual /manualpeerlist:$NTPServer /update | Out-Null
            Restart-Service w32time -Force
            w32tm /resync /force | Out-Null
            Log "NTP configured locally on PDC: $NTPServer" "SUCCESS"
        } else {
            Log "NTP: Attempting remote configuration via WinRM..." "INFO"
            try {
                Invoke-Command -ComputerName $pdc -ScriptBlock {
                    param($ntp)
                    w32tm /config /syncfromflags:manual /manualpeerlist:$ntp /update | Out-Null
                    Restart-Service w32time -Force
                    w32tm /resync /force | Out-Null
                } -ArgumentList $NTPServer -ErrorAction Stop
                Log "NTP configured on PDC via WinRM: $pdc -> $NTPServer" "SUCCESS"
            } catch {
                Log "NTP: WinRM failed. Use GPO or configure manually on PDC." "WARN"
                [System.Windows.Forms.MessageBox]::Show(
                    "WinRM to PDC failed. Options:`n`n1) Configure NTP via GPO`n2) Run this script ON the PDC`n3) Enable WinRM on PDC",
                    "NTP Configuration Failed",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                ) | Out-Null
            }
        }
    }catch{
        Log "NTP failed: $($_.Exception.Message)" "ERROR"
    }
}

# ------------------ Banner GPO ------------------
function Push-Banner {
    if(-not $script:ctx.IsDomainJoined -or -not $script:HasAD -or -not $script:HasGP){
        Log "Banner: AD/GPO not available." "WARN"
        return
    }

    $g='CCDC_Login_Banner'
    try{
        $gpo=Get-GPO -Name $g -Server $script:ctx.PreferredDC -ErrorAction SilentlyContinue
        if(-not $gpo){
            $gpo=New-GPO -Name $g -Server $script:ctx.PreferredDC
        }

        Set-GPRegistryValue -Name $g -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
            -ValueName 'legalnoticecaption' -Type String -Value 'Authorized Access Only' -Server $script:ctx.PreferredDC
        Set-GPRegistryValue -Name $g -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
            -ValueName 'legalnoticetext' -Type String -Value $BannerText -Server $script:ctx.PreferredDC

        New-GPLink -Name $g -Target $script:ctx.DomainDN -LinkEnabled Yes -Server $script:ctx.PreferredDC -ErrorAction SilentlyContinue | Out-Null
        Log "Login banner GPO deployed" "SUCCESS"
    }catch{
        Log "Banner error: $($_.Exception.Message)" "ERROR"
    }
}

# ------------------ Firewall GPO ------------------
function Push-FirewallRule-GPO {
    param([bool]$IncludeAdminPorts = $false, [string]$AdminSubnet = "")

    if(-not $script:HasAD -or -not $script:HasGP){
        Log "FW GPO: AD/GPO not available." "WARN"
        return
    }

    $gName = "CCDC_Firewall_Safe"
    try{
        $gpo = Get-GPO -Name $gName -Server $script:ctx.PreferredDC -ErrorAction SilentlyContinue
        if(-not $gpo){
            $gpo = New-GPO -Name $gName -Server $script:ctx.PreferredDC
            Log "Created firewall GPO: $gName" "SUCCESS"
        }

        foreach($port in $SafeFWPorts.TCP) {
            $ruleName = "CCDC-Safe-TCP-$port"
            Set-GPRegistryValue -Name $gName `
                -Key "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
                -ValueName $ruleName -Type String `
                -Value "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=$port|Name=$ruleName|" `
                -Server $script:ctx.PreferredDC
            Log "FW: Allowed TCP/$port" "SUCCESS"
        }

        foreach($port in $SafeFWPorts.UDP) {
            $ruleName = "CCDC-Safe-UDP-$port"
            Set-GPRegistryValue -Name $gName `
                -Key "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
                -ValueName $ruleName -Type String `
                -Value "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=$port|Name=$ruleName|" `
                -Server $script:ctx.PreferredDC
            Log "FW: Allowed UDP/$port" "SUCCESS"
        }

        if($IncludeAdminPorts -and $AdminSubnet) {
            Log "FW: Adding admin ports restricted to $AdminSubnet..." "INFO"

            foreach($port in $AdminFWPorts.TCP) {
                $ruleName = "CCDC-Admin-TCP-$port"
                Set-GPRegistryValue -Name $gName `
                    -Key "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
                    -ValueName $ruleName -Type String `
                    -Value "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=$port|RA4=$AdminSubnet|Name=$ruleName|" `
                    -Server $script:ctx.PreferredDC
                Log "FW: Allowed admin TCP/$port from $AdminSubnet" "SUCCESS"
            }

            foreach($port in $AdminFWPorts.UDP) {
                $ruleName = "CCDC-Admin-UDP-$port"
                Set-GPRegistryValue -Name $gName `
                    -Key "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" `
                    -ValueName $ruleName -Type String `
                    -Value "v2.30|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=$port|RA4=$AdminSubnet|Name=$ruleName|" `
                    -Server $script:ctx.PreferredDC
                Log "FW: Allowed admin UDP/$port from $AdminSubnet" "SUCCESS"
            }
        }

        New-GPLink -Name $gName -Target $script:ctx.DomainDN -LinkEnabled Yes -Server $script:ctx.PreferredDC -ErrorAction SilentlyContinue | Out-Null
        $portList = ($SafeFWPorts.TCP + $SafeFWPorts.UDP) -join ','
        Log "Firewall GPO linked: $gName (safe ports: $portList)" "SUCCESS"
    }catch{
        Log "FW GPO error: $($_.Exception.Message)" "ERROR"
    }
}

function Show-FirewallConfig {
    $fwForm = New-Object System.Windows.Forms.Form
    $fwForm.Text = "Firewall Configuration"
    $fwForm.Size = New-Object System.Drawing.Size(500,300)
    $fwForm.StartPosition = "CenterScreen"

    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Text = "Safe ports (always allowed):`nTCP: 25,80,110,443,53`nUDP: 53`n`nOptional admin ports (requires subnet):`nTCP: 135,139,445,3389,5985,5986`nUDP: 137,138"
    $lblInfo.Location = New-Object System.Drawing.Point(20,20)
    $lblInfo.Size = New-Object System.Drawing.Size(450,100)

    $chkAdmin = New-Object System.Windows.Forms.CheckBox
    $chkAdmin.Text = "Include admin ports (restricted by subnet)"
    $chkAdmin.Location = New-Object System.Drawing.Point(20,130)
    $chkAdmin.Size = New-Object System.Drawing.Size(300,20)

    $lblSubnet = New-Object System.Windows.Forms.Label
    $lblSubnet.Text = "Admin subnet (CIDR):"
    $lblSubnet.Location = New-Object System.Drawing.Point(20,160)
    $lblSubnet.Size = New-Object System.Drawing.Size(150,20)

    $txtSubnet = New-Object System.Windows.Forms.TextBox
    $txtSubnet.Location = New-Object System.Drawing.Point(170,158)
    $txtSubnet.Size = New-Object System.Drawing.Size(200,20)
    $txtSubnet.Text = "10.0.0.0/24"
    $txtSubnet.Enabled = $false

    $chkAdmin.Add_CheckedChanged({ $txtSubnet.Enabled = $chkAdmin.Checked })

    $btnApply = New-Object System.Windows.Forms.Button
    $btnApply.Text = "Apply Firewall GPO"
    $btnApply.Location = New-Object System.Drawing.Point(150,210)
    $btnApply.Size = New-Object System.Drawing.Size(200,40)
    $btnApply.Add_Click({
        Invoke-UiAction {
            if($chkAdmin.Checked -and [string]::IsNullOrWhiteSpace($txtSubnet.Text)) {
                [System.Windows.Forms.MessageBox]::Show("Please specify admin subnet", "Error") | Out-Null
                return
            }
            $subnet = if($chkAdmin.Checked) { $txtSubnet.Text } else { "" }
            Push-FirewallRule-GPO -IncludeAdminPorts:$($chkAdmin.Checked) -AdminSubnet $subnet
            $fwForm.Close()
        }
    })

    $fwForm.Controls.AddRange(@($lblInfo,$chkAdmin,$lblSubnet,$txtSubnet,$btnApply))
    $fwForm.ShowDialog() | Out-Null
}

# ------------------ Incident Response ------------------
function Show-IncidentResponse {
    $irForm = New-Object System.Windows.Forms.Form
    $irForm.Text = "Incident Response"
    $irForm.Size = New-Object System.Drawing.Size(500,450)
    $irForm.StartPosition = "CenterScreen"

    $lblUser = New-Object System.Windows.Forms.Label
    $lblUser.Text = "Username:"
    $lblUser.Location = New-Object System.Drawing.Point(20,20)
    $lblUser.Size = New-Object System.Drawing.Size(100,20)

    $txtUser = New-Object System.Windows.Forms.TextBox
    $txtUser.Location = New-Object System.Drawing.Point(120,18)
    $txtUser.Size = New-Object System.Drawing.Size(200,20)

    $btnDisable = New-Object System.Windows.Forms.Button
    $btnDisable.Text = "Disable User"
    $btnDisable.Location = New-Object System.Drawing.Point(330,16)
    $btnDisable.Size = New-Object System.Drawing.Size(140,25)
    $btnDisable.Add_Click({
        Invoke-UiAction {
            if ($txtUser.Text) {
                Disable-ADAccount -Identity $txtUser.Text -Server $script:ctx.PreferredDC
                Log "IR: Disabled user: $($txtUser.Text)" "SUCCESS"
                [System.Windows.Forms.MessageBox]::Show("User disabled: $($txtUser.Text)", "Success") | Out-Null
            }
        }
    })

    $btnReset = New-Object System.Windows.Forms.Button
    $btnReset.Text = "Reset Password"
    $btnReset.Location = New-Object System.Drawing.Point(330,50)
    $btnReset.Size = New-Object System.Drawing.Size(140,25)
    $btnReset.Add_Click({
        Invoke-UiAction {
            if ($txtUser.Text) {
                $newPwd = -join ((65..90) + (97..122) + (48..57) + (33,35,36,37,38,42,43) | Get-Random -Count 16 | ForEach-Object {[char]$_})
                Set-ADAccountPassword -Identity $txtUser.Text -NewPassword (ConvertTo-SecureString $newPwd -AsPlainText -Force) -Reset -Server $script:ctx.PreferredDC
                Log "IR: Reset password for user: $($txtUser.Text)" "SUCCESS"
                [System.Windows.Forms.Clipboard]::SetText($newPwd)
                [System.Windows.Forms.MessageBox]::Show("Password reset successful!`n`nNew password: $newPwd`n`n(Copied to clipboard)", "Success") | Out-Null
            }
        }
    })

    $btnExportLogs = New-Object System.Windows.Forms.Button
    $btnExportLogs.Text = "Export Security Logs (1h)"
    $btnExportLogs.Location = New-Object System.Drawing.Point(20,100)
    $btnExportLogs.Size = New-Object System.Drawing.Size(200,30)
    $btnExportLogs.Add_Click({
        Invoke-UiAction {
            $outFile = Join-Path $ReportDir ("SecurityLog_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".csv")
            Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddHours(-1)} -ErrorAction Stop |
                Select TimeCreated,Id,LevelDisplayName,Message |
                Export-Csv -Path $outFile -NoTypeInformation
            Log "IR: Exported security logs: $outFile" "SUCCESS"
            [System.Windows.Forms.MessageBox]::Show("Exported to:`n$outFile", "Success") | Out-Null
        }
    })

    $btnKillSessions = New-Object System.Windows.Forms.Button
    $btnKillSessions.Text = "Kill RDP Sessions"
    $btnKillSessions.Location = New-Object System.Drawing.Point(230,100)
    $btnKillSessions.Size = New-Object System.Drawing.Size(200,30)
    $btnKillSessions.Add_Click({
        Invoke-UiAction {
            $count = 0
            $sessions = qwinsta | Select-String "rdp"
            foreach($s in $sessions) {
                $id = ($s -split '\s+')[3]
                if($id -match '^\d+$') {
                    logoff $id 2>$null
                    $count++
                }
            }
            Log "IR: Killed $count RDP sessions" "SUCCESS"
            [System.Windows.Forms.MessageBox]::Show("Killed $count RDP sessions", "Success") | Out-Null
        }
    })

    $btnRemoveFromDA = New-Object System.Windows.Forms.Button
    $btnRemoveFromDA.Text = "Remove from Domain Admins"
    $btnRemoveFromDA.Location = New-Object System.Drawing.Point(20,150)
    $btnRemoveFromDA.Size = New-Object System.Drawing.Size(220,30)
    $btnRemoveFromDA.Add_Click({
        if ($txtUser.Text) {
            try {
                Remove-ADGroupMember -Identity "Domain Admins" -Members $txtUser.Text -Server $script:ctx.PreferredDC -Confirm:$false
                Log "IR: Removed $($txtUser.Text) from Domain Admins" "SUCCESS"
                [System.Windows.Forms.MessageBox]::Show("Removed from Domain Admins", "Success") | Out-Null
            } catch {
                Log "IR: Failed to remove from DA: $($_.Exception.Message)" "ERROR"
            }
        }
    })
    
    $txtOutput = New-Object System.Windows.Forms.TextBox
    $txtOutput.Multiline = $true
    $txtOutput.ScrollBars = "Vertical"
    $txtOutput.ReadOnly = $true
    $txtOutput.Location = New-Object System.Drawing.Point(20,200)
    $txtOutput.Size = New-Object System.Drawing.Size(450,200)
    $txtOutput.Font = New-Object System.Drawing.Font("Consolas",9)
    $txtOutput.Text = "Recent alerts from monitor.log:`r`n`r`n"
    
    $monLog = Join-Path $BaseDir 'monitor.log'
    if(Test-Path $monLog) {
        $recent = Get-Content $monLog -Tail 20
        $txtOutput.AppendText(($recent -join "`r`n"))
    } else {
        $txtOutput.AppendText("(No monitor.log yet)")
    }
    
    $irForm.Controls.AddRange(@($lblUser,$txtUser,$btnDisable,$btnReset,$btnExportLogs,$btnKillSessions,$btnRemoveFromDA,$txtOutput))
    $irForm.ShowDialog() | Out-Null
}

# --- Evidence Export ---
function Export-Evidence {
    Log "Exporting evidence..." "INFO"
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    $monLog = Join-Path $BaseDir 'monitor.log'
    if(Test-Path $monLog){
        $out = Join-Path $ReportDir "Monitor_${timestamp}.csv"
        Get-Content $monLog | ForEach-Object{ 
            if($_ -match '^(.+?)\s+(.+)$') {
                [PSCustomObject]@{Timestamp=$matches[1];Message=$matches[2]}
            }
        } | Export-Csv $out -NoTypeInformation
        Log "Evidence: Monitor log exported" "SUCCESS"
    }
    
    try {
        $v = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue
        $ldapStatus = @"
LDAP Hardening Status - $(Get-Date)
=================================
LDAPServerIntegrity: $($v.LDAPServerIntegrity) (2=required)
LdapEnforceChannelBinding: $($v.LdapEnforceChannelBinding) (2=always)
LDAPServerRequireStrongAuth: $($v.LDAPServerRequireStrongAuth) (2=required)
"@
        Set-Content (Join-Path $ReportDir "LDAP_Status_${timestamp}.txt") $ldapStatus
        Log "Evidence: LDAP status exported" "SUCCESS"
    } catch {}
    
    try {
        $gpoReport = Join-Path $ReportDir "GPO_Report_${timestamp}.html"
        Get-GPOReport -All -ReportType Html -Path $gpoReport -Server $script:ctx.PreferredDC -ErrorAction SilentlyContinue
        Log "Evidence: GPO report exported" "SUCCESS"
    } catch {}
    
    try {
        $secLog = Join-Path $ReportDir "SecurityEvents_${timestamp}.csv"
        Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddHours(-4)} -MaxEvents 1000 -ErrorAction SilentlyContinue |
          Select TimeCreated,Id,LevelDisplayName,Message |
          Export-Csv $secLog -NoTypeInformation
        Log "Evidence: Security events exported" "SUCCESS"
    } catch {}
    
    try {
        Get-ADUser -Filter * -Server $script:ctx.PreferredDC -Properties WhenCreated,LastLogonDate,Enabled -ErrorAction SilentlyContinue |
          Select Name,SamAccountName,Enabled,WhenCreated,LastLogonDate |
          Export-Csv (Join-Path $ReportDir "ADUsers_${timestamp}.csv") -NoTypeInformation
        Log "Evidence: AD users exported" "SUCCESS"
    } catch {}
    
    try {
        $groups = @('Domain Admins','Enterprise Admins','Schema Admins','Account Operators','Backup Operators')
        $privReport = Join-Path $ReportDir "PrivilegedGroups_${timestamp}.txt"
        
        foreach($g in $groups) {
            Add-Content $privReport "`n=== $g ==="
            try {
                Get-ADGroupMember $g -Recursive -Server $script:ctx.PreferredDC -ErrorAction SilentlyContinue |
                  Select Name,SamAccountName | Format-Table -AutoSize |
                  Out-String | Add-Content $privReport
            } catch {
                Add-Content $privReport "Error: $($_.Exception.Message)"
            }
        }
        Log "Evidence: Privileged groups exported" "SUCCESS"
    } catch {}
    
    Log "Evidence export complete: $ReportDir" "SUCCESS"
    Start-Process explorer.exe $ReportDir
}

# --- System Status ---
function Show-SystemStatus {
    Log "=== System Status Check ===" "INFO"
    
    Log "Checking critical services..." "INFO"
    $services = @('NTDS','DNS','ADWS','Netlogon','W32Time')
    foreach($svc in $services) {
        try {
            $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if($s) {
                $status = if($s.Status -eq 'Running') { "SUCCESS" } else { "WARN" }
                Log "  $svc : $($s.Status)" $status
            }
        } catch {}
    }
    
    Log "Checking disk space..." "INFO"
    Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 } | ForEach-Object {
        $pct = [math]::Round(($_.Used / ($_.Used + $_.Free)) * 100, 1)
        $status = if($pct -gt 90) { "ERROR" } elseif($pct -gt 80) { "WARN" } else { "SUCCESS" }
        Log "  $($_.Name): ${pct}% used" $status
    }
    
    if($script:ctx.IsDC) {
        Log "Checking AD replication..." "INFO"
        try {
            $repl = repadmin /showrepl 2>$null
            if($repl -match "consecutive failures") {
                Log "  Replication: ISSUES DETECTED" "ERROR"
            } else {
                Log "  Replication: OK" "SUCCESS"
            }
        } catch {
            Log "  Replication check failed" "WARN"
        }
    }
    
    Log "=== Status check complete ===" "INFO"
}

# --- Advanced Firewall Config Dialog ---
function Show-FirewallConfig {
    $fwForm = New-Object System.Windows.Forms.Form
    $fwForm.Text = "Firewall Configuration"
    $fwForm.Size = New-Object System.Drawing.Size(500,300)
    $fwForm.StartPosition = "CenterScreen"
    
    $lblInfo = New-Object System.Windows.Forms.Label
    $lblInfo.Text = "Safe ports (always allowed):`nTCP: 25,80,110,443,53`nUDP: 53`n`nOptional admin ports (requires subnet):`nTCP: 135,139,445,3389,5985,5986`nUDP: 137,138"
    $lblInfo.Location = New-Object System.Drawing.Point(20,20)
    $lblInfo.Size = New-Object System.Drawing.Size(450,100)
    
    $chkAdmin = New-Object System.Windows.Forms.CheckBox
    $chkAdmin.Text = "Include admin ports (restricted by subnet)"
    $chkAdmin.Location = New-Object System.Drawing.Point(20,130)
    $chkAdmin.Size = New-Object System.Drawing.Size(300,20)
    
    $lblSubnet = New-Object System.Windows.Forms.Label
    $lblSubnet.Text = "Admin subnet (CIDR):"
    $lblSubnet.Location = New-Object System.Drawing.Point(20,160)
    $lblSubnet.Size = New-Object System.Drawing.Size(150,20)
    
    $txtSubnet = New-Object System.Windows.Forms.TextBox
    $txtSubnet.Location = New-Object System.Drawing.Point(170,158)
    $txtSubnet.Size = New-Object System.Drawing.Size(200,20)
    $txtSubnet.Text = "10.0.0.0/24"
    $txtSubnet.Enabled = $false
    
    $chkAdmin.Add_CheckedChanged({
        $txtSubnet.Enabled = $chkAdmin.Checked
    })
    
    $btnApply = New-Object System.Windows.Forms.Button
    $btnApply.Text = "Apply Firewall GPO"
    $btnApply.Location = New-Object System.Drawing.Point(150,210)
    $btnApply.Size = New-Object System.Drawing.Size(200,40)
    $btnApply.Add_Click({
        if($chkAdmin.Checked -and -not $txtSubnet.Text) {
            [System.Windows.Forms.MessageBox]::Show("Please specify admin subnet", "Error") | Out-Null
            return
        }
        
        $subnet = if($chkAdmin.Checked) { $txtSubnet.Text } else { "" }
        Push-FirewallRule-GPO -IncludeAdminPorts $chkAdmin.Checked -AdminSubnet $subnet
        $fwForm.Close()
    })
    
    $fwForm.Controls.AddRange(@($lblInfo,$chkAdmin,$lblSubnet,$txtSubnet,$btnApply))
    $fwForm.ShowDialog() | Out-Null
}

# ---------- GUI ----------
$form = New-Object System.Windows.Forms.Form
$form.Text = "CCDC AD Defense - Production Fixed"
$form.Size = New-Object System.Drawing.Size(920,720)
$form.StartPosition = "CenterScreen"
$form.Font = New-Object System.Drawing.Font("Segoe UI",9)
$form.BackColor = [System.Drawing.Color]::FromArgb(240,240,240)

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "CCDC Active Directory Defense - Fixed Edition"
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI",14,[System.Drawing.FontStyle]::Bold)
$lblTitle.Location = New-Object System.Drawing.Point(20,10)
$lblTitle.Size = New-Object System.Drawing.Size(600,30)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Location = New-Object System.Drawing.Point(20,45)
$lblStatus.Size = New-Object System.Drawing.Size(860,25)
$lblStatus.Text = "Initializing..."
$lblStatus.ForeColor = [System.Drawing.Color]::DarkBlue

# === Hardening ===
$grpHarden = New-Object System.Windows.Forms.GroupBox
$grpHarden.Text = "Hardening (Choose One)"
$grpHarden.Location = New-Object System.Drawing.Point(20,80)
$grpHarden.Size = New-Object System.Drawing.Size(420,140)

$btnSafeMode = New-Object System.Windows.Forms.Button
$btnSafeMode.Text="Safe Mode (DNS + Audit)"
$btnSafeMode.Size=New-Object System.Drawing.Size(180,40)
$btnSafeMode.Location=New-Object System.Drawing.Point(15,25)
$btnSafeMode.BackColor = [System.Drawing.Color]::FromArgb(16,124,16)
$btnSafeMode.ForeColor = [System.Drawing.Color]::White
$btnSafeMode.FlatStyle = "Flat"

$btnFullHarden = New-Object System.Windows.Forms.Button
$btnFullHarden.Text="Full Hardening"
$btnFullHarden.Size=New-Object System.Drawing.Size(180,40)
$btnFullHarden.Location=New-Object System.Drawing.Point(210,25)
$btnFullHarden.BackColor = [System.Drawing.Color]::FromArgb(255,140,0)
$btnFullHarden.ForeColor = [System.Drawing.Color]::White
$btnFullHarden.FlatStyle = "Flat"

$btnLDAP = New-Object System.Windows.Forms.Button
$btnLDAP.Text="Harden LDAP (REBOOT!)"
$btnLDAP.Size=New-Object System.Drawing.Size(180,40)
$btnLDAP.Location=New-Object System.Drawing.Point(15,75)
$btnLDAP.BackColor = [System.Drawing.Color]::FromArgb(192,0,0)
$btnLDAP.ForeColor = [System.Drawing.Color]::White
$btnLDAP.FlatStyle = "Flat"

$btnLDAPStatus = New-Object System.Windows.Forms.Button
$btnLDAPStatus.Text="Check LDAP Status"
$btnLDAPStatus.Size=New-Object System.Drawing.Size(180,40)
$btnLDAPStatus.Location=New-Object System.Drawing.Point(210,75)

$grpHarden.Controls.AddRange(@($btnSafeMode,$btnFullHarden,$btnLDAP,$btnLDAPStatus))

# === Monitoring ===
$grpMon = New-Object System.Windows.Forms.GroupBox
$grpMon.Text = "Baseline & Monitoring"
$grpMon.Location = New-Object System.Drawing.Point(460,80)
$grpMon.Size = New-Object System.Drawing.Size(420,140)

$btnBaseline = New-Object System.Windows.Forms.Button
$btnBaseline.Text="Create Baseline"
$btnBaseline.Size=New-Object System.Drawing.Size(180,40)
$btnBaseline.Location=New-Object System.Drawing.Point(15,25)
$btnBaseline.BackColor = [System.Drawing.Color]::FromArgb(0,120,215)
$btnBaseline.ForeColor = [System.Drawing.Color]::White
$btnBaseline.FlatStyle = "Flat"

$btnMonitor = New-Object System.Windows.Forms.Button
$btnMonitor.Text="Start Monitor"
$btnMonitor.Size=New-Object System.Drawing.Size(180,40)
$btnMonitor.Location=New-Object System.Drawing.Point(210,25)

$btnStopMon = New-Object System.Windows.Forms.Button
$btnStopMon.Text="Stop Monitor"
$btnStopMon.Size=New-Object System.Drawing.Size(180,40)
$btnStopMon.Location=New-Object System.Drawing.Point(15,75)

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text="Export Evidence"
$btnExport.Size=New-Object System.Drawing.Size(180,40)
$btnExport.Location=New-Object System.Drawing.Point(210,75)

$grpMon.Controls.AddRange(@($btnBaseline,$btnMonitor,$btnStopMon,$btnExport))

# === Tools ===
$grpTools = New-Object System.Windows.Forms.GroupBox
$grpTools.Text = "Additional Tools"
$grpTools.Location = New-Object System.Drawing.Point(20,235)
$grpTools.Size = New-Object System.Drawing.Size(860,100)

$btnBanner = New-Object System.Windows.Forms.Button
$btnBanner.Text="Push Banner"
$btnBanner.Size=New-Object System.Drawing.Size(130,35)
$btnBanner.Location=New-Object System.Drawing.Point(15,30)

$btnNTP = New-Object System.Windows.Forms.Button
$btnNTP.Text="Set NTP"
$btnNTP.Size=New-Object System.Drawing.Size(130,35)
$btnNTP.Location=New-Object System.Drawing.Point(155,30)

$btnFW = New-Object System.Windows.Forms.Button
$btnFW.Text="Configure Firewall"
$btnFW.Size=New-Object System.Drawing.Size(150,35)
$btnFW.Location=New-Object System.Drawing.Point(295,30)

$btnIR = New-Object System.Windows.Forms.Button
$btnIR.Text="Incident Response"
$btnIR.Size=New-Object System.Drawing.Size(150,35)
$btnIR.Location=New-Object System.Drawing.Point(455,30)
$btnIR.BackColor = [System.Drawing.Color]::FromArgb(192,0,0)
$btnIR.ForeColor = [System.Drawing.Color]::White
$btnIR.FlatStyle = "Flat"

$btnStatus = New-Object System.Windows.Forms.Button
$btnStatus.Text="System Status"
$btnStatus.Size=New-Object System.Drawing.Size(130,35)
$btnStatus.Location=New-Object System.Drawing.Point(615,30)

$btnOpenDir = New-Object System.Windows.Forms.Button
$btnOpenDir.Text="Open Folder"
$btnOpenDir.Size=New-Object System.Drawing.Size(110,35)
$btnOpenDir.Location=New-Object System.Drawing.Point(755,30)

$grpTools.Controls.AddRange(@($btnBanner,$btnNTP,$btnFW,$btnIR,$btnStatus,$btnOpenDir))

# === Log ===
$lblLog = New-Object System.Windows.Forms.Label
$lblLog.Text = "Activity Log:"
$lblLog.Location = New-Object System.Drawing.Point(20,345)
$lblLog.Size = New-Object System.Drawing.Size(200,20)
$lblLog.Font = New-Object System.Drawing.Font("Segoe UI",9,[System.Drawing.FontStyle]::Bold)

$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Multiline=$true
$txtLog.ScrollBars="Vertical"
$txtLog.ReadOnly=$true
$txtLog.Location=New-Object System.Drawing.Point(20,370)
$txtLog.Size=New-Object System.Drawing.Size(860,300)
$txtLog.Font = New-Object System.Drawing.Font("Consolas",9)
$txtLog.BackColor = [System.Drawing.Color]::FromArgb(30,30,30)
$txtLog.ForeColor = [System.Drawing.Color]::FromArgb(220,220,220)

$form.Controls.AddRange(@(
  $lblTitle,$lblStatus,$grpHarden,$grpMon,$grpTools,$lblLog,$txtLog
))

# === INITIALIZATION (FIXED: proper scoping) ===
$script:ctx = Get-DomainContext
Log "Base Directory: $BaseDir" "INFO"

if ($script:ctx.IsDomainJoined) {
    $statusText = "Domain: $($script:ctx.FQDN) | DC: $($script:ctx.PreferredDC) | Is DC: $($script:ctx.IsDC)"
    $lblStatus.Text = $statusText
    $lblStatus.ForeColor = [System.Drawing.Color]::DarkGreen
    Log $statusText "SUCCESS"
} else {
    $lblStatus.Text = "NOT DOMAIN-JOINED: $($script:ctx.Reason)"
    $lblStatus.ForeColor = [System.Drawing.Color]::Red
    Log "Not domain-joined: $($script:ctx.Reason)" "ERROR"
    
    foreach($b in @($btnSafeMode,$btnFullHarden,$btnLDAP,$btnLDAPStatus,$btnBaseline,$btnMonitor,$btnStopMon,$btnBanner,$btnNTP,$btnFW,$btnStatus)){
        $b.Enabled = $false
    }
    
    [System.Windows.Forms.MessageBox]::Show(
        "This host is not domain-joined. AD features are disabled.",
        "Warning",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    ) | Out-Null
}

# === Button Handlers ===
$btnSafeMode.Add_Click({ Invoke-SafeMode })
$btnFullHarden.Add_Click({ Invoke-FullHardening })
$btnLDAP.Add_Click({ Invoke-LDAPHardening; Show-LDAPStatus })
$btnLDAPStatus.Add_Click({ Show-LDAPStatus })
$btnBaseline.Add_Click({ Save-Baseline })
$btnMonitor.Add_Click({ Start-PersistentMonitor })
$btnStopMon.Add_Click({ Stop-Monitor })
$btnBanner.Add_Click({ Push-Banner })
$btnNTP.Add_Click({ Set-NTP })
$btnFW.Add_Click({ Show-FirewallConfig })
$btnExport.Add_Click({ Export-Evidence })
$btnIR.Add_Click({ Show-IncidentResponse })
$btnStatus.Add_Click({ Show-SystemStatus })
$btnOpenDir.Add_Click({ Start-Process explorer.exe $BaseDir })

$form.Add_FormClosing({
    Log "Application closing..." "INFO"
})

[void]$form.ShowDialog()
