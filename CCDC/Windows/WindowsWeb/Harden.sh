<#
.SYNOPSIS
  Windows Server 2019 Web hardening script (CCDC-focused, strict firewall).
.DESCRIPTION
  - Logs everything to C:\CCDC\logs\
  - Sets strong password/lockout policy
  - Enables Defender + ASR + Network Protection + mitigations
  - Enables comprehensive auditing + PowerShell logging
  - Firewall: STRICT - inbound allows only 80/443, outbound allows only 80/443/9997/DNS/NTP/DHCP
  - Disables RDP and WinRM (no remote access)
  - Creates persistence monitors (Run keys, WMI subscriptions, processes, services)
  - Disables LLMNR, NetBIOS, Print Spooler
  - Enforces SMB signing and encryption
  - Credential Guard (if hardware supports)
  - Disables weak SSL/TLS protocols
.NOTES
  Run in an elevated PowerShell.
  Tested for: Server 2019, Defender available.
  Requires reboot for LSA Protection (RunAsPPL) to fully activate.
#>

[CmdletBinding()]
param(
  [string]$BaseDir = "C:\CCDC"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -------------------- Helper Functions --------------------
function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this in an elevated PowerShell (Administrator)."
  }
}

function New-Dir([string]$Path) {
  if (-not (Test-Path $Path)) { New-Item -Path $Path -ItemType Directory -Force | Out-Null }
}

function Write-Section([string]$Title) {
  Write-Host ""
  Write-Host ("=" * 90)
  Write-Host $Title
  Write-Host ("=" * 90)
}

function Try-Do([string]$Name, [scriptblock]$Block) {
  try {
    Write-Host "[+] $Name"
    & $Block
    Write-Host "[OK] $Name"
  } catch {
    Write-Host "[!!] $Name failed: $($_.Exception.Message)"
  }
}

function Ensure-EventSource {
  param(
    [string]$LogName = "Application",
    [string]$Source  = "CCDC-Hardening"
  )
  if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
    New-EventLog -LogName $LogName -Source $Source
  }
}

function Write-CCDCEvent {
  param(
    [int]$EventId,
    [ValidateSet("Information","Warning","Error")] [string]$Type,
    [string]$Message
  )
  Ensure-EventSource
  Write-EventLog -LogName Application -Source "CCDC-Hardening" -EventId $EventId -EntryType $Type -Message $Message
}

# -------------------- Begin Execution --------------------
Assert-Admin

$LogsDir  = Join-Path $BaseDir "logs"
$StateDir = Join-Path $BaseDir "state"
New-Dir $BaseDir
New-Dir $LogsDir
New-Dir $StateDir

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$Transcript = Join-Path $LogsDir "hardening-$stamp.log"
Start-Transcript -Path $Transcript -Force | Out-Null

Write-Section "Windows Server 2019 Web Hardening - STRICT FIREWALL (CCDC)"

# -------------------- Time / NTP --------------------
Try-Do "Set timezone + resync time" {
  tzutil /s "Central Standard Time" | Out-Null
  w32tm /resync | Out-Null
}

# -------------------- Accounts / Password Policy --------------------
Try-Do "Disable Guest account" {
  $g = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
  if ($null -ne $g -and $g.Enabled) { Disable-LocalUser -Name "Guest" }
}

Try-Do "Set local password + lockout policy" {
  net accounts /minpwlen:14 /maxpwage:30 /minpwage:1 /uniquepw:5 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 | Out-Null
}

# -------------------- UAC --------------------
Try-Do "Enable UAC" {
  $p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
  Set-ItemProperty -Path $p -Name EnableLUA -Type DWord -Value 1
  Set-ItemProperty -Path $p -Name ConsentPromptBehaviorAdmin -Type DWord -Value 2
  Set-ItemProperty -Path $p -Name PromptOnSecureDesktop -Type DWord -Value 1
}

# -------------------- Disable RDP --------------------
Try-Do "Disable RDP" {
  Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1
}

# -------------------- Disable WinRM --------------------
Try-Do "Disable WinRM / PowerShell remoting" {
  Disable-PSRemoting -Force -ErrorAction SilentlyContinue
  Stop-Service WinRM -Force -ErrorAction SilentlyContinue
  Set-Service WinRM -StartupType Disabled -ErrorAction SilentlyContinue
  winrm delete winrm/config/Listener?Address=*+Transport=HTTP 2>$null
  winrm delete winrm/config/Listener?Address=*+Transport=HTTPS 2>$null
}

# -------------------- Defender / Exploit Guard / ASR --------------------
Try-Do "Enable Microsoft Defender (Realtime + PUA)" {
  Set-MpPreference -DisableRealtimeMonitoring $false
  Set-MpPreference -PUAProtection Enabled
}

Try-Do "Enable Defender cloud protection & sample submission" {
  Set-MpPreference -MAPSReporting Advanced
  Set-MpPreference -SubmitSamplesConsent 1
}

Try-Do "Enable comprehensive ASR rules" {
  $ids = @(
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",  # Block executable content from email/webmail
    "3B576869-A4EC-4529-8536-B80A7769E899",  # Block Office from creating executables
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",  # Block credential stealing from LSASS
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",  # Block executable content from USB
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",  # Block Win32 API calls from Office macros
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",  # Block obfuscated scripts
    "D3E037E1-3EB8-44C8-A917-57927947596D"   # Block JS/VBS launching downloaded executables
  )
  $actions = @("Enabled","Enabled","Enabled","Enabled","Enabled","Enabled","Enabled")
  Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions
}

Try-Do "Enable Controlled Folder Access (Audit mode)" {
  Set-MpPreference -EnableControlledFolderAccess AuditMode
}

Try-Do "Enable Network Protection" {
  Set-MpPreference -EnableNetworkProtection Enabled
}

Try-Do "Set cloud block level to High" {
  Set-MpPreference -CloudBlockLevel High
  Set-MpPreference -CloudExtendedTimeout 50
}

Try-Do "System process mitigations (DEP/SEHOP/ASLR)" {
  Set-ProcessMitigation -System -Enable DEP, SEHOP, BottomUp, HighEntropy
}

# -------------------- Credential Theft Hardening --------------------
Try-Do "Disable WDigest cleartext creds" {
  $wd = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
  if (-not (Test-Path $wd)) { New-Item -Path $wd -Force | Out-Null }
  Set-ItemProperty -Path $wd -Name UseLogonCredential -Type DWord -Value 0
}

Try-Do "Enable LSA protection (RunAsPPL)" {
  $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  Set-ItemProperty -Path $lsa -Name RunAsPPL -Type DWord -Value 1
}

Try-Do "Enable Credential Guard (if hardware supports)" {
  $dg = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
  $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  
  # Check if VBS is available
  $vbsStatus = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue).VirtualizationBasedSecurityStatus
  
  if ($vbsStatus -eq 2) {
    # VBS is running
    if (-not (Test-Path $dg)) { New-Item -Path $dg -Force | Out-Null }
    Set-ItemProperty -Path $dg -Name EnableVirtualizationBasedSecurity -Type DWord -Value 1
    Set-ItemProperty -Path $dg -Name RequirePlatformSecurityFeatures -Type DWord -Value 3  # TPM + Secure Boot
    Set-ItemProperty -Path $lsa -Name LsaCfgFlags -Type DWord -Value 1  # Credential Guard enabled
    Write-Host "    Credential Guard enabled (requires reboot)"
  } else {
    Write-Host "    Hardware doesn't support VBS - skipping Credential Guard"
  }
}

Try-Do "Disable LM hashes + restrict NTLM" {
  $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  Set-ItemProperty -Path $lsa -Name NoLmHash -Type DWord -Value 1
  Set-ItemProperty -Path $lsa -Name LmCompatibilityLevel -Type DWord -Value 5  # NTLMv2 only
  Set-ItemProperty -Path $lsa -Name RestrictSendingNTLMTraffic -Type DWord -Value 2  # Deny all NTLM
}

Try-Do "Disable anonymous enumeration" {
  $lsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
  Set-ItemProperty -Path $lsa -Name RestrictAnonymous -Type DWord -Value 1
  Set-ItemProperty -Path $lsa -Name RestrictAnonymousSAM -Type DWord -Value 1
  Set-ItemProperty -Path $lsa -Name DisableDomainCreds -Type DWord -Value 1
}

Try-Do "Disable SMBv1, require SMB signing + encryption" {
  # Disable SMBv1 completely
  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
  Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
  
  # Require signing
  Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
  Set-SmbServerConfiguration -EnableSecuritySignature  $true -Force
  
  # Require encryption (SMBv3+)
  Set-SmbServerConfiguration -EncryptData $true -Force
  Set-SmbServerConfiguration -RejectUnencryptedAccess $true -Force
}

# -------------------- Disable LLMNR and NetBIOS --------------------
Try-Do "Disable LLMNR" {
  $dnsclient = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
  if (-not (Test-Path $dnsclient)) { New-Item -Path $dnsclient -Force | Out-Null }
  New-ItemProperty -Path $dnsclient -Name EnableMulticast -PropertyType DWORD -Value 0 -Force | Out-Null
}

Try-Do "Disable NetBIOS over TCP/IP" {
  $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
  foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2) | Out-Null  # 2 = Disable NetBIOS
  }
}

# -------------------- Disable Print Spooler --------------------
Try-Do "Disable Print Spooler (PrintNightmare mitigation)" {
  Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
  Set-Service -Name Spooler -StartupType Disabled
}

# -------------------- Disable Weak SSL/TLS --------------------
Try-Do "Disable SSL 2.0 and SSL 3.0" {
  $ssl2Server = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
  $ssl3Server = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
  
  if (-not (Test-Path $ssl2Server)) { New-Item -Path $ssl2Server -Force | Out-Null }
  if (-not (Test-Path $ssl3Server)) { New-Item -Path $ssl3Server -Force | Out-Null }
  
  New-ItemProperty -Path $ssl2Server -Name Enabled -Value 0 -PropertyType DWORD -Force | Out-Null
  New-ItemProperty -Path $ssl3Server -Name Enabled -Value 0 -PropertyType DWORD -Force | Out-Null
}

# -------------------- Auditing / Logging --------------------
Try-Do "Enable advanced audit policies" {
  # Logon/Logoff
  auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
  auditpol /set /subcategory:"Logoff" /success:enable /failure:enable | Out-Null
  auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable | Out-Null

  # Account management
  auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
  auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null

  # Object access
  auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
  auditpol /set /subcategory:"Registry" /success:enable /failure:enable | Out-Null

  # Policy change / privilege use
  auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable | Out-Null
  auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable | Out-Null

  # Process creation
  auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
}

Try-Do "PowerShell logging (Module + ScriptBlock) + command line auditing" {
  # Script Block + Module logging
  $sb = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
  $ml = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
  New-Item -Path $sb -Force | Out-Null
  New-Item -Path $ml -Force | Out-Null
  Set-ItemProperty -Path $sb -Name EnableScriptBlockLogging -Type DWord -Value 1
  Set-ItemProperty -Path $ml -Name EnableModuleLogging -Type DWord -Value 1
  New-Item -Path "$ml\ModuleNames" -Force | Out-Null
  Set-ItemProperty -Path "$ml\ModuleNames" -Name "*" -Type String -Value "*"

  # Process command line in 4688
  $a = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
  New-Item -Path $a -Force | Out-Null
  Set-ItemProperty -Path $a -Name ProcessCreationIncludeCmdLine_Enabled -Type DWord -Value 1
}

Try-Do "Increase event log sizes" {
  wevtutil sl Security /ms:268435456  # 256 MB
  wevtutil sl System   /ms:134217728  # 128 MB
  wevtutil sl Application /ms:134217728
  wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:67108864
}

# -------------------- SMB Shares --------------------
Try-Do "Remove non-standard SMB shares" {
  $keep = @("ADMIN$","C$","IPC$","NETLOGON","SYSVOL")
  Get-SmbShare | Where-Object { $_.Name -notin $keep } | ForEach-Object {
    Remove-SmbShare -Name $_.Name -Force -ErrorAction SilentlyContinue
  }
}

# -------------------- Firewall (STRICT: inbound 80/443, outbound 80/443/9997/DNS/NTP/DHCP) --------------------
Try-Do "Firewall: STRICT configuration (block by default, whitelist only)" {
  $fwBackup = Join-Path $LogsDir "firewall-$stamp.wfw"
  netsh advfirewall export $fwBackup | Out-Null

  # Enable profiles
  Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

  # STRICT defaults: block inbound AND outbound
  Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block
  Set-NetFirewallProfile -Profile Domain,Public,Private -NotifyOnListen True
  Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 8192 `
    -LogFileName (Join-Path $LogsDir "pfirewall.log")

  # Remove old CCDC-* rules
  Get-NetFirewallRule -DisplayName "CCDC-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

  # === INBOUND RULES ===
  # Web services
  New-NetFirewallRule -DisplayName "CCDC-HTTP-In"  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 80  -Profile Any
  New-NetFirewallRule -DisplayName "CCDC-HTTPS-In" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 443 -Profile Any

  # ICMP (ping)
  New-NetFirewallRule -DisplayName "CCDC-ICMPv4-In" -Direction Inbound -Action Allow -Protocol ICMPv4 -Profile Any

  # === OUTBOUND RULES ===
  # Web browsing (for Windows Update, etc.)
  New-NetFirewallRule -DisplayName "CCDC-HTTP-Out"  -Direction Outbound -Action Allow -Protocol TCP -RemotePort 80  -Profile Any
  New-NetFirewallRule -DisplayName "CCDC-HTTPS-Out" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 443 -Profile Any

  # Splunk forwarder
  New-NetFirewallRule -DisplayName "CCDC-Splunk-Out" -Direction Outbound -Action Allow -Protocol TCP -RemotePort 9997 -Profile Any

  # DNS (required for name resolution)
  New-NetFirewallRule -DisplayName "CCDC-DNS-Out" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53 -Profile Any

  # NTP (required for time sync)
  New-NetFirewallRule -DisplayName "CCDC-NTP-Out" -Direction Outbound -Action Allow -Protocol UDP -RemotePort 123 -Profile Any

  # DHCP (if using DHCP)
  New-NetFirewallRule -DisplayName "CCDC-DHCP-Out" -Direction Outbound -Action Allow -Protocol UDP -LocalPort 68 -RemotePort 67 -Profile Any

  Write-Host "    Firewall configured: STRICT mode (only 80/443 in, 80/443/9997/DNS/NTP/DHCP out)"
}

# -------------------- Windows Update --------------------
Try-Do "Trigger Windows Update scan/install" {
  Set-Service -Name wuauserv -StartupType Automatic
  Start-Service -Name wuauserv

  # Use UsoClient (native, no module dependency)
  Start-Process -FilePath "$env:SystemRoot\System32\UsoClient.exe" -ArgumentList "StartScan" -NoNewWindow -Wait -ErrorAction SilentlyContinue
  Start-Process -FilePath "$env:SystemRoot\System32\UsoClient.exe" -ArgumentList "StartDownload" -NoNewWindow -Wait -ErrorAction SilentlyContinue
  Start-Process -FilePath "$env:SystemRoot\System32\UsoClient.exe" -ArgumentList "StartInstall" -NoNewWindow -Wait -ErrorAction SilentlyContinue
}

# -------------------- Persistence Monitors --------------------
Try-Do "Create startup Run-key monitor (Event Log)" {
  $monitor = Join-Path $BaseDir "StartupRunKeyMonitor.ps1"
  @"
`$ErrorActionPreference = 'SilentlyContinue'
`$stateFile = '$StateDir\runkey.json'

function SaveState(`$obj){ `$obj | ConvertTo-Json -Depth 5 | Set-Content -Path `$stateFile -Force -Encoding UTF8 }
function LoadState(){ if(Test-Path `$stateFile){ Get-Content `$stateFile -Raw | ConvertFrom-Json } else { @{} } }

`$curr = @{}
try {
  `$rk = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
  foreach(`$p in `$rk.PSObject.Properties){ 
    if(`$p.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')){ 
      `$curr[`$p.Name]=[string]`$p.Value 
    } 
  }
} catch {}

`$prev = LoadState
if(-not `$prev){ SaveState `$curr; exit 0 }

`$added = Compare-Object -ReferenceObject `$prev.PSObject.Properties.Name -DifferenceObject `$curr.Keys | Where-Object SideIndicator -eq '=>'
if(`$added){
  foreach(`$a in `$added){
    `$name = `$a.InputObject
    `$val  = `$curr[`$name]
    eventcreate /T WARNING /ID 3001 /L APPLICATION /SO "CCDC-Hardening" /D "New HKLM Run startup item: `$name = `$val" | Out-Null
  }
}
SaveState `$curr
"@ | Set-Content -Path $monitor -Force -Encoding UTF8

  $taskName = "CCDC-StartupRunKeyMonitor"
  schtasks /Create /F /RU SYSTEM /RL HIGHEST /SC MINUTE /MO 2 /TN $taskName /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$monitor`"" | Out-Null
}

Try-Do "Create WMI subscription monitor (Event Log)" {
  $monitor = Join-Path $BaseDir "WmiSubMonitor.ps1"
  @"
`$ErrorActionPreference = 'SilentlyContinue'
`$stateFile = '$StateDir\wmi_subs.json'

function SaveState(`$obj){ `$obj | ConvertTo-Json -Depth 6 | Set-Content -Path `$stateFile -Force -Encoding UTF8 }
function LoadState(){ if(Test-Path `$stateFile){ Get-Content `$stateFile -Raw | ConvertFrom-Json } else { @() } }

`$curr = @()
try {
  `$bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding
  foreach(`$b in `$bindings){
    `$curr += [pscustomobject]@{
      Filter   = [string]`$b.Filter
      Consumer = [string]`$b.Consumer
    }
  }
} catch {}

`$prev = LoadState
if(-not `$prev){ SaveState `$curr; exit 0 }

`$prevS = `$prev | ForEach-Object { "`$($_.Filter) -> `$($_.Consumer)" }
`$currS = `$curr | ForEach-Object { "`$($_.Filter) -> `$($_.Consumer)" }

`$added = Compare-Object -ReferenceObject `$prevS -DifferenceObject `$currS | Where-Object SideIndicator -eq '=>'
if(`$added){
  foreach(`$a in `$added){
    eventcreate /T WARNING /ID 3002 /L APPLICATION /SO "CCDC-Hardening" /D "New WMI subscription binding: `$(`$a.InputObject)" | Out-Null
  }
}
SaveState `$curr
"@ | Set-Content -Path $monitor -Force -Encoding UTF8

  $taskName = "CCDC-WmiSubscriptionMonitor"
  schtasks /Create /F /RU SYSTEM /RL HIGHEST /SC MINUTE /MO 2 /TN $taskName /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$monitor`"" | Out-Null
}

Try-Do "Create suspicious process monitor (Event Log)" {
  $monitor = Join-Path $BaseDir "SuspiciousProcessMonitor.ps1"
  @"
`$ErrorActionPreference = 'SilentlyContinue'

# Get process creation events from last 2 minutes
`$events = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688;StartTime=(Get-Date).AddMinutes(-2)} -ErrorAction SilentlyContinue

foreach (`$event in `$events) {
    `$xml = [xml]`$event.ToXml()
    `$cmdLine = `$xml.Event.EventData.Data | Where-Object {`$_.Name -eq 'CommandLine'} | Select-Object -ExpandProperty '#text'
    
    # Suspicious patterns
    `$suspicious = @(
        'powershell.*-enc',
        'powershell.*-e ',
        'powershell.*IEX',
        'powershell.*DownloadString',
        'cmd.exe /c',
        'wmic',
        'net user',
        'net localgroup',
        'reg add',
        'schtasks',
        'vssadmin delete shadows'
    )
    
    foreach (`$pattern in `$suspicious) {
        if (`$cmdLine -match `$pattern) {
            eventcreate /T WARNING /ID 3003 /L APPLICATION /SO "CCDC-Hardening" /D "Suspicious process: `$cmdLine" | Out-Null
            break
        }
    }
}
"@ | Set-Content -Path $monitor -Force -Encoding UTF8

  $taskName = "CCDC-SuspiciousProcessMonitor"
  schtasks /Create /F /RU SYSTEM /RL HIGHEST /SC MINUTE /MO 2 /TN $taskName /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$monitor`"" | Out-Null
}

Try-Do "Create service creation monitor (Event Log)" {
  $monitor = Join-Path $BaseDir "ServiceCreationMonitor.ps1"
  @"
`$ErrorActionPreference = 'SilentlyContinue'

# Get service installation events from last 2 minutes
`$events = Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=(Get-Date).AddMinutes(-2)} -ErrorAction SilentlyContinue

foreach (`$event in `$events) {
    `$xml = [xml]`$event.ToXml()
    `$serviceName = `$xml.Event.EventData.Data[0].'#text'
    `$serviceFile = `$xml.Event.EventData.Data[1].'#text'
    
    eventcreate /T WARNING /ID 3004 /L APPLICATION /SO "CCDC-Hardening" /D "New service created: `$serviceName (`$serviceFile)" | Out-Null
}
"@ | Set-Content -Path $monitor -Force -Encoding UTF8

  $taskName = "CCDC-ServiceCreationMonitor"
  schtasks /Create /F /RU SYSTEM /RL HIGHEST /SC MINUTE /MO 2 /TN $taskName /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$monitor`"" | Out-Null
}

# -------------------- Disable Non-Admin Users --------------------
Try-Do "Disable non-administrator local users" {
  $adminSid = "S-1-5-32-544"
  $adminGroup = Get-LocalGroupMember -SID $adminSid -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
  $allUsers = Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.Name -ne "Administrator"}

  foreach ($user in $allUsers) {
    $isAdmin = $adminGroup -contains "$env:COMPUTERNAME\$($user.Name)"
    if (-not $isAdmin) {
      Disable-LocalUser -Name $user.Name
      Write-Host "    Disabled non-admin user: $($user.Name)"
    }
  }
}

# -------------------- Final Defender Scan --------------------
Try-Do "Defender quick scan" {
  Start-MpScan -ScanType QuickScan
}

# -------------------- Completion --------------------
Write-CCDCEvent -EventId 1000 -Type Information -Message "CCDC Web hardening completed (STRICT firewall). Log: $Transcript"
Write-Section "Done. Log saved to: $Transcript"
Write-Host ""
Write-Host "IMPORTANT NOTES:"
Write-Host "  - RDP and WinRM are DISABLED"
Write-Host "  - Firewall is in STRICT mode (most traffic blocked)"
Write-Host "  - Inbound: Only 80, 443 allowed"
Write-Host "  - Outbound: Only 80, 443, 9997, DNS, NTP, DHCP allowed"
Write-Host "  - REBOOT REQUIRED for LSA Protection to activate"
Write-Host "  - Monitor Application log for Event IDs: 3001 (Run keys), 3002 (WMI), 3003 (Processes), 3004 (Services)"
Write-Host ""

Stop-Transcript | Out-Null
