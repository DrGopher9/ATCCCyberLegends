#Requires -RunAsAdministrator

################################################################################
# CCDC Competition Windows Firewall Hardening Script
# 2026 Midwest CCDC Qualifier
#
# PowerShell equivalent of the Linux iptables script
# - Default BLOCK policy on all profiles
# - Only specified ports are allowed
# - Extensive logging for incident response
# - Protection against common attacks
#
# COMPETITION REQUIREMENTS:
# - Must maintain ICMP (ping) for scoring
# - Must allow scored services (HTTP/HTTPS, SMB, RDP, etc.)
# - Should log suspicious activity for IR reports
################################################################################

# Configuration
$LogFile = "C:\CCDC\Logs\firewall-$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$BackupPath = "C:\CCDC\Backups\Firewall"
$ScriptsPath = "C:\CCDC\Scripts\Firewall"

# Create directories
New-Item -ItemType Directory -Force -Path "C:\CCDC\Logs" | Out-Null
New-Item -ItemType Directory -Force -Path $BackupPath | Out-Null
New-Item -ItemType Directory -Force -Path $ScriptsPath | Out-Null

# Logging functions
function Write-Log {
    param($Message, $Color = "White")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] $Message"
    Write-Host $LogMessage -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $LogMessage
}

function Write-Success {
    param($Message)
    Write-Log "[SUCCESS] $Message" "Green"
}

function Write-Warning {
    param($Message)
    Write-Log "[WARNING] $Message" "Yellow"
}

function Write-Error {
    param($Message)
    Write-Log "[ERROR] $Message" "Red"
}

function Write-Info {
    param($Message)
    Write-Log "[INFO] $Message" "Cyan"
}

# Check for admin privileges
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit 1
}

# Backup current firewall rules
function Backup-FirewallRules {
    Write-Info "Backing up current firewall rules..."
    
    $BackupFile = Join-Path $BackupPath "firewall-rules-$(Get-Date -Format 'yyyyMMdd_HHmmss').wfw"
    
    try {
        netsh advfirewall export "$BackupFile" | Out-Null
        Write-Success "Firewall rules backed up to: $BackupFile"
        
        # Also export to PowerShell format
        $PSBackup = Join-Path $BackupPath "firewall-rules-$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
        Get-NetFirewallRule | Export-Clixml -Path $PSBackup
        Write-Success "PowerShell format backup: $PSBackup"
    }
    catch {
        Write-Error "Failed to backup firewall rules: $_"
    }
}

# Detect system role based on installed services/features
function Get-SystemRoles {
    Write-Info "Detecting system roles..."
    
    $roles = @()
    
    # Check for Web Server (IIS)
    $iis = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
    if ($iis -and $iis.Status -eq 'Running') {
        $roles += "web"
        Write-Info "  ✓ Detected: Web Server (IIS)"
    }
    
    # Check for Mail Server (SMTP Service or Exchange)
    $smtp = Get-Service -Name SMTPSVC -ErrorAction SilentlyContinue
    $exchange = Get-Service -Name MSExchangeTransport -ErrorAction SilentlyContinue
    if (($smtp -and $smtp.Status -eq 'Running') -or ($exchange -and $exchange.Status -eq 'Running')) {
        $roles += "mail"
        Write-Info "  ✓ Detected: Mail Server"
    }
    
    # Check for DNS Server
    $dns = Get-Service -Name DNS -ErrorAction SilentlyContinue
    if ($dns -and $dns.Status -eq 'Running') {
        $roles += "dns"
        Write-Info "  ✓ Detected: DNS Server"
    }
    
    # Check for Active Directory Domain Controller
    $adws = Get-Service -Name ADWS -ErrorAction SilentlyContinue
    if ($adws -and $adws.Status -eq 'Running') {
        $roles += "dc"
        Write-Info "  ✓ Detected: Active Directory Domain Controller"
    }
    
    # Check for SQL Server
    $sql = Get-Service | Where-Object { $_.Name -like 'MSSQL*' -and $_.Status -eq 'Running' }
    if ($sql) {
        $roles += "sql"
        Write-Info "  ✓ Detected: SQL Server"
    }
    
    # Check for FTP Server
    $ftp = Get-Service -Name FTPSVC -ErrorAction SilentlyContinue
    if ($ftp -and $ftp.Status -eq 'Running') {
        $roles += "ftp"
        Write-Info "  ✓ Detected: FTP Server"
    }
    
    # If no roles detected
    if ($roles.Count -eq 0) {
        $roles += "generic"
        Write-Info "  → No specific services detected, using generic rules"
    }
    
    return $roles
}

# Enable Windows Firewall on all profiles
function Enable-WindowsFirewall {
    Write-Info "Enabling Windows Firewall on all profiles..."
    
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Write-Success "Windows Firewall enabled on all profiles"
    }
    catch {
        Write-Error "Failed to enable firewall: $_"
    }
}

# Set default block policies
function Set-DefaultBlockPolicy {
    Write-Info "Setting default BLOCK policies..."
    
    try {
        # Block inbound, allow outbound by default (we'll restrict outbound later)
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow
        
        # Enable logging
        Set-NetFirewallProfile -Profile Domain,Public,Private `
            -LogAllowed True `
            -LogBlocked True `
            -LogFileName "C:\CCDC\Logs\pfirewall.log" `
            -LogMaxSizeKilobytes 32767
        
        Write-Success "Default BLOCK policy set on all profiles"
        Write-Success "Logging enabled: C:\CCDC\Logs\pfirewall.log"
    }
    catch {
        Write-Error "Failed to set default policy: $_"
    }
}

# Remove all existing firewall rules (clean slate)
function Remove-AllFirewallRules {
    Write-Warning "Removing all existing firewall rules..."
    
    try {
        Get-NetFirewallRule | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-Success "All firewall rules removed"
    }
    catch {
        Write-Error "Failed to remove rules: $_"
    }
}

# Apply base rules (ICMP, loopback, established connections)
function Add-BaseRules {
    Write-Info "Applying base firewall rules..."
    
    # Allow loopback
    Write-Info "  → Allowing loopback traffic..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-Loopback-In" `
        -Direction Inbound -Action Allow `
        -InterfaceAlias "Loopback Pseudo-Interface 1" `
        -Profile Any -Enabled True | Out-Null
    
    New-NetFirewallRule -DisplayName "CCDC-Allow-Loopback-Out" `
        -Direction Outbound -Action Allow `
        -InterfaceAlias "Loopback Pseudo-Interface 1" `
        -Profile Any -Enabled True | Out-Null
    
    # Allow ICMP (ping) - REQUIRED FOR SCORING
    Write-Info "  → Allowing ICMP (ping) - REQUIRED FOR SCORING..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-ICMPv4-In" `
        -Direction Inbound -Action Allow `
        -Protocol ICMPv4 -IcmpType 8 `
        -Profile Any -Enabled True | Out-Null
    
    New-NetFirewallRule -DisplayName "CCDC-Allow-ICMPv4-Out" `
        -Direction Outbound -Action Allow `
        -Protocol ICMPv4 `
        -Profile Any -Enabled True | Out-Null
    
    # Allow established connections (connection tracking)
    Write-Info "  → Allowing established connections..."
    # Note: Windows Firewall does this by default with stateful inspection
    
    # Block NetBIOS (common attack vector)
    Write-Info "  → Blocking NetBIOS (attack vector)..."
    New-NetFirewallRule -DisplayName "CCDC-Block-NetBIOS-137" `
        -Direction Inbound -Action Block `
        -Protocol UDP -LocalPort 137 `
        -Profile Any -Enabled True | Out-Null
    
    New-NetFirewallRule -DisplayName "CCDC-Block-NetBIOS-138" `
        -Direction Inbound -Action Block `
        -Protocol UDP -LocalPort 138 `
        -Profile Any -Enabled True | Out-Null
    
    New-NetFirewallRule -DisplayName "CCDC-Block-NetBIOS-139" `
        -Direction Inbound -Action Block `
        -Protocol TCP -LocalPort 139 `
        -Profile Any -Enabled True | Out-Null
    
    Write-Success "Base rules applied"
}

# Management/Administrative rules (RDP, WinRM)
function Add-ManagementRules {
    Write-Info "Applying management access rules..."
    
    # RDP (3389) - For team management
    Write-Info "  → Allowing RDP (3389) for team access..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-RDP-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 3389 `
        -Profile Any -Enabled True | Out-Null
    
    New-NetFirewallRule -DisplayName "CCDC-Allow-RDP-Out" `
        -Direction Outbound -Action Allow `
        -Protocol TCP -RemotePort 3389 `
        -Profile Any -Enabled True | Out-Null
    
    # WinRM (5985, 5986) - For remote PowerShell management
    Write-Info "  → Allowing WinRM (5985, 5986) for remote management..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-WinRM-HTTP-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 5985 `
        -Profile Any -Enabled True | Out-Null
    
    New-NetFirewallRule -DisplayName "CCDC-Allow-WinRM-HTTPS-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 5986 `
        -Profile Any -Enabled True | Out-Null
    
    Write-Success "Management rules applied (RDP, WinRM)"
}

# Web Server rules (HTTP, HTTPS)
function Add-WebServerRules {
    Write-Info "  → Configuring WEB server rules..."
    
    # HTTP (80) - SCORED SERVICE - NO RATE LIMITING
    Write-Info "    → Allowing HTTP (80)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-HTTP-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 80 `
        -Profile Any -Enabled True | Out-Null
    
    New-NetFirewallRule -DisplayName "CCDC-Allow-HTTP-Out" `
        -Direction Outbound -Action Allow `
        -Protocol TCP -RemotePort 80 `
        -Profile Any -Enabled True | Out-Null
    
    # HTTPS (443) - SCORED SERVICE - NO RATE LIMITING
    Write-Info "    → Allowing HTTPS (443)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-HTTPS-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 443 `
        -Profile Any -Enabled True | Out-Null
    
    New-NetFirewallRule -DisplayName "CCDC-Allow-HTTPS-Out" `
        -Direction Outbound -Action Allow `
        -Protocol TCP -RemotePort 443 `
        -Profile Any -Enabled True | Out-Null
    
    # HTTP/2 over QUIC (UDP 443)
    Write-Info "    → Allowing HTTP/3 QUIC (UDP 443)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-HTTPS-QUIC-In" `
        -Direction Inbound -Action Allow `
        -Protocol UDP -LocalPort 443 `
        -Profile Any -Enabled True | Out-Null
    
    Write-Success "  ✓ Web server rules applied (80, 443)"
}

# Mail Server rules (SMTP, POP3, IMAP)
function Add-MailServerRules {
    Write-Info "  → Configuring MAIL server rules..."
    
    # SMTP (25) - SCORED SERVICE - NO RATE LIMITING
    Write-Info "    → Allowing SMTP (25)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-SMTP-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 25 `
        -Profile Any -Enabled True | Out-Null
    
    New-NetFirewallRule -DisplayName "CCDC-Allow-SMTP-Out" `
        -Direction Outbound -Action Allow `
        -Protocol TCP -RemotePort 25 `
        -Profile Any -Enabled True | Out-Null
    
    # SMTP Submission (587)
    Write-Info "    → Allowing SMTP Submission (587)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-SMTP-Submission-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 587 `
        -Profile Any -Enabled True | Out-Null
    
    # SMTPS (465)
    Write-Info "    → Allowing SMTPS (465)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-SMTPS-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 465 `
        -Profile Any -Enabled True | Out-Null
    
    # POP3 (110) - SCORED SERVICE - NO RATE LIMITING
    Write-Info "    → Allowing POP3 (110)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-POP3-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 110 `
        -Profile Any -Enabled True | Out-Null
    
    # POP3S (995)
    Write-Info "    → Allowing POP3S (995)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-POP3S-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 995 `
        -Profile Any -Enabled True | Out-Null
    
    # IMAP (143) - NO RATE LIMITING
    Write-Info "    → Allowing IMAP (143)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-IMAP-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 143 `
        -Profile Any -Enabled True | Out-Null
    
    # IMAPS (993)
    Write-Info "    → Allowing IMAPS (993)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-IMAPS-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 993 `
        -Profile Any -Enabled True | Out-Null
    
    # Exchange Web Services (if Exchange detected)
    if (Get-Service -Name MSExchangeTransport -ErrorAction SilentlyContinue) {
        Write-Info "    → Allowing Exchange ports..."
        
        # Outlook Anywhere (RPC over HTTP)
        New-NetFirewallRule -DisplayName "CCDC-Allow-Exchange-RPC-In" `
            -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort 135,6001-6004 `
            -Profile Any -Enabled True | Out-Null
    }
    
    Write-Success "  ✓ Mail server rules applied (25, 587, 110, 995, 143, 993)"
}

# DNS Server rules
function Add-DNSServerRules {
    Write-Info "  → Configuring DNS server rules..."
    
    # DNS (53) TCP/UDP - SCORED SERVICE
    Write-Info "    → Allowing DNS (53 TCP/UDP)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-DNS-UDP-In" `
        -Direction Inbound -Action Allow `
        -Protocol UDP -LocalPort 53 `
        -Profile Any -Enabled True | Out-Null
    
    New-NetFirewallRule -DisplayName "CCDC-Allow-DNS-TCP-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 53 `
        -Profile Any -Enabled True | Out-Null
    
    New-NetFirewallRule -DisplayName "CCDC-Allow-DNS-UDP-Out" `
        -Direction Outbound -Action Allow `
        -Protocol UDP -RemotePort 53 `
        -Profile Any -Enabled True | Out-Null
    
    New-NetFirewallRule -DisplayName "CCDC-Allow-DNS-TCP-Out" `
        -Direction Outbound -Action Allow `
        -Protocol TCP -RemotePort 53 `
        -Profile Any -Enabled True | Out-Null
    
    Write-Success "  ✓ DNS server rules applied (53 TCP/UDP)"
}

# Active Directory Domain Controller rules
function Add-DomainControllerRules {
    Write-Info "  → Configuring DOMAIN CONTROLLER rules..."
    
    # Kerberos (88)
    Write-Info "    → Allowing Kerberos (88)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-Kerberos-TCP-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 88 `
        -Profile Any -Enabled True | Out-Null
    
    New-NetFirewallRule -DisplayName "CCDC-Allow-Kerberos-UDP-In" `
        -Direction Inbound -Action Allow `
        -Protocol UDP -LocalPort 88 `
        -Profile Any -Enabled True | Out-Null
    
    # LDAP (389)
    Write-Info "    → Allowing LDAP (389)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-LDAP-TCP-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 389 `
        -Profile Any -Enabled True | Out-Null
    
    New-NetFirewallRule -DisplayName "CCDC-Allow-LDAP-UDP-In" `
        -Direction Inbound -Action Allow `
        -Protocol UDP -LocalPort 389 `
        -Profile Any -Enabled True | Out-Null
    
    # LDAPS (636)
    Write-Info "    → Allowing LDAPS (636)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-LDAPS-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 636 `
        -Profile Any -Enabled True | Out-Null
    
    # Global Catalog (3268, 3269)
    Write-Info "    → Allowing Global Catalog (3268, 3269)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-GC-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 3268,3269 `
        -Profile Any -Enabled True | Out-Null
    
    # SMB/CIFS (445) - Required for AD
    Write-Info "    → Allowing SMB (445) for AD..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-SMB-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 445 `
        -Profile Any -Enabled True | Out-Null
    
    # RPC Endpoint Mapper (135)
    Write-Info "    → Allowing RPC (135)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-RPC-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 135 `
        -Profile Any -Enabled True | Out-Null
    
    # RPC Dynamic Ports (49152-65535)
    Write-Info "    → Allowing RPC Dynamic Ports..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-RPC-Dynamic-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 49152-65535 `
        -Profile Any -Enabled True | Out-Null
    
    Write-Success "  ✓ Domain Controller rules applied"
}

# SQL Server rules
function Add-SQLServerRules {
    Write-Info "  → Configuring SQL SERVER rules..."
    
    # SQL Server (1433)
    Write-Info "    → Allowing SQL Server (1433)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-SQL-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 1433 `
        -Profile Any -Enabled True | Out-Null
    
    # SQL Browser (1434)
    Write-Info "    → Allowing SQL Browser (1434)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-SQL-Browser-In" `
        -Direction Inbound -Action Allow `
        -Protocol UDP -LocalPort 1434 `
        -Profile Any -Enabled True | Out-Null
    
    Write-Success "  ✓ SQL Server rules applied (1433, 1434)"
}

# FTP Server rules
function Add-FTPServerRules {
    Write-Info "  → Configuring FTP server rules..."
    
    # FTP Control (21)
    Write-Info "    → Allowing FTP (21)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-FTP-Control-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 21 `
        -Profile Any -Enabled True | Out-Null
    
    # FTP Passive Mode (1024-65535)
    Write-Info "    → Allowing FTP Passive Mode..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-FTP-Passive-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 1024-65535 `
        -Profile Any -Enabled True | Out-Null
    
    # FTPS (990)
    Write-Info "    → Allowing FTPS (990)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-FTPS-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 990 `
        -Profile Any -Enabled True | Out-Null
    
    Write-Success "  ✓ FTP server rules applied (21, 990, passive)"
}

# Generic rules (if no specific role detected)
function Add-GenericRules {
    Write-Info "  → Configuring GENERIC rules..."
    
    # HTTP, HTTPS
    Write-Info "    → Allowing HTTP (80)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-HTTP-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 80 `
        -Profile Any -Enabled True | Out-Null
    
    Write-Info "    → Allowing HTTPS (443)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-HTTPS-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 443 `
        -Profile Any -Enabled True | Out-Null
    
    # SMB (445) - Common in Windows environments
    Write-Info "    → Allowing SMB (445)..."
    New-NetFirewallRule -DisplayName "CCDC-Allow-SMB-In" `
        -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort 445 `
        -Profile Any -Enabled True | Out-Null
    
    Write-Success "  ✓ Generic rules applied (80, 443, 445)"
}

# Apply service-specific rules based on detected roles
function Add-ServiceRules {
    param($Roles)
    
    Write-Info "Applying service-specific rules..."
    
    foreach ($role in $Roles) {
        switch ($role) {
            "web" { Add-WebServerRules }
            "mail" { Add-MailServerRules }
            "dns" { Add-DNSServerRules }
            "dc" { Add-DomainControllerRules }
            "sql" { Add-SQLServerRules }
            "ftp" { Add-FTPServerRules }
            "generic" { Add-GenericRules }
        }
    }
}

# Block dangerous ports (attack vectors)
function Add-BlockRules {
    Write-Info "Blocking dangerous ports (attack vectors)..."
    
    # Block Telnet (23) - use SSH/RDP instead
    New-NetFirewallRule -DisplayName "CCDC-Block-Telnet" `
        -Direction Inbound -Action Block `
        -Protocol TCP -LocalPort 23 `
        -Profile Any -Enabled True | Out-Null
    
    # Block TFTP (69) - insecure
    New-NetFirewallRule -DisplayName "CCDC-Block-TFTP" `
        -Direction Inbound -Action Block `
        -Protocol UDP -LocalPort 69 `
        -Profile Any -Enabled True | Out-Null
    
    # Block common backdoor ports
    $backdoorPorts = @(4444, 4445, 31337, 12345, 6666, 6667)
    foreach ($port in $backdoorPorts) {
        New-NetFirewallRule -DisplayName "CCDC-Block-Backdoor-$port" `
            -Direction Inbound -Action Block `
            -Protocol TCP -LocalPort $port `
            -Profile Any -Enabled True | Out-Null
        
        New-NetFirewallRule -DisplayName "CCDC-Block-Backdoor-Out-$port" `
            -Direction Outbound -Action Block `
            -Protocol TCP -RemotePort $port `
            -Profile Any -Enabled True | Out-Null
    }
    
    Write-Success "Dangerous ports blocked (23, 69, backdoor ports)"
}

# Enable Windows Defender Firewall logging
function Enable-FirewallLogging {
    Write-Info "Enabling enhanced firewall logging..."
    
    try {
        # Enable logging for all profiles
        Set-NetFirewallProfile -Profile Domain,Public,Private `
            -LogAllowed True `
            -LogBlocked True `
            -LogFileName "C:\CCDC\Logs\pfirewall.log" `
            -LogMaxSizeKilobytes 32767
        
        # Enable connection security logging
        auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable | Out-Null
        
        Write-Success "Firewall logging enabled"
        Write-Info "  Log file: C:\CCDC\Logs\pfirewall.log"
        Write-Info "  Security events: Event Viewer > Windows Logs > Security"
    }
    catch {
        Write-Warning "Failed to enable advanced logging: $_"
    }
}

# Create management scripts
function Create-ManagementScripts {
    Write-Info "Creating firewall management scripts..."
    
    # Show firewall rules script
    $showRulesScript = @'
# Show Windows Firewall Rules
Write-Host "=== WINDOWS FIREWALL RULES ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "CCDC Firewall Rules:" -ForegroundColor Yellow
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "CCDC-*" } | 
    Format-Table DisplayName, Direction, Action, Enabled, Profile -AutoSize
Write-Host ""
Write-Host "All Firewall Rules:" -ForegroundColor Yellow
Get-NetFirewallRule | Format-Table DisplayName, Direction, Action, Enabled -AutoSize
'@
    $showRulesScript | Out-File -FilePath (Join-Path $ScriptsPath "Show-FirewallRules.ps1") -Encoding UTF8
    
    # Temporarily allow port script
    $allowPortScript = @'
param(
    [Parameter(Mandatory=$true)]
    [int]$Port,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("TCP", "UDP")]
    [string]$Protocol
)

Write-Host "Adding temporary rule to allow $Protocol/$Port..." -ForegroundColor Yellow

New-NetFirewallRule -DisplayName "CCDC-Temp-Allow-$Protocol-$Port" `
    -Direction Inbound -Action Allow `
    -Protocol $Protocol -LocalPort $Port `
    -Profile Any -Enabled True

Write-Host "Rule added successfully!" -ForegroundColor Green
Write-Host "To remove: Remove-NetFirewallRule -DisplayName 'CCDC-Temp-Allow-$Protocol-$Port'" -ForegroundColor Cyan
'@
    $allowPortScript | Out-File -FilePath (Join-Path $ScriptsPath "Allow-Port-Temp.ps1") -Encoding UTF8
    
    # Monitor blocked connections script
    $monitorScript = @'
# Monitor Blocked Connections
Write-Host "Monitoring firewall blocks (Ctrl+C to stop)..." -ForegroundColor Cyan
Write-Host ""

Get-Content "C:\CCDC\Logs\pfirewall.log" -Wait | 
    Where-Object { $_ -match "DROP" } |
    ForEach-Object {
        Write-Host $_ -ForegroundColor Red
    }
'@
    $monitorScript | Out-File -FilePath (Join-Path $ScriptsPath "Monitor-Blocks.ps1") -Encoding UTF8
    
    # Emergency disable script
    $disableScript = @'
Write-Host "WARNING: This will DISABLE Windows Firewall" -ForegroundColor Red
Write-Host "Press Ctrl+C to cancel, or wait 5 seconds to continue..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

Write-Host "Backing up current rules..." -ForegroundColor Yellow
netsh advfirewall export "C:\CCDC\Backups\Firewall\emergency-backup-$(Get-Date -Format 'yyyyMMdd_HHmmss').wfw"

Write-Host "Disabling firewall..." -ForegroundColor Yellow
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

Write-Host "FIREWALL DISABLED - System is UNPROTECTED!" -ForegroundColor Red
Write-Host "To restore: Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True" -ForegroundColor Cyan
'@
    $disableScript | Out-File -FilePath (Join-Path $ScriptsPath "Disable-Firewall-EMERGENCY.ps1") -Encoding UTF8
    
    # Restore from backup script
    $restoreScript = @'
$backups = Get-ChildItem "C:\CCDC\Backups\Firewall\*.wfw" | Sort-Object LastWriteTime -Descending | Select-Object -First 10
Write-Host "Available backups:" -ForegroundColor Cyan
$backups | Format-Table Name, LastWriteTime

$backup = Read-Host "Enter backup filename to restore"
$fullPath = "C:\CCDC\Backups\Firewall\$backup"

if (Test-Path $fullPath) {
    Write-Host "Restoring from $backup..." -ForegroundColor Yellow
    netsh advfirewall import "$fullPath"
    Write-Host "Firewall restored!" -ForegroundColor Green
} else {
    Write-Host "Backup not found!" -ForegroundColor Red
}
'@
    $restoreScript | Out-File -FilePath (Join-Path $ScriptsPath "Restore-Firewall.ps1") -Encoding UTF8
    
    Write-Success "Management scripts created in: $ScriptsPath"
}

# Display summary
function Show-Summary {
    param($Roles)
    
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Success "Windows Firewall Configuration Complete!"
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "CONFIGURATION SUMMARY:" -ForegroundColor Yellow
    Write-Host "  Detected Roles: $($Roles -join ', ')"
    Write-Host "  Default Policy: BLOCK (all profiles)"
    Write-Host ""
    Write-Host "  Allowed Services:" -ForegroundColor Yellow
    Write-Host "    - RDP (3389) - Team Management"
    Write-Host "    - WinRM (5985, 5986) - Remote Management"
    Write-Host "    - ICMP (Ping) - REQUIRED FOR SCORING"
    
    foreach ($role in $Roles) {
        Write-Host ""
        switch ($role) {
            "web" {
                Write-Host "    WEB SERVER:" -ForegroundColor Green
                Write-Host "      - HTTP (80) - SCORED SERVICE"
                Write-Host "      - HTTPS (443) - SCORED SERVICE"
            }
            "mail" {
                Write-Host "    MAIL SERVER:" -ForegroundColor Green
                Write-Host "      - SMTP (25, 587, 465) - SCORED SERVICE"
                Write-Host "      - POP3 (110, 995) - SCORED SERVICE"
                Write-Host "      - IMAP (143, 993)"
            }
            "dns" {
                Write-Host "    DNS SERVER:" -ForegroundColor Green
                Write-Host "      - DNS (53 TCP/UDP) - SCORED SERVICE"
            }
            "dc" {
                Write-Host "    DOMAIN CONTROLLER:" -ForegroundColor Green
                Write-Host "      - Kerberos (88)"
                Write-Host "      - LDAP/LDAPS (389, 636)"
                Write-Host "      - Global Catalog (3268, 3269)"
                Write-Host "      - SMB (445)"
                Write-Host "      - RPC (135, 49152-65535)"
            }
            "sql" {
                Write-Host "    SQL SERVER:" -ForegroundColor Green
                Write-Host "      - SQL Server (1433)"
                Write-Host "      - SQL Browser (1434)"
            }
            "ftp" {
                Write-Host "    FTP SERVER:" -ForegroundColor Green
                Write-Host "      - FTP (21, 990)"
                Write-Host "      - FTP Passive (1024-65535)"
            }
            "generic" {
                Write-Host "    GENERIC:" -ForegroundColor Green
                Write-Host "      - HTTP (80, 443)"
                Write-Host "      - SMB (445)"
            }
        }
    }
    
    Write-Host ""
    Write-Host "  Protection Features:" -ForegroundColor Yellow
    Write-Host "    ✓ Default BLOCK policy"
    Write-Host "    ✓ Dangerous ports blocked (Telnet, TFTP, backdoors)"
    Write-Host "    ✓ NetBIOS blocked (attack vector)"
    Write-Host "    ✓ Extensive logging enabled"
    Write-Host "    ✓ All profiles protected (Domain, Public, Private)"
    Write-Host ""
    Write-Host "  Management Scripts:" -ForegroundColor Yellow
    Write-Host "    $ScriptsPath\Show-FirewallRules.ps1"
    Write-Host "    $ScriptsPath\Allow-Port-Temp.ps1"
    Write-Host "    $ScriptsPath\Monitor-Blocks.ps1"
    Write-Host "    $ScriptsPath\Restore-Firewall.ps1"
    Write-Host "    $ScriptsPath\Disable-Firewall-EMERGENCY.ps1"
    Write-Host ""
    Write-Host "  Backups:" -ForegroundColor Yellow
    Write-Host "    $BackupPath"
    Write-Host ""
    Write-Host "  Logs:" -ForegroundColor Yellow
    Write-Host "    $LogFile"
    Write-Host "    C:\CCDC\Logs\pfirewall.log"
    Write-Host ""
    Write-Host "IMPORTANT REMINDERS:" -ForegroundColor Red
    Write-Host "  - Test ALL scored services immediately!"
    Write-Host "  - Check Event Viewer > Security for firewall events"
    Write-Host "  - Monitor: C:\CCDC\Logs\pfirewall.log"
    Write-Host "  - Rules persist across reboots"
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
}

# Main execution
function Main {
    Clear-Host
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "           CCDC Competition Windows Firewall Hardening" -ForegroundColor Cyan
    Write-Host "           2026 Midwest CCDC Qualifier" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Warning "This will REPLACE all existing firewall rules!"
    Write-Host ""
    Write-Host "This script will:"
    Write-Host "  - Set default BLOCK policy on all profiles"
    Write-Host "  - Detect running services automatically"
    Write-Host "  - Allow only required ports per service"
    Write-Host "  - Enable extensive logging for incident response"
    Write-Host "  - Block dangerous ports and protocols"
    Write-Host ""
    
    $confirm = Read-Host "Continue? [y/N]"
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-Host "Aborted by user" -ForegroundColor Yellow
        exit 0
    }
    
    Write-Host ""
    Write-Info "Starting Windows Firewall configuration..."
    Write-Host ""
    
    # Execute configuration
    Backup-FirewallRules
    $systemRoles = Get-SystemRoles
    Write-Host ""
    
    Enable-WindowsFirewall
    Remove-AllFirewallRules
    Set-DefaultBlockPolicy
    Add-BaseRules
    Add-ManagementRules
    Add-ServiceRules -Roles $systemRoles
    Add-BlockRules
    Enable-FirewallLogging
    Create-ManagementScripts
    
    Show-Summary -Roles $systemRoles
    
    Write-Host "NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "1. Test all services immediately"
    Write-Host "2. Check Event Viewer > Security for firewall events"
    Write-Host "3. Monitor logs: Get-Content C:\CCDC\Logs\pfirewall.log -Wait"
    Write-Host "4. If service fails, use: .\Allow-Port-Temp.ps1 -Port <port> -Protocol TCP"
    Write-Host ""
    
    Read-Host "Press Enter to exit"
}

# Run main function
Main
