<#
.SYNOPSIS
    CCDC Windows AD Server Reconnaissance Script
.DESCRIPTION
    Gathers critical Active Directory, DNS, and DHCP information
    Run this FIRST to understand the environment
.NOTES
    Target: Windows Server 2019 (AD/DNS/DHCP)
    Run as: Domain Administrator
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"
$ReportPath = "C:\CCDC-Logs"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile = "$ReportPath\AD_Recon_$Timestamp.txt"

# Create log directory
New-Item -ItemType Directory -Force -Path $ReportPath | Out-Null

function Write-Section {
    param([string]$Title)
    $separator = "=" * 60
    "`n$separator" | Tee-Object -FilePath $ReportFile -Append
    "=== $Title" | Tee-Object -FilePath $ReportFile -Append
    "$separator" | Tee-Object -FilePath $ReportFile -Append
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CCDC AD Server Reconnaissance" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Report will be saved to: $ReportFile"
Write-Host ""

# System Information
Write-Section "SYSTEM INFORMATION"
"Hostname: $env:COMPUTERNAME" | Tee-Object -FilePath $ReportFile -Append
"Domain: $env:USERDNSDOMAIN" | Tee-Object -FilePath $ReportFile -Append
"Current User: $env:USERNAME" | Tee-Object -FilePath $ReportFile -Append
"OS Version:" | Tee-Object -FilePath $ReportFile -Append
(Get-WmiObject Win32_OperatingSystem).Caption | Tee-Object -FilePath $ReportFile -Append
"" | Tee-Object -FilePath $ReportFile -Append
"IP Configuration:" | Tee-Object -FilePath $ReportFile -Append
Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne "127.0.0.1"} |
    Format-Table InterfaceAlias, IPAddress, PrefixLength | Out-String | Tee-Object -FilePath $ReportFile -Append

# Domain Information
Write-Section "ACTIVE DIRECTORY DOMAIN INFO"
try {
    Import-Module ActiveDirectory
    $domain = Get-ADDomain
    "Domain Name: $($domain.DNSRoot)" | Tee-Object -FilePath $ReportFile -Append
    "NetBIOS Name: $($domain.NetBIOSName)" | Tee-Object -FilePath $ReportFile -Append
    "Forest: $($domain.Forest)" | Tee-Object -FilePath $ReportFile -Append
    "Domain Functional Level: $($domain.DomainMode)" | Tee-Object -FilePath $ReportFile -Append
    "PDC Emulator: $($domain.PDCEmulator)" | Tee-Object -FilePath $ReportFile -Append
    "Infrastructure Master: $($domain.InfrastructureMaster)" | Tee-Object -FilePath $ReportFile -Append
} catch {
    "ERROR: Could not load Active Directory module" | Tee-Object -FilePath $ReportFile -Append
}

# Domain Controllers
Write-Section "DOMAIN CONTROLLERS"
try {
    Get-ADDomainController -Filter * | Format-Table Name, IPv4Address, Site, IsGlobalCatalog, OperatingSystem |
        Out-String | Tee-Object -FilePath $ReportFile -Append
} catch {
    "Could not enumerate domain controllers" | Tee-Object -FilePath $ReportFile -Append
}

# Domain Admins
Write-Section "DOMAIN ADMINS (CRITICAL!)"
try {
    "Domain Admins Group Members:" | Tee-Object -FilePath $ReportFile -Append
    Get-ADGroupMember -Identity "Domain Admins" -Recursive |
        Format-Table Name, SamAccountName, ObjectClass | Out-String | Tee-Object -FilePath $ReportFile -Append

    "Enterprise Admins Group Members:" | Tee-Object -FilePath $ReportFile -Append
    Get-ADGroupMember -Identity "Enterprise Admins" -Recursive 2>$null |
        Format-Table Name, SamAccountName, ObjectClass | Out-String | Tee-Object -FilePath $ReportFile -Append

    "Schema Admins Group Members:" | Tee-Object -FilePath $ReportFile -Append
    Get-ADGroupMember -Identity "Schema Admins" -Recursive 2>$null |
        Format-Table Name, SamAccountName, ObjectClass | Out-String | Tee-Object -FilePath $ReportFile -Append

    "Administrators Group Members:" | Tee-Object -FilePath $ReportFile -Append
    Get-ADGroupMember -Identity "Administrators" -Recursive |
        Format-Table Name, SamAccountName, ObjectClass | Out-String | Tee-Object -FilePath $ReportFile -Append
} catch {
    "Could not enumerate admin groups" | Tee-Object -FilePath $ReportFile -Append
}

# All Users
Write-Section "ALL DOMAIN USERS"
try {
    $users = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, AdminCount
    "Total Users: $($users.Count)" | Tee-Object -FilePath $ReportFile -Append
    "Enabled Users: $(($users | Where-Object {$_.Enabled -eq $true}).Count)" | Tee-Object -FilePath $ReportFile -Append
    "Disabled Users: $(($users | Where-Object {$_.Enabled -eq $false}).Count)" | Tee-Object -FilePath $ReportFile -Append
    "" | Tee-Object -FilePath $ReportFile -Append
    "Users with AdminCount=1 (privileged):" | Tee-Object -FilePath $ReportFile -Append
    $users | Where-Object {$_.AdminCount -eq 1} |
        Format-Table Name, SamAccountName, Enabled, PasswordNeverExpires | Out-String | Tee-Object -FilePath $ReportFile -Append
} catch {
    "Could not enumerate users" | Tee-Object -FilePath $ReportFile -Append
}

# Service Accounts
Write-Section "SERVICE ACCOUNTS"
try {
    "Accounts with ServicePrincipalName (Kerberoastable):" | Tee-Object -FilePath $ReportFile -Append
    Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName |
        Format-Table Name, SamAccountName, ServicePrincipalName | Out-String | Tee-Object -FilePath $ReportFile -Append
} catch {
    "Could not check service accounts" | Tee-Object -FilePath $ReportFile -Append
}

# Computers
Write-Section "DOMAIN COMPUTERS"
try {
    Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate |
        Format-Table Name, OperatingSystem, Enabled, LastLogonDate | Out-String | Tee-Object -FilePath $ReportFile -Append
} catch {
    "Could not enumerate computers" | Tee-Object -FilePath $ReportFile -Append
}

# Group Policy Objects
Write-Section "GROUP POLICY OBJECTS"
try {
    Import-Module GroupPolicy
    Get-GPO -All | Format-Table DisplayName, GpoStatus, CreationTime, ModificationTime |
        Out-String | Tee-Object -FilePath $ReportFile -Append
} catch {
    "Could not enumerate GPOs" | Tee-Object -FilePath $ReportFile -Append
}

# Local Administrators
Write-Section "LOCAL ADMINISTRATORS ON THIS SERVER"
try {
    Get-LocalGroupMember -Group "Administrators" |
        Format-Table Name, ObjectClass, PrincipalSource | Out-String | Tee-Object -FilePath $ReportFile -Append
} catch {
    "Could not enumerate local admins" | Tee-Object -FilePath $ReportFile -Append
}

# Scheduled Tasks
Write-Section "SCHEDULED TASKS (Non-Microsoft)"
try {
    Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft\*"} |
        Format-Table TaskName, TaskPath, State, Author | Out-String | Tee-Object -FilePath $ReportFile -Append
} catch {
    "Could not enumerate scheduled tasks" | Tee-Object -FilePath $ReportFile -Append
}

# Running Services
Write-Section "RUNNING SERVICES (Non-Microsoft)"
try {
    Get-Service | Where-Object {$_.Status -eq 'Running'} |
        Where-Object {$_.DisplayName -notlike "Windows*" -and $_.DisplayName -notlike "Microsoft*"} |
        Format-Table Name, DisplayName, StartType | Out-String | Tee-Object -FilePath $ReportFile -Append
} catch {
    "Could not enumerate services" | Tee-Object -FilePath $ReportFile -Append
}

# DNS Configuration
Write-Section "DNS SERVER CONFIGURATION"
try {
    Import-Module DnsServer
    "DNS Zones:" | Tee-Object -FilePath $ReportFile -Append
    Get-DnsServerZone | Format-Table ZoneName, ZoneType, IsDsIntegrated |
        Out-String | Tee-Object -FilePath $ReportFile -Append

    "DNS Forwarders:" | Tee-Object -FilePath $ReportFile -Append
    Get-DnsServerForwarder | Out-String | Tee-Object -FilePath $ReportFile -Append
} catch {
    "DNS Server role not installed or accessible" | Tee-Object -FilePath $ReportFile -Append
}

# DHCP Configuration
Write-Section "DHCP SERVER CONFIGURATION"
try {
    Import-Module DhcpServer
    "DHCP Scopes:" | Tee-Object -FilePath $ReportFile -Append
    Get-DhcpServerv4Scope | Format-Table ScopeId, Name, State, StartRange, EndRange |
        Out-String | Tee-Object -FilePath $ReportFile -Append

    "DHCP Leases:" | Tee-Object -FilePath $ReportFile -Append
    Get-DhcpServerv4Scope | ForEach-Object {
        Get-DhcpServerv4Lease -ScopeId $_.ScopeId
    } | Format-Table IPAddress, HostName, ClientId | Out-String | Tee-Object -FilePath $ReportFile -Append
} catch {
    "DHCP Server role not installed or accessible" | Tee-Object -FilePath $ReportFile -Append
}

# Firewall Status
Write-Section "WINDOWS FIREWALL STATUS"
Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
    Out-String | Tee-Object -FilePath $ReportFile -Append

# Open Ports
Write-Section "LISTENING PORTS"
Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress, LocalPort, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |
    Sort-Object LocalPort | Format-Table | Out-String | Tee-Object -FilePath $ReportFile -Append

# Recent Security Events
Write-Section "RECENT SECURITY EVENTS (Last 20)"
try {
    Get-WinEvent -LogName Security -MaxEvents 20 |
        Format-Table TimeCreated, Id, Message -Wrap | Out-String | Tee-Object -FilePath $ReportFile -Append
} catch {
    "Could not read security log" | Tee-Object -FilePath $ReportFile -Append
}

# Password Policy
Write-Section "DOMAIN PASSWORD POLICY"
try {
    Get-ADDefaultDomainPasswordPolicy | Out-String | Tee-Object -FilePath $ReportFile -Append
} catch {
    "Could not get password policy" | Tee-Object -FilePath $ReportFile -Append
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Reconnaissance Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Report saved to: $ReportFile" -ForegroundColor Yellow
Write-Host ""
Write-Host "KEY ITEMS TO REVIEW:" -ForegroundColor Red
Write-Host "  - Unknown Domain Admins"
Write-Host "  - Accounts with PasswordNeverExpires"
Write-Host "  - Service accounts (Kerberoastable)"
Write-Host "  - Suspicious scheduled tasks"
Write-Host "  - Unauthorized GPOs"
Write-Host ""
