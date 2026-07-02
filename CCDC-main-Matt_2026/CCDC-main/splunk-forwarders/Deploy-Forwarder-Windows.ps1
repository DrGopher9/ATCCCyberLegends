<#
.SYNOPSIS
    CCDC Splunk Universal Forwarder - Windows Deployment Script
.DESCRIPTION
    Deploys and configures Splunk Universal Forwarder on Windows servers
.NOTES
    Run as: Administrator
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Splunk Universal Forwarder Deployment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

#-------------------------------------------------------------------------------
# Configuration
#-------------------------------------------------------------------------------

$SplunkIndexer = Read-Host "Enter Splunk Indexer IP/hostname"
$SplunkPort = Read-Host "Enter Splunk receiving port [9997]"
if ([string]::IsNullOrEmpty($SplunkPort)) { $SplunkPort = "9997" }

$AdminPass = Read-Host "Enter admin password for forwarder" -AsSecureString
$AdminPassPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdminPass))

$SplunkHome = "C:\Program Files\SplunkUniversalForwarder"

#-------------------------------------------------------------------------------
Write-Host ""
Write-Host "[*] Checking for existing installation..." -ForegroundColor Yellow

if (Test-Path $SplunkHome) {
    Write-Host "[!] Splunk Forwarder already installed" -ForegroundColor Yellow
    $reconfig = Read-Host "Reconfigure existing installation? (y/N)"
    if ($reconfig -ne "y") { exit }
} else {
    #---------------------------------------------------------------------------
    Write-Host ""
    Write-Host "[*] Download Instructions:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. Go to: https://www.splunk.com/en_us/download/universal-forwarder.html"
    Write-Host "2. Download Windows 64-bit MSI"
    Write-Host "3. Save to C:\Temp\splunkforwarder.msi"
    Write-Host ""

    $msiPath = Read-Host "Path to downloaded MSI (or press Enter for C:\Temp\splunkforwarder.msi)"
    if ([string]::IsNullOrEmpty($msiPath)) { $msiPath = "C:\Temp\splunkforwarder.msi" }

    if (!(Test-Path $msiPath)) {
        Write-Host "[!] MSI file not found: $msiPath" -ForegroundColor Red
        exit 1
    }

    #---------------------------------------------------------------------------
    Write-Host ""
    Write-Host "[*] Installing Splunk Universal Forwarder..." -ForegroundColor Yellow

    # Install with configuration
    $installArgs = @(
        "/i"
        "`"$msiPath`""
        "AGREETOLICENSE=yes"
        "RECEIVING_INDEXER=`"$SplunkIndexer`:$SplunkPort`""
        "SPLUNKUSERNAME=admin"
        "SPLUNKPASSWORD=$AdminPassPlain"
        "WINEVENTLOG_APP_ENABLE=1"
        "WINEVENTLOG_SEC_ENABLE=1"
        "WINEVENTLOG_SYS_ENABLE=1"
        "WINEVENTLOG_FWD_ENABLE=1"
        "WINEVENTLOG_SET_ENABLE=1"
        "ENABLEADMON=1"
        "/quiet"
    )

    Start-Process msiexec.exe -ArgumentList $installArgs -Wait -NoNewWindow

    Write-Host "[+] Installation complete" -ForegroundColor Green
}

#-------------------------------------------------------------------------------
Write-Host ""
Write-Host "[*] Configuring outputs..." -ForegroundColor Yellow

$outputsConf = @"
[tcpout]
defaultGroup = ccdc-indexers

[tcpout:ccdc-indexers]
server = $SplunkIndexer`:$SplunkPort

[tcpout-server://$SplunkIndexer`:$SplunkPort]
"@

$outputsPath = "$SplunkHome\etc\system\local\outputs.conf"
$outputsConf | Out-File -FilePath $outputsPath -Encoding ASCII -Force
Write-Host "[+] Outputs configured" -ForegroundColor Green

#-------------------------------------------------------------------------------
Write-Host ""
Write-Host "[*] Configuring inputs..." -ForegroundColor Yellow

$inputsConf = @"
# CCDC Windows Universal Forwarder Inputs
[default]
host = $env:COMPUTERNAME

# Windows Event Logs
[WinEventLog://Application]
disabled = false
index = main

[WinEventLog://Security]
disabled = false
index = main

[WinEventLog://System]
disabled = false
index = main

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
index = main
renderXml = true

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = false
index = main

[WinEventLog://Microsoft-Windows-WMI-Activity/Operational]
disabled = false
index = main

[WinEventLog://Microsoft-Windows-TaskScheduler/Operational]
disabled = false
index = main

# Active Directory (if DC)

[WinEventLog://Directory Service]
disabled = false
index = main

[WinEventLog://DNS Server]
disabled = false
index = main

# DHCP (if DHCP server)
[monitor://C:\Windows\System32\dhcp\DhcpSrvLog*.log]
disabled = false
index = main
sourcetype = dhcp

# IIS Logs (if web server)
[monitor://C:\inetpub\logs\LogFiles\...]
disabled = true
index = main
sourcetype = iis
"@

$inputsPath = "$SplunkHome\etc\system\local\inputs.conf"
$inputsConf | Out-File -FilePath $inputsPath -Encoding ASCII -Force
Write-Host "[+] Inputs configured" -ForegroundColor Green

#-------------------------------------------------------------------------------
Write-Host ""
Write-Host "[*] Restarting Splunk Forwarder..." -ForegroundColor Yellow

& "$SplunkHome\bin\splunk.exe" restart

Start-Sleep -Seconds 10

#-------------------------------------------------------------------------------
Write-Host ""
Write-Host "[*] Checking forwarder status..." -ForegroundColor Yellow

& "$SplunkHome\bin\splunk.exe" status

#-------------------------------------------------------------------------------
Write-Host ""
Write-Host "[*] Testing connection to indexer..." -ForegroundColor Yellow

try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $tcpClient.Connect($SplunkIndexer, [int]$SplunkPort)
    $tcpClient.Close()
    Write-Host "[+] Connection to $SplunkIndexer`:$SplunkPort successful" -ForegroundColor Green
} catch {
    Write-Host "[-] Cannot connect to $SplunkIndexer`:$SplunkPort" -ForegroundColor Red
    Write-Host "    Check firewall rules on both forwarder and indexer"
}

#-------------------------------------------------------------------------------
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Splunk Forwarder Deployment Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Forwarder Home: $SplunkHome"
Write-Host "Forwarding to: $SplunkIndexer`:$SplunkPort"
Write-Host ""
Write-Host "COMMANDS:" -ForegroundColor Yellow
Write-Host "  & `"$SplunkHome\bin\splunk.exe`" status"
Write-Host "  & `"$SplunkHome\bin\splunk.exe`" restart"
Write-Host "  & `"$SplunkHome\bin\splunk.exe`" list forward-server"
Write-Host ""
Write-Host "VERIFY ON INDEXER:" -ForegroundColor Cyan
Write-Host "  Search: index=* host=$env:COMPUTERNAME | head 10"
Write-Host ""
