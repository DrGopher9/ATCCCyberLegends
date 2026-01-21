# Define constants
$NewPassword = "ATCCccdc2025!"
$FirewallAllowedPorts = @(80, 443, 53, 8000)
$UserLogPath = "C:\UserAuditLog.txt"
$ServiceLogPath = "C:\DisabledServicesLog.txt"

# Gather all local users and log them
Write-Output "Gathering and logging all local users..."
net user
$Users = net user | ForEach-Object { ($_ -split '\s{2,}')[0] } | Where-Object { $_ -notmatch "^(User|accounts|-----)$" }
foreach ($User in $Users) {
    Add-Content -Path $UserLogPath -Value "User: $User"
}

# Reset passwords for all users
#foreach ($User in $Users) {
#    Write-Output "Resetting password for user: $User"
#    net user $User $NewPassword
#}

# Revoke login certificates and tokens
Write-Output "Revoking login certificates and tokens..."
$certStore = Get-ChildItem Cert:\LocalMachine\My
$certStore | ForEach-Object {
    Write-Output "Revoking certificate: $($_.Subject)"
    Remove-Item $_.PSPath -Force
}

# Configure and enable Windows Firewall
Write-Output "Configuring Windows Firewall..."
New-NetFirewallRule -DisplayName "Allow HTTP" -Direction Outbound -Protocol TCP -RemotePort 80 -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Allow HTTPS" -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Allow DNS" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Allow Splunk Port" -Direction Outbound -Protocol TCP -RemotePort 8000 -Action Allow -ErrorAction SilentlyContinue

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Block

# Enable audit logging
Write-Output "Enabling audit logging..."
AuditPol /set /category:* /success:enable /failure:enable

# Disable unused services and log them
Write-Output "Disabling unnecessary services..."
$DisableServices = @("wuauserv", "bits")
foreach ($service in $DisableServices) {
    Write-Output "Disabling service: $service"
    Add-Content -Path $ServiceLogPath -Value "Disabled service: $service"
    Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
}

# Disable unused protocols (e.g., SMBv1)
Write-Output "Disabling SMBv1..."
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Remove rogue scheduled tasks
Write-Output "Checking for unauthorized scheduled tasks..."
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"} | ForEach-Object {
    Write-Output "Removing rogue scheduled task: $($_.TaskName)"
    Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false
}

# Remove suspicious startup programs
Write-Output "Checking and removing startup programs..."
$StartupLocations = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($loc in $StartupLocations) {
    Get-ItemProperty -Path $loc | ForEach-Object {
        Write-Output "Removing startup entry: $($_.PSChildName)"
        Remove-ItemProperty -Path $loc -Name $_.PSChildName -ErrorAction SilentlyContinue
    }
}

# Set secure DNS settings
Write-Output "Setting secure DNS..."
Set-DnsClientServerAddress -InterfaceAlias "Ethernet*" -ServerAddresses @("8.8.8.8", "8.8.4.4")

# Disable File Sharing and Network Discovery
Write-Output "Disabling File Sharing and Network Discovery..."

# Disable File and Printer Sharing through Firewall
Write-Output "Disabling File and Printer Sharing through Firewall..."
Disable-NetAdapterBinding -Name "*" -ComponentID ms_server -ErrorAction SilentlyContinue

# Remove Administrative Shares
Write-Output "Removing administrative shares..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Value 0 -Force

# Disable Network Discovery
Write-Output "Disabling Network Discovery..."
Set-Service -Name "fdPHost" -StartupType Disabled -ErrorAction SilentlyContinue
Set-Service -Name "fdResPub" -StartupType Disabled -ErrorAction SilentlyContinue
Set-Service -Name "upnphost" -StartupType Disabled -ErrorAction SilentlyContinue
Set-Service -Name "SSDPSRV" -StartupType Disabled -ErrorAction SilentlyContinue

# Disable NFS Services if installed
Write-Output "Disabling NFS Services..."
Set-Service -Name "NfsClnt" -StartupType Disabled -ErrorAction SilentlyContinue
Set-Service -Name "NfsSvr" -StartupType Disabled -ErrorAction SilentlyContinue

# Run Windows updates at the end
Set-Service -Name wuauserv -StartupType Automatic
Set-Service -Name wuauserv -Status Running
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name PSWindowsUpdate -Force
Import-Module PSWindowsUpdate
Write-Output "Running Windows Updates..."
Get-WUInstall -AcceptAll -Download -Install -AutoReboot -Verbose

# Clear password from memory
Write-Output "Clearing password from memory..."
$NewPassword = $null

Write-Output "Hardening complete."
