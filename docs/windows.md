# Windows Hardening Guide

**Goal:** Lock down the domain and local accounts using PowerShell.

## 1. User Security (The Basics)
* **Change Local Administrator Password:**
    `net user Administrator "NewStrongPass!123"`
* **Disable Guest Account:**
    `net user Guest /active:no`
* **Audit Administrators Group (Who is boss?):**
    `Get-LocalGroupMember -Group "Administrators"`
    * *Remove anyone who doesn't belong:*
    `Remove-LocalGroupMember -Group "Administrators" -Member "SuspiciousUser"`

## 2. Firewall (Turn it ON)
*The Windows Firewall is often disabled by Red Team or default configs.*

* **Enable all profiles:**
    `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True`
* **Block all inbound traffic (Allow explicit rules only):**
    `Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block`

## 3. SMB & Sharing (The #1 Vulnerability)
*Disable SMBv1 immediately to stop EternalBlue-style attacks.*

* **Check SMBv1 Status:**
    `Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`
* **Disable SMBv1:**
    `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`

## 4. Services Audit
* **Find Running Services:**
    `Get-Service | Where-Object {$_.Status -eq "Running"}`
* **Stop a Service:**
    `Stop-Service -Name "ServiceName"`
* **Disable a Service (Prevent restart):**
    `Set-Service -Name "ServiceName" -StartupType Disabled`

## 5. RDP Security
*Ensure Network Level Authentication (NLA) is required.*

* **Enable NLA (Registry Tweak):**
    `(Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-Tcp'").SetUserAuthenticationRequired(1)`