# AppLocker (Windows Application Whitelisting)

**Goal:** Stop "portable" malware (EXEs running from Desktop/Downloads).
**Target:** Windows 11 Workstation & Servers.

## 1. Start the Service
*AppLocker won't work if this service is off.*
* **PowerShell:** `Set-Service -Name "AppIDSvc" -StartupType Automatic; Start-Service "AppIDSvc"`

## 2. Configure the Policy (Local Group Policy)
1.  Run `gpedit.msc`.
2.  Go to: **Computer Configuration -> Windows Settings -> Security Settings -> Application Control Policies -> AppLocker**.
3.  **Executable Rules:**
    * Right-click -> **Create Default Rules**.
    * *This automatically allows C:\Windows and C:\Program Files.*
    * *CRITICAL:* If you skip this, you will crash the OS.
4.  **Enforce It:**
    * Click **AppLocker** (top level).
    * Click **Configure Rule Enforcement**.
    * Check **Executable rules** -> Set to **Enforce rules**.

## 3. The "Panic Button" (If you lock yourself out)
*If legitimate programs stop working:*
1.  Open `gpedit.msc`.
2.  Go back to **Configure Rule Enforcement**.
3.  Change it to **Audit only**.
4.  Run `gpupdate /force` in cmd.

## 4. Script to Enable via PowerShell (Fast Mode)
*Run this to turn on default rules instantly.*

```powershell
Import-Module AppLocker
Set-AppLockerPolicy -XmlPolicy (Get-AppLockerPolicy -Effective -Xml) -Merge
# (Note: Configuring via GUI is safer for beginners)