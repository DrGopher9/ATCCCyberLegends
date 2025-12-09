# Active Directory (AD) Hardening

**Goal:** Secure the "Keys to the Kingdom." If AD falls, the game is over.

## 1. Attack Surface Reduction (ASR)

* **Disable Print Spooler on Domain Controllers (DCs):**
    * *Why:* Stops "PrintNightmare" exploits.
    * *Command:* `Stop-Service Spooler -Force; Set-Service Spooler -StartupType Disabled`
* **Block Internet on DCs:**
    * DCs should **never** browse the web. Remove the Default Gateway if possible, or block port 80/443 outbound on the firewall.
* **Remove Adobe/Office from DCs:**
    * Uninstall any software that isn't strictly needed for AD.

## 2. GPO: The "Mass Lockdown"
*Create a new Group Policy Object (GPO) linked to the whole domain.*

* **Disable cmd.exe (Prevent easy shells):**
    * `User Config > Policies > Admin Templates > System > Prevent access to the command prompt` -> **Enabled**
* **Disable Control Panel:**
    * `User Config > Policies > Admin Templates > Control Panel > Prohibit access to Control Panel` -> **Enabled**
* **Enable Audit Logging (Catch them):**
    * `Computer Config > Policies > Windows Settings > Security Settings > Advanced Audit Policy` -> **Log Logon/Logoff, Process Creation.**

## 3. Account Safety
* **Protect the "Domain Admins" Group:**
    * Run `Get-ADGroupMember "Domain Admins"` regularly.
    * There should only be **2-3 users** here. Remove everyone else.
* **KRBTGT Reset (Advanced):**
    * If you suspect a "Golden Ticket" attack, you must reset the `krbtgt` account password **twice**.