# Common Injects & Business Tasks

**Goal:** Complete these professionally and quickly. Always turn them in as a PDF unless told otherwise.

## 1. The "Password Policy" Inject
*You will almost always be asked to write a password policy in the first hour.*

**Template:**
> **To:** Management
> **From:** IT Security Team
> **Subject:** Updated Password Security Standards
>
> Effective immediately, the following password standards are enforced to secure company assets:
> 1.  **Length:** Minimum 12 characters.
> 2.  **Complexity:** Must contain Upper, Lower, Number, and Special Character.
> 3.  **History:** Cannot reuse the last 5 passwords.
> 4.  **Age:** Passwords expire every 90 days.
> 5.  **Lockout:** Account locks after 5 failed attempts for 15 minutes.

## 2. The "Incident Report" Inject
*Task: Report on a breach you found (e.g., Red Team changed a wallpaper).*

**Template:**
* **Incident Time:** [Insert Date/Time]
* **Affected Systems:** [IP Addresses / Hostnames]
* **Description:** We detected unauthorized access via [SSH/RDP/Web]. The attacker exploited a default credential.
* **Action Taken:**
    * The attacker's IP was blocked at the firewall.
    * The compromised account was locked.
    * Credentials have been reset.
* **Status:** Systems are currently stable and being monitored.

## 3. The "New User" Inject
*Task: Create a new user 'JSmith' with specific permissions.*

**Linux Command:**
```bash
useradd -m -s /bin/bash jsmith
passwd jsmith
# If they need sudo/admin rights:
usermod -aG sudo jsmith
```

**Windows Command:**
```powershell
New-LocalUser -Name "jsmith" -NoPassword
Set-LocalUser -Name "jsmith" -Password (Read-Host -AsSecureString)
Add-LocalGroupMember -Group "Users" -Member "jsmith"
```

## 4. The "User Audit" Inject
*Task: Identify all users and find who needs a password change.*

**Linux (Find old passwords):**
* `chage -l [username]` (Shows when password was last changed)
* `cut -d: -f1,3 /etc/shadow` (Shows username and date of last change)

**Windows (Find bad passwords):**
* Run this PowerShell command to see who hasn't changed their password recently:
    ```powershell
    Get-LocalUser | Select-Object Name, PasswordLastSet, Enabled
    ```

