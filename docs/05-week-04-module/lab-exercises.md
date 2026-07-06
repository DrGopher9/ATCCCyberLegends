# Week 4 — Lab Exercises: Windows Fundamentals

Work on a lab **Windows** box (Windows 11 Wks `172.20.240.100`, or a Server 2019 box). Open
**PowerShell as Administrator** (right-click → Run as administrator). Practice account changes on a
**throwaway local user** — do **not** change the Administrator password on a shared box, and do **not**
touch Active Directory this week.

**Prereqs:** RDP/console to a lab Windows box; an elevated PowerShell prompt.

---

## Exercise 1 — Local users & groups
```powershell
Get-LocalUser                                  # local accounts
Get-LocalGroup                                 # local groups
Get-LocalGroupMember -Group "Administrators"   # WHO is a local admin? (memorize this one)
```
The Administrators group is the first thing you audit on any Windows box — an account you didn't add
here is a red flag.

## Exercise 2 — Create, disable, remove a local user
```powershell
New-LocalUser -Name "practice" -NoPassword -Description "week4 practice"
Get-LocalUser practice
Disable-LocalUser -Name "practice"             # disable (don't delete) — the safe first move
Get-LocalUser practice | Select Name,Enabled
Remove-LocalUser -Name "practice"              # remove
Get-LocalUser practice -ErrorAction SilentlyContinue; "done"
```
> In competition, **disabling** a suspicious account is often safer than deleting it (you keep it for
> the incident report). Note that distinction.

## Exercise 3 — Services
```powershell
Get-Service | Where-Object {$_.Status -eq 'Running'} | Select -First 15
Get-Service -Name W32Time                       # a specific service
Restart-Service -Name W32Time -Force            # restart
Get-Service -Name W32Time                        # confirm Running
```
GUI equivalent: `services.msc`. In competition you'll restart scored services (IIS: `W3SVC`; DNS:
`DNS`; FTP: `FTPSVC`) — but verify they serve, don't just check "Running."

## Exercise 4 — Event Viewer & the Security log
GUI: Start → **Event Viewer** → Windows Logs → **Security**. Find a **4625** (failed logon) or **4624**
(successful logon). Then the PowerShell way:
```powershell
# Recent failed logons (credential attacks show up here):
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20 |
  Format-Table TimeCreated, Id, Message -Wrap
```
This is the exact search you'll use to catch the Red Team spraying passwords.

## Exercise 5 — Basic PowerShell you'll reuse
```powershell
Get-Process | Sort CPU -Descending | Select -First 10   # busiest processes
Get-NetTCPConnection -State Listen |
  Select LocalAddress, LocalPort, OwningProcess | Sort LocalPort   # listeners (like ss on Linux)
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select -First 15   # persistence hides here
```
`Get-ScheduledTask` is a preview of persistence hunting — scheduled tasks are a classic Windows
backdoor.

## Done?
You've hit the objectives if you can: list/create/disable/remove a local user, list local admins,
check/restart a service, find a 4625 in the Security log, and run the basic PowerShell above. Repeat
Exercises 1–4 solo for [`homework.md`](homework.md).
