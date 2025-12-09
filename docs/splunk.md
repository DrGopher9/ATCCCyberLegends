# Splunk Hunting Cheat Sheet

**Goal:** Don't just collect logs. Find the bad guys.
**Time Range:** Always set to **"Last 15 minutes"** for real-time hunting.

## 1. The "Who is Logging In?" Query (SSH/RDP)
*Finds brute force attacks or successful logins from weird IPs.*

```splunk
index=* sourcetype="linux_secure" OR sourcetype="WinEventLog:Security"
| search "Failed password" OR "EventCode=4625"
| stats count by src_ip, user
| sort - count
```
* **What to look for:** High counts (Brute force).
* **Refinement (Show me SUCCESSFUL logins only):**
    `index=* "Accepted password" OR "EventCode=4624"`

## 2. The "New User" Query
*Did Red Team just create a backdoor account?*

```splunk
index=* (useradd OR "EventCode=4720")
| table _time, user, src_user, dest
```

## 3. The "Sudo Abuse" Query
*Who is running commands as root?*

```splunk
index=* sourcetype="linux_secure" "COMMAND="
| table _time, user, command
```

## 4. The "Process Hunter" (Windows)
*Requires Sysmon. Finds dangerous commands like PowerShell or cmd.exe.*

```splunk
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search CommandLine="*powershell*" OR CommandLine="*cmd.exe*" OR CommandLine="*net user*"
| table _time, User, CommandLine, ParentCommandLine
```

## 5. The "Clear Logs" Query (The Smoking Gun)
*If this happens, you are 100% owned.*

```splunk
index=* (EventCode=1102 OR "clcevent" OR "rm /var/log")
```

## 6. Firewall Blocks (Palo Alto/FTD)
*See what is hitting your firewall.*

```splunk
index=* sourcetype="pan:traffic" OR sourcetype="cisco:ftd" action="blocked"
| stats count by src_ip, dest_port
| sort - count
```