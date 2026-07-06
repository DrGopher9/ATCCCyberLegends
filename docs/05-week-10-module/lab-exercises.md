# Week 10 — Lab Exercises: Splunk Basics

Goal this week: prove the data is flowing, run the two searches you'll use most, and read a dashboard.
Keep it simple — you're learning to *see*, not to build detections yet.

**Prereqs:** access to the Splunk web UI on `172.20.242.20` (creds in
[`../07-competition-reference.md`](../07-competition-reference.md)); a couple of hosts whose logs should
be flowing.

---

## Exercise 1 — Understand the pipeline
On the Splunk host and one client, see the two halves:
```bash
# On a Linux client — is the universal forwarder running and pointed at Splunk?
systemctl status SplunkForwarder 2>/dev/null || sudo /opt/splunkforwarder/bin/splunk list forward-server
```
Repo deploy scripts for reference:
[`splunk-forwarders/deploy-forwarder-linux.sh`](../../CCDC-main-Matt_2026/CCDC-main/splunk-forwarders/deploy-forwarder-linux.sh),
[`Deploy-Forwarder-Windows.ps1`](../../CCDC-main-Matt_2026/CCDC-main/splunk-forwarders/Deploy-Forwarder-Windows.ps1),
[`Linux/Splunk/LinuxUF.sh`](../../CCDC_2026/Linux/Splunk/LinuxUF.sh),
[`Linux/Splunk/WindowsUF.sh`](../../CCDC_2026/Linux/Splunk/WindowsUF.sh).

## Exercise 2 — Confirm forwarders are reporting (`T2-S1`)
In the Splunk search bar:
```spl
| metadata type=hosts index=*
```
This lists hosts sending data and when they last reported. Answer: **which of the competition hosts are
reporting? Which are silent?** A silent host is a blind spot — note it.

Also check the forwarder connection view: **Settings → Forwarder Management** (or search
`index=_internal source=*metrics.log group=tcpin_connections`).

## Exercise 3 — The failed-login search (`T2-S1`)
Linux:
```spl
index=* ("Failed password" OR "authentication failure")
| stats count by src_ip, host
| sort -count
```
Windows:
```spl
index=* EventCode=4625
| stats count by Account_Name, src_ip, host
| sort -count
```
These are the searches that catch credential attacks — the Red Team's opening move. Memorize the shape.

## Exercise 4 — Make it appear (live)
Have a partner generate failed logins on a box:
```bash
# From another host, a few bad SSH attempts (to a box you control):
ssh baduser@<target> </dev/null   # type wrong passwords a few times
```
Re-run the Exercise 3 search. **Watch your partner's source IP show up.** That's you seeing the attack.

## Exercise 5 — Read a dashboard (`T2-S2`)
Load the repo dashboards (Splunk → Dashboards, or import the XML):
[`ccdc_security_overview.xml`](../../CCDC-main-Matt_2026/CCDC-main/splunk-dashboards/ccdc_security_overview.xml),
[`ccdc_linux_security.xml`](../../CCDC-main-Matt_2026/CCDC-main/splunk-dashboards/ccdc_linux_security.xml),
[`ccdc_windows_security.xml`](../../CCDC-main-Matt_2026/CCDC-main/splunk-dashboards/ccdc_windows_security.xml).

On the overview dashboard, identify: a spike in failed logins, the top source IPs, and any host that's
gone quiet. Practice saying out loud: **"host X, spike of failed logins from IP Y at time Z"** — that's
the sentence you'll say to the captain in competition.

## Exercise 6 — Find the broken forwarder
The facilitator has stopped a forwarder on one host. Using Exercise 2, find the host that stopped
reporting and (if you can) restart its forwarder:
```bash
sudo /opt/splunkforwarder/bin/splunk restart
```

## Done?
You've hit the objectives if you can: confirm which hosts report, run the Linux + Windows failed-login
searches, watch a live failed login appear, read a dashboard and name an anomaly, and find a silent
host. Repeat Exercises 2, 3, and 5 solo for [`homework.md`](homework.md).
