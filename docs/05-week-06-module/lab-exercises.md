# Week 6 — Lab Exercises: AD Concepts & the Scored-Service Map

Two parts: a **read-only** tour of Active Directory, and building the scored-service map until you know
it cold. **Do not change anything in AD this week** — no new users, no password resets, no group
changes. Observe only.

**Prereqs:** the topology in [`../07-competition-reference.md`](../07-competition-reference.md); read
access to the Server 2019 AD/DNS box (`172.20.240.102`), elevated PowerShell.

---

## Exercise 1 — What domain is this?
On the AD/DNS server (PowerShell):
```powershell
Get-ADDomain | Select Name, DNSRoot, DomainSID
Get-ADDomainController | Select Name, IPv4Address
```
Note the domain name — every user in the competition belongs to it.

## Exercise 2 — Users and the group that matters most
```powershell
Get-ADUser -Filter * | Select Name, SamAccountName, Enabled | Sort Name
Get-ADGroupMember "Domain Admins" | Select Name, SamAccountName
```
> **Domain Admins = full control of the domain.** In competition, an account here that you didn't put
> there is a top-priority red flag. Memorize this command — it's the AD equivalent of Week 4's
> `Get-LocalGroupMember Administrators`.

## Exercise 3 — See the AD↔scoring links yourself
```powershell
# DNS runs on this AD box and is a scored service:
Get-Service DNS
Get-DnsServerZone | Select ZoneName, ZoneType

# Mail (POP3) authenticates against these same AD usernames — so these accounts
# underpin the mail score too. (Do NOT change them; just observe.)
Get-ADUser -Filter * | Measure-Object   # how many accounts back mail auth?
```
Discuss: if someone disables or breaks an AD account, which **two scored services** could suffer?
(Answer: DNS is on this box, and POP3/mail auth uses these accounts.)

## Exercise 4 — Build the scored-service map
Fill this out completely, confirming each row against `07`:

| Service | Port | Box | Internal IP | Segment / firewall |
|---|---|---|---|---|
| HTTP | 80 | | | |
| HTTPS | 443 | | | |
| SMTP | 25 | | | |
| POP3 | 110 | | | |
| DNS | 53 | | | |
| FTP (if scored) | 21 | | | |

Then, from memory, redraw it. This map is the thing you'll triage against in competition — down
service → which box → which segment → who owns it.

## Done?
You've hit the objectives if you can: name the domain, list Domain Admins, explain the two AD↔scoring
links (DNS + POP3 auth), and fill the scored-service map from memory. Practice the map + Domain Admins
command solo for [`homework.md`](homework.md).
