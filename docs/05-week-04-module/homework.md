# Week 4 — Homework (solo, before the weekend lab / Week 5)

Alone on a lab Windows box, elevated PowerShell. Budget ~1 hour. Don't touch AD or shared admin
passwords.

## 1. Local users & admins, from memory (~20 min)
- [ ] List all local users
- [ ] List the members of the **Administrators** group (write the command down — you'll use it every
      competition)
- [ ] Create a throwaway user, **disable** it, then remove it

## 2. Services (~15 min)
- [ ] List running services
- [ ] Restart one safe service and confirm it's Running afterward
- [ ] Write down the service names for IIS (`W3SVC`), DNS (`DNS`), and FTP (`FTPSVC`)

## 3. Security log (~15 min)
- [ ] In Event Viewer, open the Security log and find a 4625 (or 4624)
- [ ] Run the `Get-WinEvent ... Id=4625` command and read one event
- [ ] Note: what does 4625 mean, and why does a defender care?

## 4. Preview persistence (~10 min)
- [ ] Run `Get-ScheduledTask` and skim the enabled tasks
- [ ] Note anything that looks unfamiliar (bring it — we'll discuss in Phase 2)

## Bring to the weekend lab / Week 5
- The `Get-LocalGroupMember Administrators` command from memory
- What Event ID 4625 means, in your own words
- One question that came up
