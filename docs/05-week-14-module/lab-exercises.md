# Week 14 — Lab Exercises: Defend Your Box

You saw the attack in Week 13 — now stop it. For your track: **harden** against it, **secure** the box's
components, and **write a detection** that fires on it. Back up first; **verify the scored service after
every change**; log everything. The red team will re-probe — success means the attack fails, the service
stays up, and your alert fires.

---

## Common (every track)
1. Back up before hardening (config/state).
2. After each change: **verify the scored service** (the exact test from your baseline).
3. Write your detection in Splunk, then have the red team re-run the attack and confirm it fires.
4. Log every change; note any repo script too aggressive for a scored box.

---

## Track: AD/DNS — `T3-AD1`, `T3-AD3`
- **Harden:** enforce strong password policy / lockout (mind the scoring accounts), audit + trim Domain
  Admins, review GPOs, disable unused legacy protocols. **Do not break authentication** (POP3/mail
  depends on it — mail owner verifies mail after your changes).
- **Keep DNS scored:** confirm `nslookup` works throughout; lock down zone transfers.
- **Detection:** `EventCode=4625 | stats count by src_ip | where count > 10` as a saved alert;
  alert on new Domain Admin membership.

## Track: Web/FTP — `T3-WEB1`, `T3-WEB2`, `T3-WEB3`
- **Remove the web shell** found in Week 13; lock down write permissions on the web root; disable
  directory browsing; restrict IIS handlers.
- **Secure FTP:** disable anonymous, enforce strong creds, restrict to needed users; consider FTPS.
- **Keep HTTP/HTTPS scored:** `curl -I http://<.101>/` after every change.
- **Detection:** alert on new files in `wwwroot`; alert on POSTs to non-baseline paths in IIS logs.

## Track: E-Comm — `T3-EC1`, `T3-EC3`
- **Harden the web/app stack:** remove any web/reverse shell, fix upload dirs, patch the app, kill odd
  listeners (e.g. 4444).
- **Secure the DB:** rotate DB creds, restrict DB to localhost, remove test/anonymous DB users.
- **Keep the site scored:** `curl -I http://<.30>/` after every change; test the app's real function.
- **Detection:** alert on new listeners; alert on suspicious web-log patterns (uploads, shell params).

## Track: Email/Webmail — `T3-EM1`, `T3-EM2`, `T3-EM3`
- **Harden mail:** close open relay (`postconf` — restrict `smtpd_relay_restrictions`), enforce auth,
  rate-limit; remove unauthorized aliases/mailboxes.
- **Rotate mail creds**; harden the webmail app (patch, restrict admin).
- **Keep SMTP/POP3 scored:** test the SMTP banner on 25 and a POP3 login on 110 after every change
  (POP3 auth uses AD — coordinate).
- **Detection:** alert on mail-auth failure spikes and relay-attempt log lines.

## Track: Network — `T3-NET1`, `T3-NET2`
- **Back up all three configs** (if not already). Revert any rogue rule from Week 13.
- **Tighten policy:** allow only needed services to each box, deny the rest — **without blocking the
  scoring engine, and keep ICMP up except the PA core port.** Verify scored services on the protected
  boxes still pass.
- **Detection:** enable + review firewall logs; alert on config changes and admin logins from odd
  sources.

## Track: Splunk — `T3-SP1`, `T3-SP2`, `T3-SP3`
- **Restore/confirm forwarders:** every host reporting again (fix the one killed in Week 13); make the
  forwarder resilient.
- **Harden Splunk itself:** rotate the `admin`/`root`/`sysadmin` creds, restrict access, protect the
  config.
- **Build a detection (`T3-SP2`):** turn one Week-13 attack into a saved search + alert; confirm it
  fires when the red team repeats the attack. Share it to the team detections list.

---

## Verify + log (all tracks)
- Re-run your baseline service test — **still scoring?**
- Have the red team repeat the Week-13 attack — **does it now fail, and does your alert fire?**
- Change-log complete?

## Done?
You've hit the objectives if your box now resists its Week-13 attack, the scored service stayed up, and
your detection fires on repeat. Refine your detection + hardening solo for [`homework.md`](homework.md)
before the Tier-3 gate.
