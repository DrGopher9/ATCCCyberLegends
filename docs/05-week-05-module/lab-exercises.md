# Week 5 — Lab Exercises: Networking & the Topology

Work from a lab box (Linux is easiest for these commands; Ubuntu Ecom or Ubuntu Wks). Keep
[`../07-competition-reference.md`](../07-competition-reference.md) open — you'll confirm your findings
against it. Nothing here changes any box; you're *observing the network*.

**Prereqs:** shell on a lab box that can reach other lab boxes.

---

## Exercise 1 — See your own network position
```bash
ip a                     # your IP(s) and interface(s)
ip route                 # your default gateway (the way "out")
```
Answer: what's your IP, your subnet mask (`/24`?), and your gateway? Which **segment** are you on —
`172.20.242.x` (behind Palo Alto) or `172.20.240.x` (behind Cisco FTD)?

## Exercise 2 — Ports and the scored services
Match each scored service to its port (from the packet):

| Service | Port | Host (from `07`) |
|---|---|---|
| HTTP | 80 | Server 2019 Web / Ubuntu Ecom |
| HTTPS | 443 | Server 2019 Web / Ubuntu Ecom |
| SMTP | 25 | Fedora Webmail (`172.20.242.40`) |
| POP3 | 110 | Fedora Webmail |
| DNS | 53 | Server 2019 AD/DNS (`172.20.240.102`) |

Then see what's actually listening on a box:
```bash
sudo ss -tlnp            # which of these ports are open here?
```

## Exercise 3 — Reach other hosts
```bash
ping -c3 172.20.240.102      # the AD/DNS server (Windows may block ping — note it)
ping -c3 172.20.242.40       # the Webmail server
```
> Remember: the competition requires **ICMP stays up except the Palo Alto core port** — ping is part of
> how the scoring engine checks you (see `07`). If a host doesn't answer ping, note whether that's
> expected (Windows default) or a problem.

## Exercise 4 — DNS lookups
```bash
nslookup google.com 172.20.240.102     # ask the competition DNS server
# or:
dig @172.20.240.102 google.com +short
nslookup 172.20.242.40                  # reverse lookup
```
DNS is a scored service — if lookups fail, the DNS box is losing points. Confirm it answers.

## Exercise 5 — Test a service end to end
```bash
curl -I http://172.20.242.30/           # is the Ecom web service serving?
# SMTP banner check (Webmail):
(echo QUIT) | timeout 5 bash -c 'exec 3<>/dev/tcp/172.20.242.40/25; cat <&3' 2>/dev/null | head
```
Seeing a service *respond* — not just "port open" — is exactly how the scoring engine judges you.

## Exercise 6 — Draw the topology
On paper or a whiteboard, draw all **11 VMs**. For each, label: name, internal IP, which segment, which
firewall it sits behind, and (if any) its scored service. Include the VyOS router and both firewalls.
Then check yourself against the table in [`../07-competition-reference.md`](../07-competition-reference.md).

## Done?
You've hit the objectives if you can: state your IP/subnet/gateway, map the 5 scored services to their
ports, use `ping`/`nslookup`/`ss`, test a service end-to-end, and **draw the labeled topology**. Redraw
it from memory for [`homework.md`](homework.md).
