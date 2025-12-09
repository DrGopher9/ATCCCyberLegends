# Network Defense (VyOS, Palo Alto, FTD)

**Topology Overview:**
* **Top:** VyOS Router (Gateway)
* **Left Side:** Palo Alto Firewall (Protecting Linux/Splunk)
* **Right Side:** Cisco FTD Firewall (Protecting Windows/AD)

---

## 1. VyOS Router (The Gateway)
*VyOS uses "Juniper-style" syntax. Changes are not active until you COMMIT.*

* **Enter Config Mode:**
    `configure`
* **Show Configuration:**
    `show configuration`
* **Set IP Address:**
    `set interfaces ethernet eth0 address 10.0.0.1/24`
* **Static Route:**
    `set protocols static route 0.0.0.0/0 next-hop [Next_Hop_IP]`
* **NAT (Masquerade/Outbound):**
    `set nat source rule 100 outbound-interface 'eth0'`
    `set nat source rule 100 source address '192.168.1.0/24'`
    `set nat source rule 100 translation address 'masquerade'`
* **APPLY CHANGES (Crucial):**
    `commit`
    `save`

---

## 2. Palo Alto Firewall (Left Side)
*If the Netlab GUI is slow/broken, use the CLI.*

* **View Interfaces:**
    `show interface logical`
* **View Active Sessions:**
    `show session all`
* **View Security Rules:**
    `show running security-policy`
* **Commit Changes (CLI):**
    `configure`
    `# [Type your set commands here]`
    `commit`

---

## 3. Cisco FTD (Right Side)
*This is NOT a standard ASA. It runs FTD software. You often need to drop into the diagnostic CLI.*

* **Enter the Diagnostic CLI:**
    1.  Login to the console.
    2.  Type: `system support diagnostic-cli`
    3.  (You are now in a standard Cisco ASA-style prompt).
    4.  `enable`
* **Check Interface IPs:**
    `show interface ip brief`
* **Packet Tracer (The #1 Troubleshooting Tool):**
    * *Use this to see EXACTLY why traffic is failing.*
    * `packet-tracer input [Interface_Name] tcp [Src_IP] 12345 [Dst_IP] 80`

---

## 4. Host-Based Firewalls (Know Your OS!)

### Left Side (The Linux Mix)
* **Ubuntu 24 (Ecom & Wkst):**
    * Uses **UFW**.
    * Allow SSH: `ufw allow 22/tcp`
    * Enable: `ufw enable`
* **Fedora 42 (Webmail) & Oracle 9 (Splunk):**
    * These do **NOT** use UFW. They use **FirewallD**.
    * Check status: `systemctl status firewalld`
    * Open Port 80: `firewall-cmd --add-port=80/tcp --permanent`
    * Apply changes: `firewall-cmd --reload`
    * *Emergency Stop:* `systemctl stop firewalld`

### Right Side (The Windows Mix)
* **Server 2019/2022 & Win 11:**
    * Uses **Windows Firewall**.
    * Use the PowerShell commands found in the **Windows Hardening** page.