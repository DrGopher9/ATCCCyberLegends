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
*Protecting: Ecom, Webmail, Splunk, Linux Workstation*

### Access Details
* [cite_start]**Management IP:** `172.20.242.150` [cite: 253]
* [cite_start]**Credentials:** `admin` / `Changeme123` [cite: 254]
* **How to Access:**
    * [cite_start]**GUI:** Open Firefox on the **Ubuntu Workstation** and browse to `https://172.20.242.150`[cite: 253].
    * **CLI:** SSH to `172.20.242.150` or use the Netlab Console.

### Critical Commands (CLI)
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
*Protecting: AD/DNS, Web Server, FTP, Windows Workstation*

### Access Details
* [cite_start]**Management IP:** `172.20.240.200` [cite: 256]
* [cite_start]**Credentials:** `admin` / `!Changeme123` [cite: 257, 258]
* **How to Access (CRITICAL):**
    * **GUI:** You **MUST** use the **Windows 11 Workstation**.
    * [cite_start]**URL:** Browse to `https://172.20.102.254/#/login`[cite: 260].
    * *Note: The PDF specifies this odd IP `102.254` for GUI access from the workstation.*

### Troubleshooting (CLI)
*This is NOT a standard ASA. You must drop into diagnostic mode.*

* **Enter the Diagnostic CLI:**
    1.  Login to the console (`admin` / `!Changeme123`).
    2.  Type: `system support diagnostic-cli`
    3.  Type: `enable`
    4.  (You are now in a standard Cisco ASA-style prompt).
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