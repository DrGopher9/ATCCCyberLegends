# DNS Hardening (Bind & Windows)

**Goal:** Prevent Zone Transfers (giving away the network map) and Cache Poisoning.

## 1. BIND9 (Linux)
*Config File:* `/etc/bind/named.conf.options`

* **Restrict Recursion (Don't be an open resolver):**
    ```bind
    allow-recursion { localnets; localhost; };
    allow-query-cache { localnets; localhost; };
    ```
* **Block Zone Transfers (Critical):**
    ```bind
    allow-transfer { none; };
    ```
* **Hide Version:**
    ```bind
    version "unknown";
    ```
* **Check Config Syntax:**
    `named-checkconf /etc/bind/named.conf`

## 2. Windows DNS
*Manage via DNS Manager (dnsmgmt.msc)*

* **Disable Zone Transfers:**
    1. Right-click the Zone -> **Properties**.
    2. **Zone Transfers** Tab.
    3. Uncheck **"Allow zone transfers"** (Or restrict to specific IPs only).
* **Disable Recursion (If it's an external server):**
    1. Right-click Server Name -> **Properties**.
    2. **Advanced** Tab.
    3. Check **"Disable recursion"** (Only if this server does NOT need to resolve Google/Internet for clients).
* **Enable Scavenging (Clean up old records):**
    1. Right-click Server Name -> **Properties**.
    2. **Advanced** Tab -> Enable **"Scavenging of stale records"**.