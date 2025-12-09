# Web Server Hardening (Apache, Nginx, IIS)

**Goal:** Stop information leaks and prevent web shells.

## 1. Apache (Linux)
*Config File:* Usually `/etc/apache2/apache2.conf` or `/etc/httpd/conf/httpd.conf`

* **Hide Version Banner (Stop scanners):**
    * Add/Edit these lines:
    ```apache
    ServerSignature Off
    ServerTokens Prod
    ```
* **Disable Directory Listing (Prevent snooping):**
    * Remove `Indexes` from the Options line:
    * `Options -Indexes +FollowSymLinks`
* **Disable "server-status" (Leak hazard):**
    * Comment out the `<Location /server-status>` block if found.

## 2. Nginx (Linux)
*Config File:* Usually `/etc/nginx/nginx.conf`

* **Hide Version:**
    * Add to the `http` block:
    ```nginx
    server_tokens off;
    ```
* **Block hidden files (like .git):**
    ```nginx
    location ~ /\. {
        deny all;
    }
    ```

## 3. IIS (Windows)
*Manage via "Internet Information Services (IIS) Manager"*

* **Disable Directory Browsing:**
    * Click the specific Site -> Double click **Directory Browsing** -> Click **Disable** on the right.
* **Remove HTTP Headers (X-Powered-By):**
    * Click **HTTP Response Headers** -> Remove `X-Powered-By`.
* **Application Pools (Isolation):**
    * Ensure each website runs in its own **Application Pool**. If one gets hacked, the others survive.