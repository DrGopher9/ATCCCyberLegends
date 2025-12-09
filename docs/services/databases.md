# Database Hardening (MySQL & PostgreSQL)

**Goal:** Prevent data exfiltration and unauthorized access.

## 1. MySQL / MariaDB (Common on Ecom)
*Config File:* `/etc/mysql/my.cnf` or `/etc/my.cnf`

* **Run the Secure Installation Script (DO THIS FIRST):**
    * Command: `sudo mysql_secure_installation`
    * *Answer "Yes" to:* Remove anonymous users, Disallow root login remotely, Remove test database, Reload privilege tables.
* **Bind to Localhost (Stop Remote Access):**
    * Edit the config file and find `bind-address`.
    * Change it to: `bind-address = 127.0.0.1`
    * *Restart:* `sudo systemctl restart mysql` (or `mariadb`)
* **Audit Users (SQL Console):**
    * Login: `mysql -u root -p`
    * Show users: `SELECT User, Host FROM mysql.user;`
    * *Drop bad users:* `DROP USER 'hacker'@'%';`
    * *Lock root to localhost:* `RENAME USER 'root'@'%' TO 'root'@'localhost';`

## 2. PostgreSQL (Common on Webmail)
*Config File:* `/etc/postgresql/[version]/main/postgresql.conf`
*Access Control:* `/etc/postgresql/[version]/main/pg_hba.conf`

* **Restrict Listening Address:**
    * Edit `postgresql.conf`:
    * Change `listen_addresses = '*'` to `listen_addresses = 'localhost'`
* **Restrict Authentication (pg_hba.conf):**
    * This file controls who can connect.
    * **Bad (Dangerous):** `host all all 0.0.0.0/0 trust`
    * **Good (Secure):** `host all all 127.0.0.1/32 md5`
    * *Note:* "md5" or "scram-sha-256" means "Ask for a password." "Trust" means "Let them in without a password."
* **Restart Service:**
    `sudo systemctl restart postgresql`

## 3. General "Quick Wins"
* **Change Default Passwords:**
    * If the competition packet says the database password is "changeme", **CHANGE IT.**
    * *MySQL:* `ALTER USER 'root'@'localhost' IDENTIFIED BY 'NewC0mplexP@ss!';`
    * *Postgres:* `\password postgres`
* **Check for Web Shells in Database:**
    * Red Team sometimes hides code in the DB.
    * *Dump data:* `mysqldump -u root -p --all-databases > db_dump.sql`
    * *Search it:* `grep "cmd.exe" db_dump.sql` or `grep "base64" db_dump.sql`