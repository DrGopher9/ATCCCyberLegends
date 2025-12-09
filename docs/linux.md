# Linux Hardening Guide

**Goal:** Secure the box without breaking scoring services.

## 1. User Management (The basics)
* **Lock the Root Account (Force sudo use):**
    `sudo passwd -l root`
* **Lock a suspicious user:**
    `sudo passwd -l [username]`
* **Check for empty passwords:**
    `awk -F: '($2 == "") {print}' /etc/shadow`

## 2. SSH Hardening (Priority #1)
*Edit `/etc/ssh/sshd_config`*

* **Disable Root Login:**
    Change `PermitRootLogin yes` to `PermitRootLogin no`
* **Disable Empty Passwords:**
    Change `PermitEmptyPasswords yes` to `PermitEmptyPasswords no`
* **Restart SSH (Careful!):**
    `sudo systemctl restart sshd` (or `ssh`)

## 3. Firewall (UFW - The Easy Way)
*If UFW is installed, use it. It is faster than raw iptables.*

1.  **Default Deny:**
    `sudo ufw default deny incoming`
    `sudo ufw default allow outgoing`
2.  **Allow SSH (DO NOT SKIP THIS):**
    `sudo ufw allow ssh`
3.  **Allow Scoring Services (Example: Web & DNS):**
    `sudo ufw allow 80/tcp`
    `sudo ufw allow 53`
4.  **Turn it on:**
    `sudo ufw enable`

## 4. Service Auditing
* **List all running services:**
    `systemctl list-units --type=service --state=running`
* **Stop and Disable a service:**
    `sudo systemctl stop [service_name]`
    `sudo systemctl disable [service_name]`

## 5. Cron Jobs (Persistence)
* **List tasks for current user:**
    `crontab -l`
* **Edit tasks:**
    `crontab -e`
* **Check system-wide tasks:**
    `cat /etc/crontab`