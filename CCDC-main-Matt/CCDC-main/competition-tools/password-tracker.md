# CCDC Password Tracker

## Competition Date: ____________

---

## CRITICAL PASSWORDS

### Network Infrastructure

| System | Service | Username | Password | Changed By | Time |
|--------|---------|----------|----------|------------|------|
| Firewall (PAN-OS) | Admin | admin | | | |
| Firewall (PAN-OS) | Backup Admin | | | | |

---

### Windows AD Server (172.20.242.x)

| System | Service | Username | Password | Changed By | Time |
|--------|---------|----------|----------|------------|------|
| Windows AD | Local Admin | Administrator | | | |
| Windows AD | Domain Admin | Administrator | | | |
| Windows AD | Domain Admin | | | | |
| Windows AD | KRBTGT | krbtgt | (hash reset) | | |
| Windows AD | Service Account | | | | |
| Windows AD | DSRM | Administrator | | | |

---

### E-Commerce Server - Ubuntu (172.20.x.x)

| System | Service | Username | Password | Changed By | Time |
|--------|---------|----------|----------|------------|------|
| Ubuntu | Root | root | | | |
| Ubuntu | SSH User | | | | |
| Ubuntu | MySQL Root | root | | | |
| Ubuntu | MySQL App | prestashop | | | |
| PrestaShop | Admin | | | | |
| PrestaShop | API Key | | | | |

---

### Email Server - Postfix/Dovecot (172.20.x.x)

| System | Service | Username | Password | Changed By | Time |
|--------|---------|----------|----------|------------|------|
| Linux | Root | root | | | |
| Linux | SSH User | | | | |
| Postfix | SASL Auth | | | | |
| Dovecot | Admin | | | | |
| Webmail | Admin | | | | |

---

### Webmail/Apps Server - Fedora (172.20.x.x)

| System | Service | Username | Password | Changed By | Time |
|--------|---------|----------|----------|------------|------|
| Fedora | Root | root | | | |
| Fedora | SSH User | | | | |
| MySQL | Root | root | | | |
| MySQL | Roundcube | roundcube | | | |
| Roundcube | Admin | admin | | | |

---

### Splunk SIEM (172.20.x.x)

| System | Service | Username | Password | Changed By | Time |
|--------|---------|----------|----------|------------|------|
| Linux | Root | root | | | |
| Linux | Splunk User | splunk | | | |
| Splunk | Admin | admin | | | |
| Splunk | Backup Admin | | | | |
| Splunk | HEC Token | | | | |

---

## NOTES

### Password Requirements
- Minimum 16 characters
- Mix of upper, lower, numbers, special characters
- No dictionary words
- Unique per service

### Password Generation (Linux)
```bash
< /dev/urandom tr -dc 'A-Za-z0-9!@#$%^&*' | head -c 20; echo
```

### Password Generation (Windows PowerShell)
```powershell
-join ((65..90) + (97..122) + (48..57) | Get-Random -Count 16 | ForEach-Object {[char]$_})
```

---

## CHANGE LOG

| Time | System | Change Made | By |
|------|--------|-------------|-----|
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |

---

## EMERGENCY CONTACTS

| Role | Name | Phone |
|------|------|-------|
| Team Captain | | |
| Windows Lead | | |
| Linux Lead | | |
| Network Lead | | |
| White Team | | |

---

**SECURE THIS DOCUMENT - DESTROY AFTER COMPETITION**
