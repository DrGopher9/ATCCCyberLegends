# Service Self-Check Script

**Goal:** Run this every 5 minutes to see if you are passing BEFORE the scoreboard updates.

## Linux Check Script (Run on Ecom or Workstation)
*Save this file as `check_score.sh` on your Linux machine and run `chmod +x check_score.sh` to make it executable.*

```bash
#!/bin/bash

# 1. Check Web Content (Must match original!)
# If the Red Team defaces your site, grep will fail to find "Welcome"
echo "--- Checking Web Servers ---"
if curl -s [http://172.20.240.101](http://172.20.240.101) | grep -q "Welcome"; then
    echo "[PASS] Windows Web Server Content Match"
else
    echo "[FAIL] Windows Web Server (Content Mismatch or Down)"
fi

# 2. Check DNS (Must resolve internally)
# We test if the AD/DNS server (172.20.240.102) can resolve a domain
echo "--- Checking DNS ---"
if nslookup google.com 172.20.240.102 > /dev/null; then
    echo "[PASS] Windows DNS is resolving"
else
    echo "[FAIL] Windows DNS is DOWN"
fi

# 3. Check POP3 & SMTP (Email)
# The scoring engine logs into AD (172.20.240.102) to check email
echo "--- Checking Email Ports ---"
nc -zv 172.20.240.102 110 && echo "[PASS] POP3 Port Open" || echo "[FAIL] POP3 Closed"
nc -zv 172.20.240.102 25 && echo "[PASS] SMTP Port Open" || echo "[FAIL] SMTP Closed"
```