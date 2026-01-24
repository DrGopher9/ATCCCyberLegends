#!/bin/bash
###############################################################################
# 09-mail-incident-response.sh - Mail Server Incident Response
# Target: Linux Mail Server (Postfix + Dovecot)
# Purpose: Rapid response to suspected compromise or abuse
###############################################################################

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

LOGDIR="/root/ccdc-logs"
IR_LOG="$LOGDIR/mail_incident_$(date +%Y%m%d_%H%M%S).log"
mkdir -p "$LOGDIR"

log() {
    echo "[$(date '+%H:%M:%S')] $1" | tee -a "$IR_LOG"
}

banner() {
    echo ""
    echo -e "${RED}============================================${NC}"
    echo -e "${RED}  $1${NC}"
    echo -e "${RED}============================================${NC}"
    echo ""
}

banner "MAIL SERVER INCIDENT RESPONSE"

echo "This script provides rapid response options."
echo "Log file: $IR_LOG"
echo ""
echo "Select action:"
echo ""
echo "  1) Block IP from sending mail"
echo "  2) Clear mail queue (spam incident)"
echo "  3) Disable open relay (emergency)"
echo "  4) Lock mail user account"
echo "  5) Check for spam/relay abuse"
echo "  6) Emergency Postfix restart"
echo "  7) Emergency Dovecot restart"
echo "  8) Kill suspicious process"
echo "  9) Capture mail server state"
echo " 10) Check for backdoors"
echo "  0) Exit"
echo ""

MAIL_LOG="/var/log/mail.log"
[ -f "/var/log/maillog" ] && MAIL_LOG="/var/log/maillog"

while true; do
    read -p "Select action [0-10]: " -r ACTION

    case $ACTION in
        1)
            banner "BLOCK IP FROM SENDING MAIL"
            echo "Recent connection IPs:"
            grep "connect from" "$MAIL_LOG" 2>/dev/null | \
                grep -oE "\[[0-9.]+\]" | tr -d '[]' | sort | uniq -c | sort -rn | head -10 || echo "Cannot parse log"
            echo ""
            read -p "Enter IP to block: " -r IP
            if [ -n "$IP" ]; then
                # Add to Postfix restrictions
                CURRENT=$(postconf -h smtpd_client_restrictions 2>/dev/null || echo "")
                if [ -z "$CURRENT" ]; then
                    postconf -e "smtpd_client_restrictions = check_client_access hash:/etc/postfix/client_access"
                fi

                # Add to client_access file
                echo "$IP REJECT Blocked by administrator" >> /etc/postfix/client_access
                postmap /etc/postfix/client_access
                postfix reload

                log "Blocked IP in Postfix: $IP"
                echo -e "${GREEN}Blocked: $IP${NC}"

                # Also add to firewall
                read -p "Also block at firewall level? (y/N): " -r REPLY
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    if command -v ufw &> /dev/null; then
                        ufw deny from "$IP" to any
                    elif command -v firewall-cmd &> /dev/null; then
                        firewall-cmd --add-rich-rule="rule family=ipv4 source address=$IP reject"
                    else
                        iptables -I INPUT -s "$IP" -j DROP
                    fi
                    log "Blocked IP at firewall: $IP"
                fi
            fi
            ;;

        2)
            banner "CLEAR MAIL QUEUE"
            echo "Current queue status:"
            mailq 2>/dev/null | tail -20
            echo ""
            echo "Queue size: $(mailq 2>/dev/null | grep -c "^[A-F0-9]" || echo "unknown") messages"
            echo ""
            echo "Options:"
            echo "  1) Delete ALL queued mail"
            echo "  2) Delete deferred mail only"
            echo "  3) Delete mail from specific sender"
            echo "  4) Cancel"
            read -p "Select option: " -r OPT
            case $OPT in
                1)
                    read -p "Delete ALL queued mail? This cannot be undone! (y/N): " -r CONFIRM
                    if [[ $CONFIRM =~ ^[Yy]$ ]]; then
                        postsuper -d ALL
                        log "Deleted ALL mail from queue"
                    fi
                    ;;
                2)
                    postsuper -d ALL deferred
                    log "Deleted all deferred mail"
                    ;;
                3)
                    read -p "Enter sender address to purge: " -r SENDER
                    mailq | grep "$SENDER" | awk '{print $1}' | tr -d '*!' | while read qid; do
                        postsuper -d "$qid"
                    done
                    log "Purged mail from sender: $SENDER"
                    ;;
            esac
            ;;

        3)
            banner "EMERGENCY: DISABLE OPEN RELAY"
            log "Applying emergency relay restrictions..."
            echo "Current mynetworks:"
            postconf mynetworks
            echo ""

            # Restrict to localhost only
            postconf -e "mynetworks = 127.0.0.0/8 [::1]/128"
            postconf -e "smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination"
            postconf -e "smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination"
            postfix reload

            log "Relay restrictions applied"
            echo -e "${GREEN}Open relay disabled. Only localhost and authenticated users can relay.${NC}"
            echo ""
            echo "New mynetworks:"
            postconf mynetworks
            ;;

        4)
            banner "LOCK MAIL USER ACCOUNT"
            echo "Checking for mail users..."

            # Check Dovecot passwd file
            for pfile in /etc/dovecot/users /etc/dovecot/passwd; do
                if [ -f "$pfile" ]; then
                    echo "Users in $pfile:"
                    cat "$pfile" | cut -d: -f1
                fi
            done

            echo ""
            echo "System users with login:"
            grep -E '/bin/(bash|sh)$' /etc/passwd | cut -d: -f1
            echo ""

            read -p "Enter username to lock: " -r USER
            if [ -n "$USER" ]; then
                # Lock system account
                usermod -L "$USER" 2>/dev/null && log "Locked system account: $USER"

                # Disable in Dovecot passwd file
                for pfile in /etc/dovecot/users /etc/dovecot/passwd; do
                    if [ -f "$pfile" ] && grep -q "^$USER:" "$pfile"; then
                        sed -i "s/^$USER:/$USER:DISABLED:/" "$pfile"
                        log "Disabled in $pfile: $USER"
                    fi
                done

                echo -e "${GREEN}Locked: $USER${NC}"
            fi
            ;;

        5)
            banner "CHECK FOR SPAM/RELAY ABUSE"
            log "Running spam/relay abuse check..."
            echo ""

            echo "=== Open Relay Check ==="
            MYNETWORKS=$(postconf -h mynetworks)
            echo "mynetworks: $MYNETWORKS"
            if echo "$MYNETWORKS" | grep -qE "0\.0\.0\.0/0"; then
                echo -e "${RED}[CRITICAL] Server is configured as open relay!${NC}"
            else
                echo -e "${GREEN}mynetworks looks restricted${NC}"
            fi

            echo ""
            echo "=== Mail Queue Analysis ==="
            QUEUE_SIZE=$(mailq 2>/dev/null | grep -c "^[A-F0-9]" || echo "0")
            echo "Queue size: $QUEUE_SIZE"
            if [ "$QUEUE_SIZE" -gt 100 ]; then
                echo -e "${RED}[WARNING] Large queue - possible spam incident${NC}"
            fi

            echo ""
            echo "=== Top Senders in Queue ==="
            mailq 2>/dev/null | grep -E "^[A-F0-9]" | awk '{print $7}' | sort | uniq -c | sort -rn | head -10

            echo ""
            echo "=== Recent Relay Rejections ==="
            grep -i "relay access denied" "$MAIL_LOG" 2>/dev/null | tail -10 || echo "None found"

            echo ""
            echo "=== Suspicious Volume (last hour) ==="
            HOUR_AGO=$(date -d '1 hour ago' '+%b %d %H' 2>/dev/null || date -v-1H '+%b %d %H' 2>/dev/null || echo "")
            if [ -n "$HOUR_AGO" ]; then
                grep "$HOUR_AGO" "$MAIL_LOG" 2>/dev/null | grep -c "status=sent" || echo "0"
            fi

            log "Spam/relay check complete"
            ;;

        6)
            banner "EMERGENCY POSTFIX RESTART"
            log "Emergency Postfix restart..."
            systemctl stop postfix
            sleep 2
            systemctl start postfix
            systemctl status postfix --no-pager | head -10
            log "Postfix restarted"
            ;;

        7)
            banner "EMERGENCY DOVECOT RESTART"
            log "Emergency Dovecot restart..."
            systemctl stop dovecot
            sleep 2
            systemctl start dovecot
            systemctl status dovecot --no-pager | head -10
            log "Dovecot restarted"
            ;;

        8)
            banner "KILL SUSPICIOUS PROCESS"
            echo "Current processes:"
            ps aux --sort=-%cpu | head -20
            echo ""
            read -p "Enter PID to kill: " -r PID
            if [ -n "$PID" ]; then
                ps -p "$PID" -o pid,user,comm 2>/dev/null && {
                    read -p "Kill this process? (y/N): " -r CONFIRM
                    if [[ $CONFIRM =~ ^[Yy]$ ]]; then
                        kill -9 "$PID" && log "Killed PID $PID" || log "Failed to kill PID $PID"
                    fi
                } || echo "PID not found"
            fi
            ;;

        9)
            banner "CAPTURE MAIL SERVER STATE"
            CAPTURE_DIR="$LOGDIR/mail_capture_$(date +%Y%m%d_%H%M%S)"
            mkdir -p "$CAPTURE_DIR"
            log "Capturing state to $CAPTURE_DIR"

            echo "Capturing processes..."
            ps auxf > "$CAPTURE_DIR/processes.txt" 2>/dev/null

            echo "Capturing network..."
            ss -tulnp > "$CAPTURE_DIR/listening.txt" 2>/dev/null
            ss -tnp > "$CAPTURE_DIR/connections.txt" 2>/dev/null

            echo "Capturing mail queue..."
            mailq > "$CAPTURE_DIR/mailq.txt" 2>/dev/null

            echo "Capturing Postfix config..."
            postconf -n > "$CAPTURE_DIR/postconf.txt" 2>/dev/null

            echo "Capturing Dovecot config..."
            doveconf -n > "$CAPTURE_DIR/doveconf.txt" 2>/dev/null

            echo "Capturing mail log tail..."
            tail -500 "$MAIL_LOG" > "$CAPTURE_DIR/mail_log_tail.txt" 2>/dev/null

            echo "Capturing auth log..."
            tail -200 /var/log/auth.log > "$CAPTURE_DIR/auth_tail.txt" 2>/dev/null || \
            tail -200 /var/log/secure > "$CAPTURE_DIR/auth_tail.txt" 2>/dev/null

            log "State captured to: $CAPTURE_DIR"
            echo -e "${GREEN}Capture complete: $CAPTURE_DIR${NC}"
            ;;

        10)
            banner "CHECK FOR BACKDOORS"
            log "Running backdoor checks..."
            echo ""

            echo "=== Checking Postfix config for anomalies ==="
            echo "relayhost: $(postconf -h relayhost)"
            echo "mynetworks: $(postconf -h mynetworks)"

            echo ""
            echo "=== Checking for suspicious aliases ==="
            grep -v "^#" /etc/aliases | grep -v "^$" || true
            grep -v "^#" /etc/postfix/virtual* 2>/dev/null | grep -v "^$" || true

            echo ""
            echo "=== Checking for reverse shells ==="
            ps aux | grep -E "(nc |ncat|netcat|bash -i|/dev/tcp)" | grep -v grep || echo "None found"

            echo ""
            echo "=== Checking cron jobs ==="
            for user in root $(cut -f1 -d: /etc/passwd | head -20); do
                CRON=$(crontab -l -u "$user" 2>/dev/null | grep -v "^#" | grep -v "^$")
                if [ -n "$CRON" ]; then
                    echo "Cron for $user:"
                    echo "$CRON"
                fi
            done

            echo ""
            echo "=== Recently modified mail configs ==="
            find /etc/postfix /etc/dovecot -mmin -60 -type f 2>/dev/null || echo "None in last hour"

            echo ""
            echo "=== SSH authorized_keys ==="
            for dir in /root /home/*; do
                if [ -f "$dir/.ssh/authorized_keys" ]; then
                    COUNT=$(wc -l < "$dir/.ssh/authorized_keys")
                    echo "$dir/.ssh/authorized_keys: $COUNT keys"
                fi
            done

            log "Backdoor check complete"
            ;;

        0)
            echo "Exiting incident response."
            log "IR session ended"
            exit 0
            ;;

        *)
            echo "Invalid option"
            ;;
    esac

    echo ""
    read -p "Press Enter to continue..."
done
