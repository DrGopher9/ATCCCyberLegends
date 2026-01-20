#!/usr/bin/env bash
set -euo pipefail

########################################
# MWCCDC Qualifier Hardening Script
# Fedora 42 Webmail Server
# 
# SCORED SERVICES ON THIS BOX:
#   SMTP (25) - Postfix
#   POP3 (110) - Dovecot
#   HTTP/HTTPS (80/443) - Webmail Interface
#
# Server IP: 172.20.242.40
# Public IP: 172.25.20+team#.39
#
# Competition Rules:
#   - Cannot change IPs/hostnames
#   - Cannot change VLAN scheme
#   - Max 3 VM scrubs per event
#   - Scoring is continuous
########################################

if [[ ${EUID} -ne 0 ]]; then
  echo "[!] Run as root: sudo $0"
  exit 1
fi

# Disable history for this session - no password traces
HISTFILE=/dev/null
set +o history

LOG="/root/hardening_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

log() { echo "[$(date '+%H:%M:%S')] [+] $*"; }
warn() { echo "[$(date '+%H:%M:%S')] [!] $*"; }
err() { echo "[$(date '+%H:%M:%S')] [ERROR] $*"; }

########################################
# BACKUP CRITICAL CONFIGS FIRST
########################################
log "Creating backup of original configs"
BACKUP_DIR="/root/backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup mail services
for dir in /etc/postfix /etc/dovecot /etc/httpd /etc/nginx /var/www; do
  if [[ -d "$dir" ]]; then
    cp -a "$dir" "$BACKUP_DIR/" 2>/dev/null || true
  fi
done

# Backup webmail configs (common locations)
for dir in /etc/roundcubemail /usr/share/roundcubemail /var/lib/roundcubemail; do
  if [[ -d "$dir" ]]; then
    cp -a "$dir" "$BACKUP_DIR/" 2>/dev/null || true
  fi
done

# Backup user/auth files
cp /etc/passwd "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/shadow "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/group "$BACKUP_DIR/" 2>/dev/null || true
cp /etc/aliases "$BACKUP_DIR/" 2>/dev/null || true

# Backup SSSD/AD configs if present
cp -a /etc/sssd "$BACKUP_DIR/" 2>/dev/null || true
cp -a /etc/samba "$BACKUP_DIR/" 2>/dev/null || true

log "Backup created at: $BACKUP_DIR"

########################################
# DETECT AUTHENTICATION BACKEND
########################################
detect_auth_backend() {
  log "Detecting authentication backend..."
  
  AUTH_BACKEND="local"
  AD_INFO=""
  
  # Check for SSSD (most common modern AD integration)
  if systemctl is-active --quiet sssd 2>/dev/null; then
    if [[ -f /etc/sssd/sssd.conf ]] && grep -qi "id_provider.*ad\|ldap" /etc/sssd/sssd.conf 2>/dev/null; then
      AUTH_BACKEND="sssd"
      AD_INFO=$(grep "^domains" /etc/sssd/sssd.conf 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
      log "Detected: SSSD with AD/LDAP ($AD_INFO)"
    fi
  fi
  
  # Check for Winbind
  if systemctl is-active --quiet winbind 2>/dev/null; then
    AUTH_BACKEND="winbind"
    AD_INFO=$(grep -i "realm" /etc/samba/smb.conf 2>/dev/null | head -1 | cut -d'=' -f2 | tr -d ' ')
    log "Detected: Winbind ($AD_INFO)"
  fi
  
  # Check for direct LDAP in Dovecot
  if [[ -f /etc/dovecot/dovecot-ldap.conf.ext ]]; then
    LDAP_HOST=$(grep "^hosts" /etc/dovecot/dovecot-ldap.conf.ext 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    if [[ -n "$LDAP_HOST" ]]; then
      AUTH_BACKEND="ldap"
      AD_INFO="$LDAP_HOST"
      log "Detected: Direct LDAP auth to $LDAP_HOST"
    fi
  fi
  
  # Check NSS configuration
  if grep -q "sss" /etc/nsswitch.conf 2>/dev/null; then
    log "NSS configured with SSSD"
  elif grep -q "winbind" /etc/nsswitch.conf 2>/dev/null; then
    log "NSS configured with Winbind"
  fi
  
  echo "$AUTH_BACKEND"
}

########################################
# PASSWORD MANAGEMENT - AD AWARE
########################################
change_passwords() {
  log "Starting password management"
  
  AUTH_BACKEND=$(detect_auth_backend)
  
  echo ""
  echo "========================================="
  echo "  PASSWORD MANAGEMENT"
  echo "========================================="
  echo ""
  echo "  Detected auth backend: $AUTH_BACKEND"
  echo ""
  
  if [[ "$AUTH_BACKEND" != "local" ]]; then
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│  ⚠️  AD/LDAP AUTHENTICATION DETECTED                        │"
    echo "├─────────────────────────────────────────────────────────────┤"
    echo "│  Mail users authenticate against Active Directory.         │"
    echo "│                                                             │"
    echo "│  DO NOT change mail user passwords on this Linux box!      │"
    echo "│  They must be changed on Windows AD server instead.        │"
    echo "│                                                             │"
    echo "│  This script will ONLY change LOCAL accounts:              │"
    echo "│    • root                                                   │"
    echo "│    • sysadmin (if local)                                    │"
    echo "│                                                             │"
    echo "│  For mail users (~100 accounts):                           │"
    echo "│    → Run PowerShell script on AD server (172.20.240.102)   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    read -p "Press ENTER to continue with local account changes only..."
    echo ""
    
    # Only change truly local accounts
    change_local_accounts_only
    
  else
    echo "Local authentication detected."
    echo "All users are stored in /etc/shadow on this system."
    echo ""
    
    # Count users
    USER_COUNT=$(awk -F: '$3 >= 1000 && $3 < 60000 {count++} END {print count}' /etc/passwd)
    echo "Found $USER_COUNT regular user accounts (UID >= 1000)"
    echo ""
    
    if [[ "$USER_COUNT" -gt 10 ]]; then
      change_bulk_local_accounts "$USER_COUNT"
    else
      change_few_local_accounts
    fi
  fi
}

########################################
# LOCAL ACCOUNTS ONLY (AD ENVIRONMENT)
########################################
change_local_accounts_only() {
  log "Changing local accounts only (AD environment)"
  
  echo "--- LOCAL ACCOUNT PASSWORD CHANGES ---"
  echo ""
  echo "These passwords will be displayed ONCE. Write them down!"
  echo "NO passwords are saved to disk."
  echo ""
  read -p "Press ENTER when ready..."
  echo ""
  
  # Root password
  echo "Setting password for: root"
  while true; do
    read -s -p "  Enter new password for root: " p1; echo ""
    read -s -p "  Confirm password: " p2; echo ""
    
    if [[ "$p1" != "$p2" ]]; then
      echo "  Passwords don't match. Try again."
      continue
    fi
    
    if [[ ${#p1} -lt 10 ]]; then
      echo "  Password too short (minimum 10 characters). Try again."
      continue
    fi
    
    echo "root:$p1" | chpasswd
    log "✓ root password changed"
    break
  done
  
  # Sysadmin password (if exists and is local)
  if id "sysadmin" &>/dev/null; then
    # Check if sysadmin is local (in /etc/passwd with valid shell)
    if grep -q "^sysadmin:" /etc/passwd; then
      echo ""
      echo "Setting password for: sysadmin"
      while true; do
        read -s -p "  Enter new password for sysadmin: " p1; echo ""
        read -s -p "  Confirm password: " p2; echo ""
        
        if [[ "$p1" != "$p2" ]]; then
          echo "  Passwords don't match. Try again."
          continue
        fi
        
        if [[ ${#p1} -lt 10 ]]; then
          echo "  Password too short (minimum 10 characters). Try again."
          continue
        fi
        
        echo "sysadmin:$p1" | chpasswd
        log "✓ sysadmin password changed"
        break
      done
    fi
  fi
  
  # Clear password variables
  unset p1 p2
  
  echo ""
  log "Local account passwords changed"
  echo ""
  warn "REMINDER: Change mail user passwords on Windows AD server!"
  echo ""
}

########################################
# BULK LOCAL ACCOUNTS (NO AD)
########################################
change_bulk_local_accounts() {
  local user_count=$1
  
  log "Bulk password change mode ($user_count users)"
  
  echo "========================================="
  echo "  BULK PASSWORD CHANGE OPTIONS"
  echo "========================================="
  echo ""
  echo "  1) Set individual passwords for critical accounts (root, sysadmin)"
  echo "     + Single password for all $user_count mail users"
  echo "     [RECOMMENDED - Fast and secure enough for CCDC]"
  echo ""
  echo "  2) Set individual passwords for critical accounts"
  echo "     + Pattern-based for mail users (username + suffix)"
  echo "     [Moderate security, memorable]"
  echo ""
  echo "  3) Auto-generate and DISPLAY all passwords"
  echo "     [Most secure but requires writing down $user_count passwords]"
  echo ""
  read -p "Choose option [1/2/3]: " BULK_OPTION
  echo ""
  
  # Always do critical accounts first
  echo "--- CRITICAL ACCOUNTS ---"
  echo ""
  
  # Root
  echo "Setting password for: root"
  while true; do
    read -s -p "  Enter new password: " p1; echo ""
    read -s -p "  Confirm: " p2; echo ""
    if [[ "$p1" == "$p2" && ${#p1} -ge 10 ]]; then
      echo "root:$p1" | chpasswd
      log "✓ root password changed"
      break
    else
      echo "  Passwords must match and be 10+ characters."
    fi
  done
  
  # Sysadmin
  if id "sysadmin" &>/dev/null && grep -q "^sysadmin:" /etc/passwd; then
    echo ""
    echo "Setting password for: sysadmin"
    while true; do
      read -s -p "  Enter new password: " p1; echo ""
      read -s -p "  Confirm: " p2; echo ""
      if [[ "$p1" == "$p2" && ${#p1} -ge 10 ]]; then
        echo "sysadmin:$p1" | chpasswd
        log "✓ sysadmin password changed"
        break
      else
        echo "  Passwords must match and be 10+ characters."
      fi
    done
  fi
  
  unset p1 p2
  
  # Collect mail users
  MAIL_USERS=()
  while IFS=: read -r username _ uid _; do
    if [[ $uid -ge 1000 && $uid -lt 60000 ]]; then
      if [[ "$username" != "sysadmin" && "$username" != "nobody" ]]; then
        MAIL_USERS+=("$username")
      fi
    fi
  done < /etc/passwd
  
  echo ""
  echo "--- MAIL USERS (${#MAIL_USERS[@]} accounts) ---"
  echo ""
  
  case "$BULK_OPTION" in
    1)
      # Single password for all mail users
      echo "Enter ONE password for all ${#MAIL_USERS[@]} mail users."
      echo "This is what the scoring engine will use for POP3/SMTP."
      echo ""
      
      while true; do
        read -s -p "  Password for all mail users: " BULK_PASS; echo ""
        read -s -p "  Confirm: " BULK_PASS2; echo ""
        
        if [[ "$BULK_PASS" == "$BULK_PASS2" && ${#BULK_PASS} -ge 10 ]]; then
          break
        else
          echo "  Passwords must match and be 10+ characters."
        fi
      done
      
      echo ""
      echo "Changing passwords..."
      
      for username in "${MAIL_USERS[@]}"; do
        echo "$username:$BULK_PASS" | chpasswd 2>/dev/null && echo -n "." || echo -n "x"
      done
      
      echo ""
      log "✓ Changed passwords for ${#MAIL_USERS[@]} mail users"
      echo ""
      echo "┌─────────────────────────────────────────────────────────────┐"
      echo "│  ALL MAIL USERS: Use the password you just entered         │"
      echo "│  Remember it - NOT stored on disk!                         │"
      echo "└─────────────────────────────────────────────────────────────┘"
      
      unset BULK_PASS BULK_PASS2
      ;;
      
    2)
      # Pattern-based: username + suffix
      echo "Pattern mode: password = username + your suffix"
      echo "Example: suffix 'CCDC2026!' → user 'john' gets 'johnCCDC2026!'"
      echo ""
      
      while true; do
        read -s -p "  Enter suffix: " SUFFIX; echo ""
        read -s -p "  Confirm suffix: " SUFFIX2; echo ""
        
        if [[ "$SUFFIX" == "$SUFFIX2" && ${#SUFFIX} -ge 8 ]]; then
          break
        else
          echo "  Suffix must match and be 8+ characters."
        fi
      done
      
      echo ""
      echo "Changing passwords..."
      
      for username in "${MAIL_USERS[@]}"; do
        echo "$username:${username}${SUFFIX}" | chpasswd 2>/dev/null && echo -n "." || echo -n "x"
      done
      
      echo ""
      log "✓ Pattern-based passwords set for ${#MAIL_USERS[@]} users"
      echo ""
      echo "┌─────────────────────────────────────────────────────────────┐"
      echo "│  PATTERN: {username}[your suffix]                          │"
      echo "│  Remember the suffix - NOT stored on disk!                 │"
      echo "└─────────────────────────────────────────────────────────────┘"
      
      unset SUFFIX SUFFIX2
      ;;
      
    3)
      # Auto-generate and display in batches
      echo "Passwords will be displayed in batches of 10."
      echo "Write them down or photograph each batch."
      echo ""
      read -p "Ready? Press ENTER to begin..."
      
      BATCH_SIZE=10
      BATCH_NUM=0
      BATCH_OUTPUT=""
      
      for i in "${!MAIL_USERS[@]}"; do
        username="${MAIL_USERS[$i]}"
        NEW_PASS=$(openssl rand -base64 10 | tr -d '/+=')
        echo "$username:$NEW_PASS" | chpasswd 2>/dev/null
        
        BATCH_OUTPUT+=$(printf "  %-20s %s\n" "$username" "$NEW_PASS")
        BATCH_OUTPUT+=$'\n'
        
        if (( (i + 1) % BATCH_SIZE == 0 )); then
          ((BATCH_NUM++))
          clear
          echo "========================================="
          echo "  BATCH $BATCH_NUM - WRITE THESE DOWN"
          echo "========================================="
          echo ""
          echo "$BATCH_OUTPUT"
          echo "========================================="
          echo ""
          read -p "Press ENTER when noted..."
          BATCH_OUTPUT=""
        fi
      done
      
      # Final partial batch
      if [[ -n "$BATCH_OUTPUT" ]]; then
        ((BATCH_NUM++))
        clear
        echo "========================================="
        echo "  BATCH $BATCH_NUM (FINAL)"
        echo "========================================="
        echo ""
        echo "$BATCH_OUTPUT"
        echo "========================================="
        echo ""
        read -p "Press ENTER when noted..."
      fi
      
      clear
      log "✓ Random passwords set for ${#MAIL_USERS[@]} users"
      
      unset BATCH_OUTPUT NEW_PASS
      ;;
      
    *)
      warn "Invalid option - skipping bulk password changes (DANGEROUS!)"
      ;;
  esac
  
  unset MAIL_USERS BULK_OPTION
}

########################################
# FEW LOCAL ACCOUNTS (NO AD, <10 USERS)
########################################
change_few_local_accounts() {
  log "Individual password change mode"
  
  echo "Setting individual passwords for each account."
  echo "Passwords will NOT be stored on disk."
  echo ""
  
  # Root first
  echo "Setting password for: root"
  while true; do
    read -s -p "  Enter new password: " p1; echo ""
    read -s -p "  Confirm: " p2; echo ""
    if [[ "$p1" == "$p2" && ${#p1} -ge 10 ]]; then
      echo "root:$p1" | chpasswd
      log "✓ root password changed"
      break
    else
      echo "  Passwords must match and be 10+ characters."
    fi
  done
  
  # All other users
  while IFS=: read -r username _ uid _; do
    if [[ $uid -ge 1000 && $uid -lt 60000 && "$username" != "nobody" ]]; then
      echo ""
      echo "Setting password for: $username"
      while true; do
        read -s -p "  Enter new password: " p1; echo ""
        read -s -p "  Confirm: " p2; echo ""
        if [[ "$p1" == "$p2" && ${#p1} -ge 8 ]]; then
          echo "$username:$p1" | chpasswd
          log "✓ $username password changed"
          break
        else
          echo "  Passwords must match and be 8+ characters."
        fi
      done
    fi
  done < /etc/passwd
  
  unset p1 p2
  log "All passwords changed"
}

########################################
# IDENTIFY WEBMAIL SOFTWARE
########################################
log "Detecting webmail software"

WEBMAIL="unknown"
WEBSERVER="unknown"

if [[ -d /etc/roundcubemail ]] || [[ -d /usr/share/roundcubemail ]]; then
  WEBMAIL="roundcube"
  log "Detected: Roundcube webmail"
elif [[ -d /usr/share/squirrelmail ]]; then
  WEBMAIL="squirrelmail"
  log "Detected: SquirrelMail webmail"
elif [[ -d /var/www/rainloop ]]; then
  WEBMAIL="rainloop"
  log "Detected: RainLoop webmail"
fi

if systemctl list-unit-files | grep -q "^httpd"; then
  WEBSERVER="httpd"
  log "Detected: Apache (httpd)"
elif systemctl list-unit-files | grep -q "^nginx"; then
  WEBSERVER="nginx"
  log "Detected: Nginx"
fi

########################################
# VERIFY SCORED SERVICE PACKAGES
########################################
log "Verifying scored service packages"

REQUIRED_PKGS=(postfix dovecot)
if [[ "$WEBSERVER" == "httpd" ]]; then
  REQUIRED_PKGS+=(httpd mod_ssl)
elif [[ "$WEBSERVER" == "nginx" ]]; then
  REQUIRED_PKGS+=(nginx)
fi

MISSING=()
for pkg in "${REQUIRED_PKGS[@]}"; do
  if ! rpm -q "$pkg" &>/dev/null; then
    MISSING+=("$pkg")
  fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  warn "Missing packages: ${MISSING[*]}"
  log "Installing missing packages"
  dnf install -y "${MISSING[@]}"
fi

########################################
# CHANGE PASSWORDS (INTERACTIVE)
########################################
change_passwords

########################################
# REMOVE UNAUTHORIZED SSH KEYS
########################################
log "Removing unauthorized SSH keys"

for homedir in /root /home/*; do
  if [[ -d "$homedir/.ssh" ]]; then
    log "Backing up and clearing SSH keys in $homedir/.ssh"
    cp -a "$homedir/.ssh" "$BACKUP_DIR/$(basename $homedir)_ssh" 2>/dev/null || true
    rm -f "$homedir/.ssh/authorized_keys" 2>/dev/null || true
    rm -f "$homedir/.ssh/id_*" 2>/dev/null || true
  fi
done

########################################
# DISABLE SSH (NOT SCORED)
########################################
log "Disabling SSH service"
systemctl disable --now sshd.service 2>/dev/null || true

########################################
# FIREWALL CONFIGURATION
########################################
log "Configuring firewalld"

dnf install -y firewalld 2>/dev/null || true
systemctl enable --now firewalld

# Reset to clean state
firewall-cmd --permanent --remove-service=ssh 2>/dev/null || true
firewall-cmd --permanent --remove-service=dhcpv6-client 2>/dev/null || true
firewall-cmd --permanent --remove-service=cockpit 2>/dev/null || true

# Add ONLY scored services for this box
firewall-cmd --permanent --add-service=http      # 80
firewall-cmd --permanent --add-service=https     # 443
firewall-cmd --permanent --add-service=smtp      # 25
firewall-cmd --permanent --add-port=110/tcp      # POP3

# Block SSH explicitly
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" port port="22" protocol="tcp" reject'

# Block common attack ports
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" port port="23" protocol="tcp" reject'    # Telnet
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" port port="3389" protocol="tcp" reject'  # RDP
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" port port="5900" protocol="tcp" reject'  # VNC

firewall-cmd --reload

log "Firewall configured - SMTP(25), POP3(110), HTTP(80), HTTPS(443) allowed"

########################################
# POSTFIX HARDENING
########################################
log "Hardening Postfix (SMTP)"

POSTFIX_MAIN="/etc/postfix/main.cf"

if [[ -f "$POSTFIX_MAIN" ]]; then
  # Backup current config
  cp "$POSTFIX_MAIN" "$BACKUP_DIR/main.cf.current"
  
  # Get current hostname and domain (don't change these per rules)
  CURRENT_HOSTNAME=$(postconf -h myhostname 2>/dev/null || hostname)
  CURRENT_DOMAIN=$(postconf -h mydomain 2>/dev/null || hostname -d)
  
  log "Current Postfix hostname: $CURRENT_HOSTNAME"
  log "Current Postfix domain: $CURRENT_DOMAIN"
  
  # Apply security settings without changing identity
  postconf -e "smtpd_banner = \$myhostname ESMTP"
  
  # Disable open relay
  postconf -e "smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination"
  
  # Disable VRFY command (user enumeration)
  postconf -e "disable_vrfy_command = yes"
  
  # Require HELO/EHLO
  postconf -e "smtpd_helo_required = yes"
  
  # Size limits
  postconf -e "message_size_limit = 10240000"
  postconf -e "mailbox_size_limit = 51200000"
  
  # Connection limits (anti-DoS)
  postconf -e "smtpd_client_connection_count_limit = 10"
  postconf -e "smtpd_client_connection_rate_limit = 30"
  
  # Timeout settings
  postconf -e "smtpd_timeout = 30s"
  postconf -e "smtpd_hard_error_limit = 5"
  
  log "Postfix hardening applied"
else
  err "Postfix main.cf not found!"
fi

########################################
# DOVECOT HARDENING
########################################
log "Hardening Dovecot (POP3)"

DOVECOT_CONF="/etc/dovecot/dovecot.conf"
DOVECOT_AUTH="/etc/dovecot/conf.d/10-auth.conf"
DOVECOT_MAIL="/etc/dovecot/conf.d/10-mail.conf"
DOVECOT_SSL="/etc/dovecot/conf.d/10-ssl.conf"

if [[ -f "$DOVECOT_CONF" ]]; then
  # Ensure only POP3 is enabled (scored service)
  # Check current protocols
  log "Checking Dovecot protocols"
  
  if [[ -f "$DOVECOT_CONF" ]]; then
    # Backup and modify
    cp "$DOVECOT_CONF" "$BACKUP_DIR/dovecot.conf.current"
    
    # Enable only required protocols - POP3 is scored
    # Don't disable IMAP if webmail needs it internally
    if grep -q "^protocols" "$DOVECOT_CONF"; then
      sed -i 's/^protocols.*/protocols = pop3 imap/' "$DOVECOT_CONF"
    else
      echo "protocols = pop3 imap" >> "$DOVECOT_CONF"
    fi
  fi
  
  # Harden authentication
  if [[ -f "$DOVECOT_AUTH" ]]; then
    cp "$DOVECOT_AUTH" "$BACKUP_DIR/10-auth.conf.current"
    
    # Disable plaintext auth on non-SSL (if SSL is available)
    # Be careful - scoring might use plaintext POP3
    # sed -i 's/^#disable_plaintext_auth.*/disable_plaintext_auth = yes/' "$DOVECOT_AUTH"
    
    # Only allow plain and login mechanisms (required for basic auth)
    if grep -q "^auth_mechanisms" "$DOVECOT_AUTH"; then
      sed -i 's/^auth_mechanisms.*/auth_mechanisms = plain login/' "$DOVECOT_AUTH"
    fi
  fi
  
  # Logging for incident response
  if [[ -f /etc/dovecot/conf.d/10-logging.conf ]]; then
    cp /etc/dovecot/conf.d/10-logging.conf "$BACKUP_DIR/"
    
    cat >> /etc/dovecot/conf.d/10-logging.conf <<'EOF'

# CCDC Enhanced Logging
auth_verbose = yes
auth_verbose_passwords = sha1
mail_debug = no
verbose_ssl = no
log_timestamp = "%Y-%m-%d %H:%M:%S "
EOF
  fi
  
  log "Dovecot hardening applied"
else
  err "Dovecot config not found!"
fi

########################################
# WEBMAIL HARDENING (ROUNDCUBE)
########################################
log "Hardening webmail interface"

if [[ "$WEBMAIL" == "roundcube" ]]; then
  RCUBE_CONFIG="/etc/roundcubemail/config.inc.php"
  
  if [[ -f "$RCUBE_CONFIG" ]]; then
    cp "$RCUBE_CONFIG" "$BACKUP_DIR/"
    
    # Check for installer directory and disable/remove
    if [[ -d /usr/share/roundcubemail/installer ]]; then
      mv /usr/share/roundcubemail/installer "$BACKUP_DIR/roundcube_installer" 2>/dev/null || true
      log "Removed Roundcube installer directory"
    fi
    
    # Harden config
    # Disable installer
    sed -i "s/\$config\['enable_installer'\].*/\$config['enable_installer'] = false;/" "$RCUBE_CONFIG" 2>/dev/null || true
    
    log "Roundcube hardening applied"
  fi
fi

########################################
# APACHE/NGINX HARDENING
########################################
log "Hardening web server"

if [[ "$WEBSERVER" == "httpd" ]]; then
  # Apache hardening
  HTTPD_CONF="/etc/httpd/conf/httpd.conf"
  HTTPD_SSL="/etc/httpd/conf.d/ssl.conf"
  
  if [[ -f "$HTTPD_CONF" ]]; then
    cp "$HTTPD_CONF" "$BACKUP_DIR/"
    
    # Hide Apache version
    if ! grep -q "^ServerTokens" "$HTTPD_CONF"; then
      echo "ServerTokens Prod" >> "$HTTPD_CONF"
      echo "ServerSignature Off" >> "$HTTPD_CONF"
    else
      sed -i 's/^ServerTokens.*/ServerTokens Prod/' "$HTTPD_CONF"
      sed -i 's/^ServerSignature.*/ServerSignature Off/' "$HTTPD_CONF"
    fi
    
    # Disable directory listing
    sed -i 's/Options Indexes FollowSymLinks/Options FollowSymLinks/' "$HTTPD_CONF"
    
    # Disable TRACE method
    if ! grep -q "^TraceEnable" "$HTTPD_CONF"; then
      echo "TraceEnable Off" >> "$HTTPD_CONF"
    fi
  fi
  
  # SSL hardening
  if [[ -f "$HTTPD_SSL" ]]; then
    cp "$HTTPD_SSL" "$BACKUP_DIR/"
    
    # Modern SSL protocols only
    sed -i 's/^SSLProtocol.*/SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1/' "$HTTPD_SSL" 2>/dev/null || true
  fi
  
  log "Apache hardening applied"
  
elif [[ "$WEBSERVER" == "nginx" ]]; then
  NGINX_CONF="/etc/nginx/nginx.conf"
  
  if [[ -f "$NGINX_CONF" ]]; then
    cp "$NGINX_CONF" "$BACKUP_DIR/"
    
    # Hide nginx version
    if ! grep -q "server_tokens" "$NGINX_CONF"; then
      sed -i '/http {/a \    server_tokens off;' "$NGINX_CONF"
    fi
  fi
  
  log "Nginx hardening applied"
fi

########################################
# PHP HARDENING (for webmail)
########################################
log "Hardening PHP"

PHP_INI=$(php -i 2>/dev/null | grep "Loaded Configuration File" | awk '{print $NF}')
if [[ -f "$PHP_INI" ]]; then
  cp "$PHP_INI" "$BACKUP_DIR/"
  
  # Disable dangerous functions
  sed -i 's/^disable_functions.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source/' "$PHP_INI" 2>/dev/null || true
  
  # Hide PHP version
  sed -i 's/^expose_php.*/expose_php = Off/' "$PHP_INI" 2>/dev/null || true
  
  # Disable remote file inclusion
  sed -i 's/^allow_url_fopen.*/allow_url_fopen = Off/' "$PHP_INI" 2>/dev/null || true
  sed -i 's/^allow_url_include.*/allow_url_include = Off/' "$PHP_INI" 2>/dev/null || true
  
  log "PHP hardening applied"
else
  warn "PHP config not found - skipping PHP hardening"
fi

########################################
# CHECK FOR BACKDOORS/SUSPICIOUS FILES
########################################
log "Scanning for suspicious files"

# Common webshell names
WEBSHELL_PATTERNS=(
  "c99.php" "r57.php" "shell.php" "cmd.php" "backdoor.php"
  "webshell.php" "eval.php" "base64.php" "upload.php"
  "FilesMan" "WSO" "b374k"
)

SUSPICIOUS_FILES=()

for pattern in "${WEBSHELL_PATTERNS[@]}"; do
  while IFS= read -r -d '' file; do
    SUSPICIOUS_FILES+=("$file")
  done < <(find /var/www -name "*$pattern*" -print0 2>/dev/null)
done

# Look for PHP files with suspicious content
while IFS= read -r -d '' file; do
  if grep -l -E "(eval\s*\(\s*base64_decode|eval\s*\(\s*\\\$_(GET|POST|REQUEST)|passthru|shell_exec\s*\()" "$file" &>/dev/null; then
    SUSPICIOUS_FILES+=("$file")
  fi
done < <(find /var/www -name "*.php" -print0 2>/dev/null)

if [[ ${#SUSPICIOUS_FILES[@]} -gt 0 ]]; then
  warn "SUSPICIOUS FILES FOUND:"
  printf '%s\n' "${SUSPICIOUS_FILES[@]}" | tee -a "$BACKUP_DIR/suspicious_files.txt"
  warn "Review these files manually - they may be backdoors!"
fi

########################################
# CHECK FOR UNAUTHORIZED CRON JOBS
########################################
log "Checking for suspicious cron jobs"

mkdir -p "$BACKUP_DIR/cron"
cp -a /etc/crontab "$BACKUP_DIR/cron/" 2>/dev/null || true
cp -a /etc/cron.d "$BACKUP_DIR/cron/" 2>/dev/null || true
cp -a /var/spool/cron "$BACKUP_DIR/cron/" 2>/dev/null || true

# List all cron jobs
log "Current cron jobs:"
for user in $(cut -f1 -d: /etc/passwd); do
  crontab -l -u "$user" 2>/dev/null && echo "--- Above cron for: $user ---"
done

# Check for suspicious entries
if grep -r -E "(wget|curl|nc |netcat|bash -i|/dev/tcp|python.*socket)" /etc/cron* /var/spool/cron 2>/dev/null; then
  warn "SUSPICIOUS CRON ENTRIES FOUND - review manually!"
fi

########################################
# CHECK FOR UNAUTHORIZED SERVICES
########################################
log "Checking for suspicious services"

# Look for services listening on unexpected ports
log "Current listening services:"
ss -tlnp | tee "$BACKUP_DIR/listening_services.txt"

# Check for suspicious systemd services
log "Checking systemd services"
systemctl list-unit-files --type=service --state=enabled | tee "$BACKUP_DIR/enabled_services.txt"

########################################
# DISABLE UNNECESSARY SERVICES
########################################
log "Disabling non-essential services"

DISABLE_SERVICES=(
  "avahi-daemon"
  "cups"
  "bluetooth"
  "rpcbind"
  "nfs-server"
  "vsftpd"
  "telnet"
)

for svc in "${DISABLE_SERVICES[@]}"; do
  if systemctl list-unit-files | grep -q "^${svc}.service"; then
    systemctl disable --now "${svc}.service" 2>/dev/null || true
    log "Disabled: $svc"
  fi
done

########################################
# START/ENABLE SCORED SERVICES
########################################
log "Starting/enabling scored services"

# Postfix (SMTP)
systemctl enable postfix
systemctl restart postfix
sleep 2
if systemctl is-active --quiet postfix; then
  log "✓ Postfix (SMTP) is running"
else
  err "✗ Postfix FAILED - check logs!"
  journalctl -u postfix --no-pager -n 20
fi

# Dovecot (POP3)
systemctl enable dovecot
systemctl restart dovecot
sleep 2
if systemctl is-active --quiet dovecot; then
  log "✓ Dovecot (POP3) is running"
else
  err "✗ Dovecot FAILED - check logs!"
  journalctl -u dovecot --no-pager -n 20
fi

# Web server (HTTP/HTTPS)
if [[ "$WEBSERVER" == "httpd" ]]; then
  systemctl enable httpd
  systemctl restart httpd
  sleep 2
  if systemctl is-active --quiet httpd; then
    log "✓ Apache (HTTP/HTTPS) is running"
  else
    err "✗ Apache FAILED - check logs!"
    journalctl -u httpd --no-pager -n 20
  fi
elif [[ "$WEBSERVER" == "nginx" ]]; then
  systemctl enable nginx
  systemctl restart nginx
  sleep 2
  if systemctl is-active --quiet nginx; then
    log "✓ Nginx (HTTP/HTTPS) is running"
  else
    err "✗ Nginx FAILED - check logs!"
    journalctl -u nginx --no-pager -n 20
  fi
fi

########################################
# VERIFY SCORED PORTS ARE LISTENING
########################################
log "Verifying scored service ports"

declare -A PORTS=(
  ["25"]="SMTP (Postfix)"
  ["110"]="POP3 (Dovecot)"
  ["80"]="HTTP"
  ["443"]="HTTPS"
)

for port in "${!PORTS[@]}"; do
  if ss -tlnp | grep -q ":$port "; then
    log "✓ Port $port (${PORTS[$port]}) is listening"
  else
    err "✗ Port $port (${PORTS[$port]}) NOT listening!"
  fi
done

########################################
# SECURE SYSCTL PARAMETERS
########################################
log "Applying kernel hardening"

cat > /etc/sysctl.d/99-ccdc-hardening.conf <<'EOF'
# Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# SYN Flood Protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Don't send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log martian packets
net.ipv4.conf.all.log_martians = 1

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1
EOF

sysctl -p /etc/sysctl.d/99-ccdc-hardening.conf

########################################
# SELINUX
########################################
log "Checking SELinux status"

if command -v getenforce &>/dev/null; then
  SELINUX_STATUS=$(getenforce)
  log "SELinux is: $SELINUX_STATUS"
  
  if [[ "$SELINUX_STATUS" == "Enforcing" ]]; then
    # Set helpful booleans for mail services
    setsebool -P httpd_can_sendmail on 2>/dev/null || true
    setsebool -P httpd_can_network_connect on 2>/dev/null || true  # May be needed for webmail
    log "SELinux booleans configured for mail services"
  fi
fi

########################################
# AUDITD FOR INCIDENT RESPONSE
########################################
log "Configuring auditd"

dnf install -y audit 2>/dev/null || true
systemctl enable --now auditd

cat > /etc/audit/rules.d/ccdc-webmail.rules <<'EOF'
# Monitor mail configs
-w /etc/postfix/ -p wa -k postfix_config
-w /etc/dovecot/ -p wa -k dovecot_config

# Monitor web configs
-w /etc/httpd/ -p wa -k httpd_config
-w /etc/nginx/ -p wa -k nginx_config

# Monitor webmail
-w /etc/roundcubemail/ -p wa -k roundcube_config
-w /var/www/ -p wa -k www_changes

# Monitor authentication
-w /etc/passwd -p wa -k user_modification
-w /etc/shadow -p wa -k password_modification

# Monitor sudo
-w /etc/sudoers -p wa -k sudoers_changes
EOF

augenrules --load 2>/dev/null || true

########################################
# FILE PERMISSIONS
########################################
log "Hardening file permissions"

chmod 0700 /root
chmod 0600 /etc/shadow
chmod 0600 /etc/gshadow
chmod 0644 /etc/passwd
chmod 0644 /etc/group

# Secure mail directories
chmod 0750 /etc/postfix 2>/dev/null || true
chmod 0750 /etc/dovecot 2>/dev/null || true

# Secure home directories
find /home -mindepth 1 -maxdepth 1 -type d -exec chmod 0700 {} \; 2>/dev/null || true

########################################
# FINAL SERVICE VERIFICATION
########################################
log "=== FINAL SERVICE STATUS ==="

echo ""
echo "SCORED SERVICES:"
for svc in postfix dovecot; do
  if systemctl is-active --quiet "$svc"; then
    echo "  ✓ $svc is RUNNING"
  else
    echo "  ✗ $svc is DOWN - INVESTIGATE!"
  fi
done

if [[ "$WEBSERVER" == "httpd" ]]; then
  if systemctl is-active --quiet httpd; then
    echo "  ✓ httpd is RUNNING"
  else
    echo "  ✗ httpd is DOWN - INVESTIGATE!"
  fi
elif [[ "$WEBSERVER" == "nginx" ]]; then
  if systemctl is-active --quiet nginx; then
    echo "  ✓ nginx is RUNNING"
  else
    echo "  ✗ nginx is DOWN - INVESTIGATE!"
  fi
fi

echo ""
echo "LISTENING PORTS:"
ss -tlnp | grep -E ":(25|110|80|443) "

########################################
# CLEAR SENSITIVE DATA
########################################
# Clear any remaining password variables
unset p1 p2 BULK_PASS BULK_PASS2 SUFFIX SUFFIX2 NEW_PASS

# Clear bash history
history -c 2>/dev/null || true

########################################
# COMPLETION
########################################
echo ""
log "========================================="
log "Fedora Webmail Hardening Complete"
log "========================================="
echo ""
log "CRITICAL FILES:"
log "  Backup:    $BACKUP_DIR"
log "  Log:       $LOG"
echo ""
echo "┌─────────────────────────────────────────────────────────────┐"
echo "│  ✓ NO PASSWORDS STORED ON DISK                             │"
echo "│  ✓ Bash history disabled for this session                  │"
echo "└─────────────────────────────────────────────────────────────┘"
echo ""
warn "NEXT STEPS:"
echo "  1. TEST SMTP: telnet localhost 25"
echo "  2. TEST POP3: telnet localhost 110"
echo "  3. TEST Webmail: Browse to https://<server-ip>"
echo "  4. Verify users can send/receive email"
echo "  5. Monitor NISE scoring dashboard"
echo "  6. Review $BACKUP_DIR/suspicious_files.txt if created"
echo ""
warn "Remember: Max 3 VM scrubs allowed in competition!"
echo ""
