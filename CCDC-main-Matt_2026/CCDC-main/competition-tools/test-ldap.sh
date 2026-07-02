#!/bin/bash
#===============================================================================
# CCDC LDAP Connectivity Test Script
# Run FROM: Email Server (Linux)
# Test TO: Windows AD Server
#===============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}========================================"
echo "  LDAP Connectivity Test"
echo "  Email Server -> Windows AD"
echo -e "========================================${NC}"
echo ""

#===============================================================================
# CONFIGURATION - UPDATE THESE
#===============================================================================
AD_SERVER="172.20.242.10"          # Windows AD IP
AD_DOMAIN="yourdomain.local"       # Your AD domain
BASE_DN="DC=yourdomain,DC=local"   # Base DN (update to match domain)
BIND_USER="CN=Administrator,CN=Users,DC=yourdomain,DC=local"  # Or service account
# BIND_PASS will be prompted

echo -e "${YELLOW}[*] Configuration${NC}"
echo "    AD Server: $AD_SERVER"
echo "    Domain: $AD_DOMAIN"
echo "    Base DN: $BASE_DN"
echo ""

read -p "Enter AD Server IP [$AD_SERVER]: " input
AD_SERVER=${input:-$AD_SERVER}

read -p "Enter AD Domain [$AD_DOMAIN]: " input
AD_DOMAIN=${input:-$AD_DOMAIN}

# Auto-generate Base DN from domain
BASE_DN="DC=$(echo $AD_DOMAIN | sed 's/\./,DC=/g')"
echo "    Using Base DN: $BASE_DN"

read -p "Enter bind username (sAMAccountName) [Administrator]: " BIND_USER
BIND_USER=${BIND_USER:-Administrator}

read -sp "Enter bind password: " BIND_PASS
echo ""
echo ""

#===============================================================================
# TEST 1: Basic Connectivity (Port 389 - LDAP)
#===============================================================================
echo -e "${CYAN}[TEST 1] Port Connectivity${NC}"

echo -n "  Checking LDAP port 389... "
if timeout 3 bash -c "echo > /dev/tcp/$AD_SERVER/389" 2>/dev/null; then
    echo -e "${GREEN}OPEN${NC}"
    LDAP_PORT=389
else
    echo -e "${RED}CLOSED${NC}"
fi

echo -n "  Checking LDAPS port 636... "
if timeout 3 bash -c "echo > /dev/tcp/$AD_SERVER/636" 2>/dev/null; then
    echo -e "${GREEN}OPEN${NC}"
    LDAPS_AVAILABLE=true
else
    echo -e "${YELLOW}CLOSED (SSL not configured)${NC}"
    LDAPS_AVAILABLE=false
fi

echo -n "  Checking Global Catalog 3268... "
if timeout 3 bash -c "echo > /dev/tcp/$AD_SERVER/3268" 2>/dev/null; then
    echo -e "${GREEN}OPEN${NC}"
else
    echo -e "${YELLOW}CLOSED${NC}"
fi
echo ""

#===============================================================================
# TEST 2: LDAP Tools Check
#===============================================================================
echo -e "${CYAN}[TEST 2] Required Tools${NC}"

TOOLS_OK=true

echo -n "  ldapsearch... "
if command -v ldapsearch &>/dev/null; then
    echo -e "${GREEN}INSTALLED${NC}"
else
    echo -e "${RED}MISSING${NC}"
    TOOLS_OK=false
fi

if [ "$TOOLS_OK" = false ]; then
    echo ""
    echo -e "${YELLOW}Installing LDAP tools...${NC}"
    if [ -f /etc/debian_version ]; then
        apt-get update && apt-get install -y ldap-utils
    elif [ -f /etc/redhat-release ]; then
        dnf install -y openldap-clients || yum install -y openldap-clients
    fi
fi
echo ""

#===============================================================================
# TEST 3: Anonymous Bind (usually disabled on AD)
#===============================================================================
echo -e "${CYAN}[TEST 3] Anonymous LDAP Query${NC}"
echo "  (Usually disabled on AD - failure is expected)"
echo ""

ldapsearch -x -H ldap://$AD_SERVER -b "$BASE_DN" -s base "(objectclass=*)" 2>&1 | head -5

echo ""

#===============================================================================
# TEST 4: Authenticated Bind
#===============================================================================
echo -e "${CYAN}[TEST 4] Authenticated LDAP Bind${NC}"
echo ""

# Try simple bind with sAMAccountName
echo "  Attempting bind as: $BIND_USER@$AD_DOMAIN"
echo ""

LDAP_RESULT=$(ldapsearch -x -H ldap://$AD_SERVER \
    -D "$BIND_USER@$AD_DOMAIN" \
    -w "$BIND_PASS" \
    -b "$BASE_DN" \
    -s base "(objectclass=*)" namingContexts 2>&1)

if echo "$LDAP_RESULT" | grep -q "namingContexts"; then
    echo -e "  ${GREEN}SUCCESS - LDAP bind working!${NC}"
    echo ""
    echo "$LDAP_RESULT" | grep -E "(namingContexts|dn:)" | head -10
else
    echo -e "  ${RED}FAILED${NC}"
    echo "$LDAP_RESULT" | head -10
fi
echo ""

#===============================================================================
# TEST 5: Query Users
#===============================================================================
echo -e "${CYAN}[TEST 5] Query AD Users${NC}"
echo ""

echo "  Searching for users in AD..."
echo ""

USER_RESULT=$(ldapsearch -x -H ldap://$AD_SERVER \
    -D "$BIND_USER@$AD_DOMAIN" \
    -w "$BIND_PASS" \
    -b "$BASE_DN" \
    "(objectClass=user)" sAMAccountName mail userPrincipalName 2>&1)

if echo "$USER_RESULT" | grep -q "sAMAccountName"; then
    echo -e "  ${GREEN}SUCCESS - Found users:${NC}"
    echo ""
    echo "$USER_RESULT" | grep -E "^(dn:|sAMAccountName:|mail:)" | head -30
else
    echo -e "  ${RED}FAILED or no users found${NC}"
    echo "$USER_RESULT" | head -10
fi
echo ""

#===============================================================================
# TEST 6: Query Specific User
#===============================================================================
echo -e "${CYAN}[TEST 6] Query Specific User${NC}"
echo ""

read -p "  Enter username to search for [Administrator]: " SEARCH_USER
SEARCH_USER=${SEARCH_USER:-Administrator}

echo ""
echo "  Searching for user: $SEARCH_USER"
echo ""

SPECIFIC_RESULT=$(ldapsearch -x -H ldap://$AD_SERVER \
    -D "$BIND_USER@$AD_DOMAIN" \
    -w "$BIND_PASS" \
    -b "$BASE_DN" \
    "(sAMAccountName=$SEARCH_USER)" \
    dn sAMAccountName mail memberOf userPrincipalName 2>&1)

if echo "$SPECIFIC_RESULT" | grep -q "dn:"; then
    echo -e "  ${GREEN}FOUND:${NC}"
    echo ""
    echo "$SPECIFIC_RESULT" | grep -E "^(dn:|sAMAccountName:|mail:|memberOf:|userPrincipalName:)"
else
    echo -e "  ${RED}NOT FOUND${NC}"
    echo "$SPECIFIC_RESULT" | head -5
fi
echo ""

#===============================================================================
# TEST 7: Test User Authentication (Bind as that user)
#===============================================================================
echo -e "${CYAN}[TEST 7] Test User Authentication${NC}"
echo ""

read -p "  Test authentication for user [$SEARCH_USER]: " AUTH_USER
AUTH_USER=${AUTH_USER:-$SEARCH_USER}

read -sp "  Enter password for $AUTH_USER: " AUTH_PASS
echo ""
echo ""

AUTH_RESULT=$(ldapsearch -x -H ldap://$AD_SERVER \
    -D "$AUTH_USER@$AD_DOMAIN" \
    -w "$AUTH_PASS" \
    -b "$BASE_DN" \
    -s base "(objectclass=*)" 2>&1)

if echo "$AUTH_RESULT" | grep -q "dn:"; then
    echo -e "  ${GREEN}AUTHENTICATION SUCCESSFUL${NC}"
    echo "  User $AUTH_USER can authenticate via LDAP"
else
    echo -e "  ${RED}AUTHENTICATION FAILED${NC}"
    echo "$AUTH_RESULT" | head -5
fi
echo ""

#===============================================================================
# SUMMARY
#===============================================================================
echo -e "${CYAN}========================================"
echo "  LDAP Test Summary"
echo -e "========================================${NC}"
echo ""
echo "  AD Server: $AD_SERVER"
echo "  Domain: $AD_DOMAIN"
echo "  Base DN: $BASE_DN"
echo ""
echo "  For Postfix/Dovecot LDAP configuration, use:"
echo ""
echo "    server_host = $AD_SERVER"
echo "    server_port = 389"
echo "    search_base = $BASE_DN"
echo "    bind_dn = $BIND_USER@$AD_DOMAIN"
echo "    bind_pw = <password>"
echo "    query_filter = (sAMAccountName=%u)"
echo ""
echo "========================================"
