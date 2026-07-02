<#
.SYNOPSIS
    Test LDAP connectivity from Windows AD server
.DESCRIPTION
    Verifies LDAP is working on the AD server and tests queries
.NOTES
    Run on: Windows AD Server
#>

Write-Host @"

================================================================================
  LDAP Service Test - Windows AD Server
================================================================================

"@ -ForegroundColor Cyan

#===============================================================================
# TEST 1: Check LDAP Service Status
#===============================================================================
Write-Host "[TEST 1] LDAP/AD DS Service Status" -ForegroundColor Yellow
Write-Host ""

$services = @("NTDS", "DNS", "Netlogon", "KDC")

foreach ($svc in $services) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            Write-Host "  [OK] $($service.DisplayName) - Running" -ForegroundColor Green
        } else {
            Write-Host "  [!!] $($service.DisplayName) - $($service.Status)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [--] $svc - Not found" -ForegroundColor Gray
    }
}
Write-Host ""

#===============================================================================
# TEST 2: Check LDAP Ports
#===============================================================================
Write-Host "[TEST 2] LDAP Port Listeners" -ForegroundColor Yellow
Write-Host ""

$ports = @(
    @{Port=389; Name="LDAP"},
    @{Port=636; Name="LDAPS (SSL)"},
    @{Port=3268; Name="Global Catalog"},
    @{Port=3269; Name="Global Catalog SSL"}
)

foreach ($p in $ports) {
    $listener = Get-NetTCPConnection -LocalPort $p.Port -State Listen -ErrorAction SilentlyContinue
    if ($listener) {
        Write-Host "  [OK] Port $($p.Port) ($($p.Name)) - Listening" -ForegroundColor Green
    } else {
        Write-Host "  [--] Port $($p.Port) ($($p.Name)) - Not listening" -ForegroundColor Yellow
    }
}
Write-Host ""

#===============================================================================
# TEST 3: Domain Information
#===============================================================================
Write-Host "[TEST 3] Domain Information" -ForegroundColor Yellow
Write-Host ""

try {
    $domain = Get-ADDomain
    Write-Host "  Domain Name: $($domain.DNSRoot)" -ForegroundColor White
    Write-Host "  NetBIOS Name: $($domain.NetBIOSName)" -ForegroundColor White
    Write-Host "  Distinguished Name: $($domain.DistinguishedName)" -ForegroundColor White
    Write-Host "  Domain Controllers:" -ForegroundColor White
    $domain.ReplicaDirectoryServers | ForEach-Object { Write-Host "    - $_" }
    Write-Host ""
    Write-Host "  [OK] AD Domain is accessible" -ForegroundColor Green
} catch {
    Write-Host "  [!!] Failed to query AD Domain: $_" -ForegroundColor Red
}
Write-Host ""

#===============================================================================
# TEST 4: Test LDAP Query (Local)
#===============================================================================
Write-Host "[TEST 4] Local LDAP Query Test" -ForegroundColor Yellow
Write-Host ""

try {
    $users = Get-ADUser -Filter * -Properties mail, Enabled |
             Where-Object { $_.Enabled -eq $true } |
             Select-Object -First 10 SamAccountName, mail, Enabled

    Write-Host "  Found $(@(Get-ADUser -Filter {Enabled -eq $true}).Count) enabled users" -ForegroundColor White
    Write-Host ""
    Write-Host "  Sample users (first 10):" -ForegroundColor White
    $users | Format-Table -AutoSize | Out-String | Write-Host
    Write-Host "  [OK] LDAP queries working" -ForegroundColor Green
} catch {
    Write-Host "  [!!] LDAP query failed: $_" -ForegroundColor Red
}
Write-Host ""

#===============================================================================
# TEST 5: Test Remote LDAP Connection
#===============================================================================
Write-Host "[TEST 5] Test Remote LDAP Access" -ForegroundColor Yellow
Write-Host ""

$EmailServerIP = Read-Host "  Enter Email Server IP to test from (or press Enter to skip)"

if ($EmailServerIP) {
    Write-Host ""
    Write-Host "  Testing if $EmailServerIP can reach LDAP ports..." -ForegroundColor White

    # Check firewall rules
    Write-Host ""
    Write-Host "  Checking Windows Firewall rules for LDAP:" -ForegroundColor White

    $ldapRules = Get-NetFirewallRule -DisplayName "*LDAP*" -ErrorAction SilentlyContinue |
                 Where-Object { $_.Enabled -eq $true }

    if ($ldapRules) {
        $ldapRules | ForEach-Object {
            $action = if ($_.Action -eq "Allow") { "ALLOW" } else { "BLOCK" }
            Write-Host "    [$action] $($_.DisplayName)" -ForegroundColor $(if ($_.Action -eq "Allow") {"Green"} else {"Red"})
        }
    } else {
        Write-Host "    No specific LDAP firewall rules found" -ForegroundColor Yellow
        Write-Host "    LDAP may be allowed by default AD rules" -ForegroundColor Yellow
    }

    # Check if Domain Controller firewall rules exist
    $dcRules = Get-NetFirewallRule -DisplayGroup "*Active Directory*" -ErrorAction SilentlyContinue |
               Where-Object { $_.Enabled -eq $true -and $_.Action -eq "Allow" }

    if ($dcRules) {
        Write-Host ""
        Write-Host "  Active Directory firewall rules (enabled):" -ForegroundColor White
        Write-Host "    Found $(@($dcRules).Count) AD-related allow rules" -ForegroundColor Green
    }
}
Write-Host ""

#===============================================================================
# TEST 6: Create/Verify LDAP Bind Account
#===============================================================================
Write-Host "[TEST 6] LDAP Bind Account for Email Server" -ForegroundColor Yellow
Write-Host ""

$bindAccountName = "svc_ldap_mail"
$bindAccount = Get-ADUser -Filter {SamAccountName -eq $bindAccountName} -ErrorAction SilentlyContinue

if ($bindAccount) {
    Write-Host "  [OK] Service account '$bindAccountName' exists" -ForegroundColor Green
    Write-Host "      DN: $($bindAccount.DistinguishedName)" -ForegroundColor White
} else {
    Write-Host "  [--] Service account '$bindAccountName' not found" -ForegroundColor Yellow
    Write-Host ""
    $create = Read-Host "  Create LDAP bind account for email server? (y/n)"

    if ($create -eq 'y') {
        $password = Read-Host "  Enter password for service account" -AsSecureString

        try {
            New-ADUser -Name "LDAP Mail Service" `
                       -SamAccountName $bindAccountName `
                       -UserPrincipalName "$bindAccountName@$((Get-ADDomain).DNSRoot)" `
                       -AccountPassword $password `
                       -Enabled $true `
                       -PasswordNeverExpires $true `
                       -CannotChangePassword $true `
                       -Description "Service account for email server LDAP authentication"

            Write-Host ""
            Write-Host "  [OK] Created service account: $bindAccountName" -ForegroundColor Green

            $newAccount = Get-ADUser $bindAccountName
            Write-Host "      DN: $($newAccount.DistinguishedName)" -ForegroundColor White
        } catch {
            Write-Host "  [!!] Failed to create account: $_" -ForegroundColor Red
        }
    }
}
Write-Host ""

#===============================================================================
# SUMMARY - Configuration for Email Server
#===============================================================================
Write-Host @"
================================================================================
  LDAP Configuration for Email Server (Postfix/Dovecot)
================================================================================

"@ -ForegroundColor Cyan

$domain = Get-ADDomain
$dc = (Get-ADDomainController).HostName

Write-Host "  Use these settings on your email server:" -ForegroundColor White
Write-Host ""
Write-Host "  LDAP Server:     $(hostname) or $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.PrefixOrigin -eq 'Manual' -or $_.PrefixOrigin -eq 'Dhcp'} | Select-Object -First 1).IPAddress)" -ForegroundColor Yellow
Write-Host "  LDAP Port:       389 (or 636 for SSL)" -ForegroundColor Yellow
Write-Host "  Base DN:         $($domain.DistinguishedName)" -ForegroundColor Yellow
Write-Host "  Bind DN:         $bindAccountName@$($domain.DNSRoot)" -ForegroundColor Yellow
Write-Host "  User Filter:     (sAMAccountName=%u)" -ForegroundColor Yellow
Write-Host "  Mail Attribute:  mail" -ForegroundColor Yellow
Write-Host ""
Write-Host @"
================================================================================
  Example Dovecot LDAP Config (/etc/dovecot/dovecot-ldap.conf.ext)
================================================================================

  hosts = $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.PrefixOrigin -eq 'Manual' -or $_.PrefixOrigin -eq 'Dhcp'} | Select-Object -First 1).IPAddress)
  dn = $bindAccountName@$($domain.DNSRoot)
  dnpass = <password>
  auth_bind = yes
  base = $($domain.DistinguishedName)
  user_filter = (&(objectClass=user)(sAMAccountName=%u))
  pass_filter = (&(objectClass=user)(sAMAccountName=%u))

================================================================================
  Example Postfix LDAP Config (/etc/postfix/ldap-users.cf)
================================================================================

  server_host = $((Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.PrefixOrigin -eq 'Manual' -or $_.PrefixOrigin -eq 'Dhcp'} | Select-Object -First 1).IPAddress)
  server_port = 389
  search_base = $($domain.DistinguishedName)
  bind = yes
  bind_dn = $bindAccountName@$($domain.DNSRoot)
  bind_pw = <password>
  query_filter = (sAMAccountName=%u)
  result_attribute = mail

================================================================================
"@ -ForegroundColor Gray
