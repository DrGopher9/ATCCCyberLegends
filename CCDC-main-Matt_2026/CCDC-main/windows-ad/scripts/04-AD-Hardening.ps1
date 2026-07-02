<#
.SYNOPSIS
    CCDC AD Hardening Script
.DESCRIPTION
    Applies security hardening to Active Directory
.NOTES
    Target: Windows Server 2019 (AD/DNS/DHCP)
    Run as: Domain Administrator
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"
Import-Module ActiveDirectory

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CCDC AD Hardening Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

#region Disable Guest Account
Write-Host "[*] Disabling Guest account..." -ForegroundColor Yellow
try {
    Disable-ADAccount -Identity "Guest"
    Write-Host "[+] Guest account disabled" -ForegroundColor Green
} catch {
    Write-Host "[!] Guest account already disabled or error" -ForegroundColor Gray
}
#endregion

#region Protected Users Group
Write-Host "`n[*] Adding Domain Admins to Protected Users group..." -ForegroundColor Yellow
Write-Host "    (Provides additional credential theft protection)" -ForegroundColor Gray

$response = Read-Host "Add Domain Admins to Protected Users? (y/N)"
if ($response -eq "y") {
    try {
        $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive |
            Where-Object { $_.objectClass -eq "user" }

        foreach ($admin in $domainAdmins) {
            Add-ADGroupMember -Identity "Protected Users" -Members $admin.SamAccountName -ErrorAction SilentlyContinue
            Write-Host "    [+] Added: $($admin.SamAccountName)" -ForegroundColor Green
        }
    } catch {
        Write-Host "[-] Error adding to Protected Users: $_" -ForegroundColor Red
    }
}
#endregion

#region Disable LLMNR
Write-Host "`n[*] Disabling LLMNR (Link-Local Multicast Name Resolution)..." -ForegroundColor Yellow
Write-Host "    (Prevents LLMNR poisoning attacks)" -ForegroundColor Gray

try {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "EnableMulticast" -Value 0 -Type DWord
    Write-Host "[+] LLMNR disabled" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to disable LLMNR: $_" -ForegroundColor Red
}
#endregion

#region Disable NBT-NS
Write-Host "`n[*] Disabling NetBIOS over TCP/IP..." -ForegroundColor Yellow
Write-Host "    (Prevents NBT-NS poisoning attacks)" -ForegroundColor Gray

try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
    Get-ChildItem $regPath | ForEach-Object {
        Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 2
    }
    Write-Host "[+] NetBIOS disabled on all interfaces" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to disable NetBIOS: $_" -ForegroundColor Red
}
#endregion

#region Disable WPAD
Write-Host "`n[*] Disabling WPAD (Web Proxy Auto-Discovery)..." -ForegroundColor Yellow
try {
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad"
    if (!(Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "WpadOverride" -Value 1 -Type DWord
    Write-Host "[+] WPAD disabled" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to disable WPAD: $_" -ForegroundColor Red
}
#endregion

#region SMB Signing
Write-Host "`n[*] Enabling SMB Signing..." -ForegroundColor Yellow
Write-Host "    (Prevents SMB relay attacks)" -ForegroundColor Gray

try {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
    Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
    Write-Host "[+] SMB Signing enabled (required)" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to configure SMB signing: $_" -ForegroundColor Red
}
#endregion

#region Disable SMBv1
Write-Host "`n[*] Disabling SMBv1..." -ForegroundColor Yellow
try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
    Write-Host "[+] SMBv1 disabled" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to disable SMBv1: $_" -ForegroundColor Red
}
#endregion

#region LM Hash Storage
Write-Host "`n[*] Disabling LM Hash storage..." -ForegroundColor Yellow
try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $regPath -Name "NoLMHash" -Value 1 -Type DWord
    Write-Host "[+] LM Hash storage disabled" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to disable LM Hash: $_" -ForegroundColor Red
}
#endregion

#region NTLMv1 Restriction
Write-Host "`n[*] Restricting NTLM authentication..." -ForegroundColor Yellow
try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    # LMCompatibilityLevel: 5 = Send NTLMv2 response only, refuse LM & NTLM
    Set-ItemProperty -Path $regPath -Name "LMCompatibilityLevel" -Value 5 -Type DWord
    Write-Host "[+] NTLM restricted to NTLMv2 only" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to configure NTLM: $_" -ForegroundColor Red
}
#endregion

#region Credential Guard (if supported)
Write-Host "`n[*] Checking Credential Guard support..." -ForegroundColor Yellow
try {
    $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    if ($deviceGuard.SecurityServicesConfigured -contains 1) {
        Write-Host "[+] Credential Guard is available" -ForegroundColor Green
    } else {
        Write-Host "[!] Credential Guard not configured (requires Hyper-V and UEFI)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] Could not check Credential Guard status" -ForegroundColor Yellow
}
#endregion

#region Audit Policy
Write-Host "`n[*] Configuring audit policy..." -ForegroundColor Yellow
try {
    # Enable success and failure auditing for key events
    auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
    auditpol /set /category:"Account Logon" /success:enable /failure:enable
    auditpol /set /category:"Account Management" /success:enable /failure:enable
    auditpol /set /category:"Privilege Use" /success:enable /failure:enable
    auditpol /set /category:"System" /success:enable /failure:enable
    auditpol /set /category:"Object Access" /failure:enable
    auditpol /set /category:"Policy Change" /success:enable /failure:enable

    Write-Host "[+] Audit policy configured" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to configure audit policy: $_" -ForegroundColor Red
}
#endregion

#region Windows Firewall
Write-Host "`n[*] Enabling Windows Firewall..." -ForegroundColor Yellow
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Write-Host "[+] Windows Firewall enabled on all profiles" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to enable firewall: $_" -ForegroundColor Red
}
#endregion

#region Disable Print Spooler (if not needed)
Write-Host "`n[*] Print Spooler service (PrintNightmare vulnerability)..." -ForegroundColor Yellow
$response = Read-Host "Disable Print Spooler service? (y/N)"
if ($response -eq "y") {
    try {
        Stop-Service -Name "Spooler" -Force
        Set-Service -Name "Spooler" -StartupType Disabled
        Write-Host "[+] Print Spooler disabled" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to disable Print Spooler: $_" -ForegroundColor Red
    }
}
#endregion

#region Remote Desktop Security
Write-Host "`n[*] Configuring Remote Desktop security..." -ForegroundColor Yellow
try {
    # Require NLA
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
    Set-ItemProperty -Path $regPath -Name "UserAuthentication" -Value 1 -Type DWord

    # Set encryption level to high
    Set-ItemProperty -Path $regPath -Name "MinEncryptionLevel" -Value 3 -Type DWord

    Write-Host "[+] RDP NLA enabled, encryption set to high" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to configure RDP: $_" -ForegroundColor Red
}
#endregion

#region Password Policy Check
Write-Host "`n[*] Current Domain Password Policy:" -ForegroundColor Yellow
try {
    $policy = Get-ADDefaultDomainPasswordPolicy
    Write-Host "    Min Password Length: $($policy.MinPasswordLength)"
    Write-Host "    Password History: $($policy.PasswordHistoryCount)"
    Write-Host "    Max Password Age: $($policy.MaxPasswordAge)"
    Write-Host "    Complexity Required: $($policy.ComplexityEnabled)"
    Write-Host "    Lockout Threshold: $($policy.LockoutThreshold)"
    Write-Host "    Lockout Duration: $($policy.LockoutDuration)"

    if ($policy.MinPasswordLength -lt 12) {
        Write-Host ""
        Write-Host "[!] Consider increasing minimum password length to 12+" -ForegroundColor Yellow
    }

    if ($policy.LockoutThreshold -eq 0) {
        Write-Host "[!] Account lockout is DISABLED - consider enabling" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[-] Could not read password policy" -ForegroundColor Red
}
#endregion

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  AD Hardening Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Applied Hardening:" -ForegroundColor Yellow
Write-Host "  [+] Guest account disabled"
Write-Host "  [+] LLMNR disabled"
Write-Host "  [+] NetBIOS disabled"
Write-Host "  [+] WPAD disabled"
Write-Host "  [+] SMB Signing required"
Write-Host "  [+] SMBv1 disabled"
Write-Host "  [+] LM Hash storage disabled"
Write-Host "  [+] NTLM restricted to v2"
Write-Host "  [+] Audit policy configured"
Write-Host "  [+] Firewall enabled"
Write-Host "  [+] RDP NLA enabled"
Write-Host ""
Write-Host "RECOMMENDED ADDITIONAL STEPS:" -ForegroundColor Yellow
Write-Host "  1. Create and apply security GPOs"
Write-Host "  2. Configure LAPS for local admin passwords"
Write-Host "  3. Implement tiered admin model"
Write-Host "  4. Enable Advanced Audit Policy"
Write-Host ""
Write-Host "NOTE: Some changes may require a restart to take effect." -ForegroundColor Yellow
