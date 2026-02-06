# Windows Hardening Script
# Run as Administrator

Write-Host "[*] Starting Windows Hardening Process..." -ForegroundColor Cyan

# 1. Enable Firewall
Write-Host "[*] Enabling Windows Firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-Host "[+] Firewall enabled for all profiles." -ForegroundColor Green

# 2. Disable SMBv1 (Common vulnerability)
Write-Host "[*] Checking SMBv1 status..."
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
if ($smb1.State -eq "Enabled") {
    Write-Host "[!] SMBv1 is enabled. Disabling..."
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    Write-Host "[+] SMBv1 disabled (Restart required to fully apply)." -ForegroundColor Green
} else {
    Write-Host "[+] SMBv1 is already disabled." -ForegroundColor Green
}

# 3. Configure Audit Policies (Basic)
Write-Host "[*] Configuring Audit Policies..."
# Note: auditpol requires elevated privileges
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
Write-Host "[+] Basic audit policies configured." -ForegroundColor Green

# 4. Disable Guest Account
Write-Host "[*] Disabling Guest Account..."
$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($guest -and $guest.Enabled) {
    Disable-LocalUser -Name "Guest"
    Write-Host "[+] Guest account disabled." -ForegroundColor Green
} else {
    Write-Host "[+] Guest account already disabled or not found." -ForegroundColor Green
}

Write-Host "[*] Windows Hardening Complete." -ForegroundColor Cyan
