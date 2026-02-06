#!/bin/bash

# Linux Hardening Script
# Targets: Debian/Ubuntu based systems (expandable)

set -e

echo "[*] Starting Linux Hardening Process..."

# 1. Update System
echo "[*] Updating system packages..."
if command -v apt-get &> /dev/null; then
    apt-get update && apt-get upgrade -y
elif command -v yum &> /dev/null; then
    yum update -y
else
    echo "[!] Package manager not found. Skipping update."
fi

# 2. Configure Firewall (UFW)
echo "[*] Configuring Firewall (UFW)..."
if command -v ufw &> /dev/null; then
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    # ufw enable # Commented out to prevent accidental lockout during automation
    echo "[*] UFW rules set. Run 'ufw enable' manually to activate."
else
    echo "[!] UFW not installed. Installing..."
    if command -v apt-get &> /dev/null; then
        apt-get install ufw -y
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow ssh
        echo "[*] UFW installed and configured."
    else
        echo "[!] Cannot install UFW. Manual firewall configuration required."
    fi
fi

# 3. SSH Hardening
echo "[*] Hardening SSH Configuration..."
SSH_CONFIG="/etc/ssh/sshd_config"

if [ -f "$SSH_CONFIG" ]; then
    # Backup config
    cp "$SSH_CONFIG" "$SSH_CONFIG.bak"

    # Disable Root Login
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"

    # Disable Empty Passwords
    sed -i 's/^#PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSH_CONFIG"
    sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSH_CONFIG"

    echo "[*] SSH Configuration updated. Restart sshd to apply changes."
else
    echo "[!] $SSH_CONFIG not found."
fi

# 4. Check for world-writable files (Reporting only)
echo "[*] Scanning for world-writable files..."
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null | head -n 10
echo "[*] (Output truncated to first 10 entries)"

echo "[*] Linux Hardening Complete."
