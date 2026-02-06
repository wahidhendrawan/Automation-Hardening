#!/bin/bash

# macOS Hardening Script
# Requires Sudo

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
else
    echo "[*] Starting macOS Hardening Process..."

    # 1. Enable Application Layer Firewall
    echo "[*] Enabling Firewall..."
    /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
    echo "[*] Firewall enabled."

    # 2. Enable Gatekeeper
    echo "[*] Enabling Gatekeeper..."
    spctl --master-enable
    echo "[*] Gatekeeper enabled."

    # 3. Configure Software Update
    echo "[*] Configuring Software Update to Automatic..."
    softwareupdate --schedule on
    echo "[*] Software update scheduled."

    # 4. Disable Guest Account
    echo "[*] Disabling Guest Account..."
    sysadminctl -guestAccount off
    echo "[*] Guest account disabled."

    # 5. Enable FileVault (Check only)
    echo "[*] Checking FileVault status..."
    fdesetup status

    echo "[*] macOS Hardening Complete."
fi
