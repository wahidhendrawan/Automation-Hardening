# Automated Hardening Tools (AH)

This repository contains automated hardening scripts for Linux, Windows, macOS, and Cloud environments (AWS, Azure, GCP).

## Structure

- `linux/`: Bash scripts for Debian/Ubuntu hardening.
- `windows/`: PowerShell scripts for Windows 10/11/Server hardening.
- `macos/`: Bash scripts for macOS hardening.
- `cloud/`: Python-based auditing tool for cloud providers.

## Usage

### Linux
Run as root:
```bash
sudo bash linux/harden.sh
```
Actions: Updates packages, configures UFW firewall, hardens SSH configuration (disables root login).

### Windows
Run PowerShell as Administrator:
```powershell
.\windows\harden.ps1
```
Actions: Enables Firewall, Disables SMBv1, Configures Audit Policies, Disables Guest Account.

### macOS
Run as root:
```bash
sudo bash macos/harden.sh
```
Actions: Enables Firewall, Gatekeeper, Auto-updates, Disables Guest Account.

### Cloud (AWS/Azure/GCP)
Prerequisites: Python 3 and dependencies.
```bash
pip install -r cloud/requirements.txt
```

Run the audit tool:
```bash
python3 cloud/main.py [aws|azure|gcp]
```
Example:
```bash
python3 cloud/main.py aws
```
*Note: Currently only the AWS module implements S3 public access checks. Azure/GCP modules are placeholders.*

## Disclaimer
These scripts are for educational and baseline hardening purposes. Always review the scripts before running them in a production environment.
**Do not run on critical systems without testing.**
