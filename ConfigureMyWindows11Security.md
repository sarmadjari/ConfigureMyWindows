# Windows 11 CIS Security Configuration Script

## Overview
This PowerShell script is designed to configure Windows 11 security settings according to the recommendations provided by the Center for Internet Security (CIS). It offers both granular control over individual security settings and the option to apply all recommended configurations at once.

## Features
- **Selective Configuration**: Apply specific security measures based on your system's needs.
- **Comprehensive Hardening**: Use the `-ApplyAll` switch to enforce all CIS benchmarks.
- **Detailed Logging**: Each function logs actions taken and errors, ensuring transparency and ease of troubleshooting.

## Prerequisites
- Windows 11 Operating System
- PowerShell 5.1 or higher
- Administrative privileges on the Windows 11 machine where the script will be executed

## Usage

### Notes
Always run the script in a non-production environment first to ensure that it functions as expected without disrupting existing configurations.
Ensure that you have backups or system restore points before making significant changes to system configurations.

### Parameters
Each setting in the script can be applied independently by using its corresponding switch. Below are the parameters that can be used:

- `-ApplySMBv1`: Disables SMBv1 protocol.
- `-ApplyWindowsDefenderAntivirus`: Enables real-time protection for Windows Defender Antivirus.
- `-ApplyWindowsDefenderFirewall`: Activates the firewall across all profiles.
- `-ApplyRemoteDesktopProtocol`: Disables Remote Desktop Protocol (RDP).
- `-ApplyUserAccountControl`: Configures User Account Control settings for maximum security.
- `-ApplyAuditPolicy`: Sets audit policies for monitoring both successful and failed security events.
- `-ApplyWindowsUpdateSettings`: Configures Windows Update to automatically download and install updates.
- `-ApplyWindowsDefenderSmartScreen`: Enables SmartScreen filter for additional protection.
- `-ApplyWindowsDefenderExploitGuard`: Applies protective settings via Windows Defender Exploit Guard.
- `-ApplyFirewallConfiguration`: Ensures correct firewall configuration.
- `-ApplyAutoRun`: Disables AutoRun and AutoPlay features.
- `-ApplyPageFileClearance`: Sets the system to clear the page file at every shutdown.
- `-ApplyWindowsScriptHost`: Disables the Windows Script Host.
- `-ApplyPasswordPolicy`: Enforces strong password policies.
- `-ApplyGuestAccount`: Disables the guest account.
- `-ApplyAll`: Applies all available security configurations.

### Running the Script
To run the script, open PowerShell as an administrator and navigate to the directory containing the script. Execute the script with the desired parameters. For example:

```powershell
# To apply all recommended settings:
.\Secure-Windows11.ps1 -ApplyAll

# To apply specific settings, such as SMBv1 and firewall configuration:
.\Secure-Windows11.ps1 -ApplySMBv1 -ApplyFirewallConfiguration
