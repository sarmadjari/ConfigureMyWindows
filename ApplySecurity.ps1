# Windows 11 Security Configuration Script based on some of CIS Benchmark recomendations.

# Disable SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Enable Windows Defender Antivirus Real-time Protection
Set-MpPreference -DisableRealtimeMonitoring $false

# Enable Windows Defender Firewall
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

# Disable Remote Desktop Protocol (RDP) if not needed
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1

# Enable User Account Control (UAC)
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name "EnableLUA" -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name "ConsentPromptBehaviorAdmin" -Value 5

# Disable PowerShell Script Execution (Requires further consideration based on organization needs)
# Set-ExecutionPolicy Restricted -Scope LocalMachine

# Configure Windows Update settings
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name "AUOptions" -Value 4

# Configure Windows Defender SmartScreen
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name "EnableSmartScreen" -Value 1

# Enable Windows Defender Exploit Guard
Set-MpPreference -ExploitProtectionAuditMode $false
Set-MpPreference -ExploitProtectionEnabled $true

# Disable AutoRun
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "NoAutorun" -Value 1

# Clear Pagefile at Shutdown
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name "ClearPageFileAtShutdown" -Value 1

# Disable Windows Script Host (WSH) if not needed
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name "Enabled" -Value 0

# Set Strong Password Policy
$policy = @{
    "MinPasswordLength" = 14
    "PasswordComplexity" = 1
    "PasswordHistorySize" = 24
    "MaxPasswordAge" = (New-TimeSpan -Days 90).TotalDays
}
Set-LocalUserDefaultPasswordPolicy -Policy $policy

# Disable Guest Account
Set-LocalUser -Name "Guest" -Description "Disabled" -Enabled $false

# Configure Windows Defender Firewall Rules (customize based on your environment)
# Example:
# New-NetFirewallRule -DisplayName "Block Incoming Remote Desktop" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Block

Write-Host "Security configurations applied successfully."
