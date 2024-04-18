<#
.SYNOPSIS
This PowerShell script assesses the security configurations of a Windows 11 system based on CIS Benchmarks.

.DESCRIPTION
The script performs checks on various system settings against the CIS Benchmark for Windows 11 to determine
compliance with recommended security settings. Each function in this script corresponds to a specific CIS
recommendation and will output the current state, the recommended state, and a score based on compliance.

# Each check follows this pattern:
# - Check a specific configuration against CIS recommendations.
# - Provide a recommendation message.
# - Evaluate current system configuration.
# - Score the check as fully compliant (100) or non-compliant (0).
#>

# Function to check a registry path for a specific property
function CheckRegistryPath {
    param (
        [string]$path,
        [string]$property
    )
    if (Test-Path $path) {
        $regValue = Get-ItemProperty -Path $path -Name $property -ErrorAction SilentlyContinue
        if ($null -ne $regValue) {
            return $regValue.$property
        } else {
            return "Property not found"
        }
    } else {
        return "Path not found"
    }
}



# Function to check if SMBv1 is disabled
function AssessSMBv1 {
    $name = "Server Message Block (SMBv1)"
    $recommended = "$name should be disabled."
    
    # Using CheckRegistryPath function to check the SMB1 parameter
    $smb1Status = CheckRegistryPath -path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -property 'SMB1'
    
    # Interpreting the return value from CheckRegistryPath
    $current = if ($smb1Status -eq 0) {
        "SMBv1 is disabled."
    } else {
        "SMBv1 is enabled."
    }
    
    $score = if ($smb1Status -eq 0) { 100 } else { 0 }
    $command = if ($score -eq 100) { "" } else { "-ApplySMBv1" }

    return $name, $recommended, $current, $score, $command
}


# Function to check if Windows Defender Antivirus real-time protection is enabled
function AssessWindowsDefenderAntivirus {
    $name = "Windows Defender Antivirus real-time protection"
    $recommended = "$name should be enabled."
    $realTimeProtection = Get-MpPreference
    $current = if ($realTimeProtection -and $realTimeProtection.RealTimeMonitoringEnabled) {
        "$name is enabled."
    } else {
        "$name is disabled."
    }
    $score = if ($realTimeProtection -and $realTimeProtection.RealTimeMonitoringEnabled) { 100 } else { 0 }
    $command = if ($realTimeProtection -and $realTimeProtection.RealTimeMonitoringEnabled) { "" } else { "-ApplyWindowsDefenderAntivirus" }
    return $name, $recommended, $current, $score, $command
}

# Function to check if Windows Defender Firewall is enabled
function AssessWindowsDefenderFirewall {
    $name = "Windows Defender Firewall"
    $recommended = "$name should be enabled."
    $firewallStatus = Get-NetFirewallProfile | Where-Object { $_.Enabled }
    $current = if ($firewallStatus) {
        "$name is enabled."
    } else {
        "$name is disabled."
    }
    $score = if ($firewallStatus) { 100 } else { 0 }
    $command = if ($score -eq 100) { "" } else { "-ApplyWindowsDefenderFirewall" }
    return $name, $recommended, $current, $score, $command
}

# Function to check if Remote Desktop Protocol (RDP) is disabled
function AssessRemoteDesktopProtocol {
    $name = "Remote Desktop Protocol (RDP)"
    $recommended = "$name should be disabled."
    $rdpStatus = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    $current = if ($rdpStatus -and $rdpStatus.fDenyTSConnections -eq 1) {
        "$name is disabled."
    } else {
        "$name is enabled."
    }
    $score = if ($rdpStatus -and $rdpStatus.fDenyTSConnections -eq 1) { 100 } else { 0 }
    $command = if ($rdpStatus -and $rdpStatus.fDenyTSConnections -eq 1) { "" } else { "-ApplyRemoteDesktopProtocol" }
    return $name, $recommended, $current, $score, $command
}

# Function to check if User Account Control (UAC) is enabled with recommended settings
function AssessUserAccountControl {
    $name = "User Account Control (UAC)"
    $recommended = "$name should be enabled with the highest security settings."
    $uacSettings = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $enableLUA = $uacSettings.EnableLUA -eq 1
    $consentPromptBehaviorAdmin = $uacSettings.ConsentPromptBehaviorAdmin -eq 2  # 2 means 'Prompt for consent on the secure desktop'
    $promptOnSecureDesktop = $uacSettings.PromptOnSecureDesktop -eq 1

    $current = if ($enableLUA -and $consentPromptBehaviorAdmin -and $promptOnSecureDesktop) {
        "$name is enabled with the highest security settings."
    } else {
        "$name is not enabled with the highest security settings."
    }
    $score = if ($enableLUA -and $consentPromptBehaviorAdmin -and $promptOnSecureDesktop) { 100 } else { 0 }
    $command = if ($enableLUA -and $consentPromptBehaviorAdmin -and $promptOnSecureDesktop) { "" } else { "-ApplyUserAccountControl" }
    return $name, $recommended, $current, $score, $command
}

# Function to check if the Audit policies are configured to log both success and failure events.
function AssessAuditPolicy {
    $name = "Audit Policy Configuration"
    $recommended = "$name should log both success and failure."
    $auditPolicy = CheckRegistryPath -path 'HKLM:\Software\Policies\Microsoft\Windows\Audit' -property "AuditBaseObjects"
    $current = if ($auditPolicy -eq 1) {
        "$name logs both success and failure."
    } else {
        "$name does not log both."
    }
    $score = if ($auditPolicy -eq 1) { 100 } else { 0 }
    $command = if ($score -eq 100) { "" } else { "-ApplyAuditPolicy" }
    return $name, $recommended, $current, $score, $command
}
 
# Function to check Windows Update settings
function AssessWindowsUpdateSettings {
    $name = "Windows Update Settings"
    $recommended = "Check if Windows Update settings follow the CIS Benchmark recommendations."

    # Define the registry paths and keys
    $registryPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $auOptionsKey = "AUOptions"  # Value of 4 means 'Install updates automatically'
    $scheduledInstallDayKey = "ScheduledInstallDay"  # Value of 7 means 'Every Sunday'
    $scheduledInstallTimeKey = "ScheduledInstallTime"  # Value in hours (0-23)

    try {
        # Use CheckRegistryPath to retrieve Windows Update settings from the registry
        $auOptions = CheckRegistryPath -path $registryPath -property $auOptionsKey
        $scheduledInstallDay = CheckRegistryPath -path $registryPath -property $scheduledInstallDayKey
        $scheduledInstallTime = CheckRegistryPath -path $registryPath -property $scheduledInstallTimeKey
        
        # Initialize compliance flag and reason list
        $compliance = $true
        $reason = @()

        # Assess the retrieved settings for compliance with CIS recommendations
        if ($auOptions -ne 4) {
            $reason += "Automatic updates are not set to install automatically."
            $compliance = $false
        }

        if ($scheduledInstallDay -ne 7 -or $scheduledInstallTime -lt 17) {
            $reason += "Updates are not scheduled for non-business hours (Sunday after 5:00 PM)."
            $compliance = $false
        }

        # Determine the current status based on compliance
        if ($compliance) {
            $current = "Windows Update settings comply with CIS Benchmark recommendations."
        } else {
            $current = "Windows Update settings do not comply with CIS Benchmark recommendations!"
            $current += "`n - Reason(s): $($reason -join "`n              ")"
        }

        # Score based on compliance
        $score = if ($compliance) { 100 } else { 0 }
    }
    catch {
        $current = "Error: Unable to retrieve Windows Update settings from the registry - $($_.Exception.Message)"
        $score = 0
    }

    $command = if ($score -eq 100) { "" } else { "-ApplyWindowsUpdateSettings" }

    return $name, $recommended, $current, $score, $command
}


# Function to check if Windows Defender SmartScreen is enabled
function AssessWindowsDefenderSmartScreen {
    $name = "Windows Defender SmartScreen"
    $recommended = "$name should be consistently enabled across all configurations for maximum security."

    try {
        $smartScreenStatus = "Not Configured"
        
        # Attempt to retrieve the SmartScreenEnabled property from MpPreference safely
        $mpPreference = Get-MpPreference
        $mpSmartScreenStatus = $null
        if ($mpPreference.PSObject.Properties.Name -contains "SmartScreenEnabled") {
            $mpSmartScreenStatus = $mpPreference.SmartScreenEnabled
        }
        
        # Check Group Policy and Explorer settings via a helper function that safely checks registry paths
        $gpSmartScreen = CheckRegistryPath -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -property "EnableSmartScreen"
        $explorerSmartScreen = CheckRegistryPath -path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -property "SmartScreenEnabled"

        # Determine the final effective status based on prioritization of Group Policy over local settings
        if ($gpSmartScreen -eq "Enabled" -or $mpSmartScreenStatus -eq "Enabled" -or $explorerSmartScreen -eq "Prompt") {
            $smartScreenStatus = "Enabled"
        } elseif ($gpSmartScreen -eq "Disabled" -or $explorerSmartScreen -eq "Off") {
            $smartScreenStatus = "Disabled"
        }

        $current = "SmartScreen status: $smartScreenStatus"
        $score = if ($smartScreenStatus -eq "Enabled") { 100 } else { 0 }
    } catch {
        $current = "Error retrieving SmartScreen settings: $_"
        $score = 0
    }

    $command = if ($score -eq 100) { "" } else { "-ApplyWindowsDefenderSmartScreen" }

    return $name, $recommended, $current, $score, $command
}



# Function to check if Windows Defender Exploit Guard is enabled
function AssessWindowsDefenderExploitGuard {
    $name = "Windows Defender Exploit Guard"
    $recommended = "$name should be enabled."
    
    try {
        $asrRulesEnabled = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions -ErrorAction Stop
        
        # Checking if ASR rules are correctly configured (assuming '1' signifies enabled)
        $current = if ($asrRulesEnabled -contains 1) {
            "Exploit Guard is enabled."
        } else {
            "Exploit Guard is partially enabled or disabled."
        }
    } catch {
        $current = "Error retrieving Exploit Guard settings: $_"
    }
    
    $score = if ($asrRulesEnabled -contains 1) { 100 } else { 0 }
    $command = if ($score -eq 100) { "" } else { "-ApplyWindowsDefenderExploitGuard" }

    return $name, $recommended, $current, $score, $command
}



# Function to check if Firewall Configuration is enabled for all profiles
function AssessFirewallConfiguration {
    $name = "Firewall Configuration"
    $recommended = "$name should be enabled for all profiles."
    $firewallStatus = Get-NetFirewallProfile
    $allEnabled = -not ($firewallStatus | ForEach-Object { $_.Enabled } | Where-Object { $_ -eq $false })
    $current = if ($allEnabled) {
        "$name is fully enabled."
    } else {
        "$name is not fully enabled."
    }
    $score = if ($allEnabled) { 100 } else { 0 }
    $command = if ($score -eq 100) { "" } else { "-ApplyFirewallConfiguration" }

    return $name, $recommended, $current, $score, $command
}


# Function to check if AutoRun is disabled
function AssessAutoRun {
    $name = "AutoRun"
    $recommended = "$name should be disabled."
    try {
        # Using the CheckRegistryPath function to retrieve the AutoRun setting
        $autoRunStatus = CheckRegistryPath -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -property "NoDriveTypeAutoRun"
        
        # Interpret the return value to determine if AutoRun is disabled
        $current = if ($autoRunStatus -eq 0xff) {
            "AutoRun is disabled."
        } else {
            "AutoRun is not fully disabled."
        }
    } catch {
        $current = "Error retrieving AutoRun settings: $_"
    }

    $score = if ($autoRunStatus -eq 0xff) { 100 } else { 0 }
    $command = if ($score -eq 100) { "" } else { "-ApplyAutoRun" }

    return $name, $recommended, $current, $score, $command
}


# Function to check if Pagefile clearance at shutdown is enabled
function AssessPageFileClearance {
    $name = "Pagefile clearance at shutdown"
    $recommended = "$name should be enabled."
    try {
        # Using CheckRegistryPath to check the 'ClearPageFileAtShutdown' registry setting
        $pageFileClearanceStatus = CheckRegistryPath -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -property "ClearPageFileAtShutdown"
        
        # Interpreting the return value to determine if pagefile clearance is enabled
        $current = if ($pageFileClearanceStatus -eq 1) {
            "Pagefile clearance at shutdown is enabled."
        } else {
            "Pagefile clearance at shutdown is not enabled."
        }
    } catch {
        $current = "Error retrieving Pagefile clearance settings: $_"
    }

    $score = if ($pageFileClearanceStatus -eq 1) { 100 } else { 0 }
    $command = $command = if ($score -eq 100) { "" } else { "-ApplyPageFileClearance" }

    return $name, $recommended, $current, $score, $command
}


function AssessWindowsScriptHost {
    $name = "Windows Script Host (WSH)"
    $recommended = "$name should be disabled."

    $score = 0 # Default score if WSH is not disabled

    try {
        # Using CheckRegistryPath to check WSH settings in HKLM and HKCU
        # Assume CheckRegistryPath returns $null if the property or path does not exist
        $wshMachineStatus = CheckRegistryPath -path "HKLM:\Software\Microsoft\Windows Script Host\Settings" -property "Enabled"
        $wshUserStatus = CheckRegistryPath -path "HKCU:\Software\Microsoft\Windows Script Host\Settings" -property "Enabled"

        # Determine the current status and report where WSH is enabled
        if ($wshMachineStatus -eq 1 -and $wshUserStatus -eq 1) {
            $current = "Windows Script Host is enabled at both the system and user levels."
        } elseif ($wshMachineStatus -eq 1) {
            $current = "Windows Script Host is enabled at the system level."
        } elseif ($wshUserStatus -eq 1) {
            $current = "Windows Script Host is enabled at the user level."
        } else {
            $current = "Windows Script Host is disabled."
            $score = 100 # Score 100 if WSH is disabled
        }
    } catch {
        $current = "Error retrieving Windows Script Host settings: $_"
    }

    $command = if ($score -eq 100) { "" } else { "-ApplyWindowsScriptHost" }

    return $name, $recommended, $current, $score, $command
}




# Function to check if Password Policy is configured as recommended
function AssessPasswordPolicy {
    $name = "Password Policy"
    $recommended = "$name should enforce strong complexity and a minimum length of 14 characters."

    # Get the current password policy settings from the registry
    $passwordPolicy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue

    if ($passwordPolicy) {
        $complexityEnabled = $passwordPolicy.PasswordComplexity -eq 1  # Ensure complexity is enabled
        $minLength = $passwordPolicy.MinimumPasswordLength -ge 14  # Minimum length of 14 characters

        # Calculate the compliance status
        $complexityStatus = if ($complexityEnabled) { "Compliant" } else { "Non-compliant" }
        $minLengthStatus = if ($minLength) { "Compliant" } else { "Non-compliant" }

        $current = "Password Complexity: $complexityStatus, Minimum Password Length: $minLengthStatus"

        # Calculate the score based on both complexity and minimum length requirements
        $score = if ($complexityEnabled -and $minLength) { 100 } else { 0 }
    } else {
        $current = "Password Policy configuration not found or inaccessible."
        $score = 0
    }

    $command = if ($score -eq 100) { "" } else { "-ApplyPasswordPolicy" }

    return $name, $recommended, $current, $score, $command
}



# Function to check if Guest Account is disabled
function AssessGuestAccount {
    $name = "Guest Account"
    $recommended = "$name should be disabled."
    $guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    $current = if ($guestAccount) {
        "$name is enabled."
    } else {
        "$name is disabled."
    }
    $score = if ($current -eq "$name is disabled.") { 100 } else { 0 }
    $command = if ($score -eq 100) { "" } else { "-ApplyGuestAccount" }

    return $name, $recommended, $current, $score, $command
}

# Array to store assessment functions
$assessmentFunctions = @(
    "AssessSMBv1",
    "AssessWindowsDefenderAntivirus",
    "AssessWindowsDefenderFirewall",
    "AssessRemoteDesktopProtocol",
    "AssessUserAccountControl",
    "AssessAuditPolicy",
    "AssessWindowsUpdateSettings",
    "AssessWindowsDefenderSmartScreen",
    "AssessWindowsDefenderExploitGuard",
    "AssessFirewallConfiguration",
    "AssessAutoRun",
    "AssessPageFileClearance",
    "AssessWindowsScriptHost",
    "AssessPasswordPolicy",
    "AssessGuestAccount"
)

# Array to store assessment results
$assessmentResults = @()

# Loop through each assessment function, invoke it, and store the results
foreach ($functionName in $assessmentFunctions) {
    $result = & $functionName
    $assessmentResults += , $result
}

# Output the assessment report
Write-Output "==================================================================================="
Write-Output "Security Configuration Assessment Report based on CIS Benchmark for Windows 11:"


$commandline = ""
# Loop through the assessment results and output the details
foreach ($result in $assessmentResults) {
    $name, $recommended, $current, $score, $command = $result
    Write-Output "-----------------------------------------------------------------------------------"
    Write-Output "Checking $name ..."
    Write-Output " - Recomended: $recommended"
    # Check if $current starts with "Error:"
    if ($current.StartsWith("Error:")) {
        Write-Output " - $current`n"
    } else {
        Write-Output " - Current: $current`n"
    }

    $commandline += " " + $command
}

# Remove extra spaces from the commandline
$commandline = $commandline -replace '\s+', ' '

# Calculate the overall compliance score if there are assessment results
$count = 0
if ($assessmentResults.Count -gt 0) {
    $totalScore = ($assessmentResults | ForEach-Object { $_[3] } | Measure-Object -Sum).Sum
    $maximumScore = ($assessmentResults.Count) * 100
    $percentageScore = if ($maximumScore -gt 0) { [math]::Round(($totalScore / $maximumScore) * 100, 2) } else { 0 }
    $count = $assessmentResults.Count

    # Output the overall compliance score
    Write-Output "-----------------------------------------------------------------------------------"
    Write-Output "Overall Compliance Score for the $count assesments is: $percentageScore%"
    Write-Output "-----------------------------------------------------------------------------------"
    Write-Output "To mediate the non-compliant settings, run the following command as an Adminstrator:"
    Write-Output ".\AssesMyWindows11Security.ps1 $commandline"
    Write-Output "===================================================================================`n"
}
