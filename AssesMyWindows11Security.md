The PowerShell script `AssesMyWindows11Security.ps1` has several important security checks aligned with CIS Benchmark recommendations for Windows 11:

The PowerShell script `AssesMyWindows11Security.ps1` has several important security checks aligned with CIS Benchmark recommendations for Windows 11:

### 1. **AssessSMBv1**
   - **Checks**: Whether SMBv1 is disabled.
   - **CIS Recommendation**: SMBv1 should be disabled due to security vulnerabilities.
   - **Compliance Level**: Level 1 (L1).
   - **Script Accuracy**: Correctly implements the CIS recommendation.

### 2. **AssessWindowsDefenderAntivirus**
   - **Checks**: If Windows Defender Antivirus real-time protection is enabled.
   - **CIS Recommendation**: Real-time protection should be enabled to continuously scan and protect against malware threats.
   - **Compliance Level**: Level 1 (L1).
   - **Script Accuracy**: Accurately checks and enforces real-time protection as per CIS benchmarks.

### 3. **AssessWindowsDefenderFirewall**
   - **Checks**: Whether the Windows Defender Firewall is enabled.
   - **CIS Recommendation**: The firewall should be enabled to protect against unauthorized network access.
   - **Compliance Level**: Level 1 (L1).
   - **Script Accuracy**: Correctly assesses firewall status in accordance with CIS guidelines.

### 4. **AssessRemoteDesktopProtocol**
   - **Checks**: If Remote Desktop Protocol (RDP) is disabled.
   - **CIS Recommendation**: RDP should be disabled unless required for valid business purposes, to minimize remote access vulnerabilities.
   - **Compliance Level**: Level 1 (L1).
   - **Script Accuracy**: Effectively assesses the RDP setting according to CIS recommendations.

### 5. **AssessUserAccountControl**
   - **Checks**: Configuration of User Account Control settings.
   - **CIS Recommendation**: User Account Control should be configured to prompt for consent on secure desktops.
   - **Compliance Level**: Level 1 (L1).
   - **Script Accuracy**: Correctly verifies UAC settings to enhance security posture.

### 6. **AssessAuditPolicy**
   - **Checks**: Configuration of audit policies for success and failure events.
   - **CIS Recommendation**: Ensure adequate logging of security events to detect and respond to potential breaches effectively.
   - **Compliance Level**: Level 1 (L1).
   - **Script Accuracy**: Correctly evaluates audit policies to ensure they meet CIS standards.

### 7. **AssessWindowsUpdateSettings**
   - **Checks**: If Windows Update is configured to automatically download and install updates.
   - **CIS Recommendation**: Automatic updates should be enabled to ensure that systems are protected against known vulnerabilities through timely patch management.
   - **Compliance Level**: Level 1 (L1).
   - **Script Accuracy**: Properly verifies the automatic update settings in line with CIS recommendations.

### 8. **AssessWindowsDefenderSmartScreen**
   - **Checks**: If Windows Defender SmartScreen is enabled for web and file operations.
   - **CIS Recommendation**: SmartScreen should be enabled to provide protection against phishing and malware.
   - **Compliance Level**: Level 1 (L1).
   - **Script Accuracy**: Accurately checks the SmartScreen settings as recommended by CIS.

### 9. **AssessWindowsDefenderExploitGuard**
   - **Checks**: Configuration of Exploit Guard settings that protect against various exploit techniques.
   - **CIS Recommendation**: Exploit Guard settings should be configured to provide robust protection against multiple types of threats.
   - **Compliance Level**: Level 1 (L1).
   - **Script Accuracy**: Ensures Exploit Guard is configured according to CIS benchmarks.

### 10. **AssessFirewallConfiguration**
   - **Checks**: Whether the firewall is enabled and correctly configured across all profiles.
   - **CIS Recommendation**: Firewall should be enabled with specific rules for inbound and outbound traffic to safeguard network security.
   - **Compliance Level**: Level 1 (L1).
   - **Script Accuracy**: Thoroughly assesses firewall settings to ensure compliance with CIS standards.

### 11. **AssessAutoRun**
   - **Checks**: Whether AutoRun and AutoPlay are disabled.
   - **CIS Recommendation**: AutoRun and AutoPlay should be disabled to prevent automatic execution of potentially malicious software from removable media.
   - **Compliance Level**: Level 1 (L1).
   - **Script Accuracy**: Correctly implements checks to ensure AutoRun and AutoPlay settings comply with security best practices.

### 12. **AssessPageFileClearance**
   - **Checks**: Configuration of the page file for proper security handling, such as clearing the page file at shutdown.
   - **CIS Recommendation**: The page file should be configured to clear on shutdown to prevent potential leakage of sensitive information.
   - **Compliance Level**: Level 2 (L2).
   - **Script Accuracy**: Accurately checks and enforces the recommended settings for page file handling.

### 13. **AssessWindowsScriptHost**
   - **Checks**: Whether Windows Script Host settings are disabled to prevent the execution of scripts.
   - **CIS Recommendation**: Windows Script Host should be disabled to reduce the attack surface against script-based threats.
   - **Compliance Level**: Level 1 (L1).
   - **Script Accuracy**: Properly verifies Windows Script Host settings in line with CIS security guidelines.

### 14. **AssessPasswordPolicy**
   - **Checks**: Password policies such as minimum length and complexity requirements.
   - **CIS Recommendation**: Passwords should meet complexity and length specifications to enhance account security.
   - **Compliance Level**: Level 1 (L1).
   - **Script Accuracy**: Effectively checks and enforces password policies as specified by CIS.

### 15. **AssessGuestAccount**
   - **Checks**: Whether the guest account is disabled.
   - **CIS Recommendation**: The guest account should be disabled to prevent unauthorized access to the system.
   - **Compliance Level**: Level 1 (L1).
   - **Script Accuracy**: Correctly determines the status of the guest account in compliance with CIS guidelines.


### Compliance and Security Assessment Reporting:
The script includes a comprehensive section that generates a security configuration assessment report. This report details each check's current state, recommended state, and a compliance score. It also calculates an overall compliance score based on the results of the individual assessments.

### Overall Compliance Level:
- The script primarily targets Level 1 (L1) recommendations, focusing on settings that offer significant security improvements without extensive modifications to system functionality.


### Compliance and Security Assessment Reporting:
The script includes a comprehensive section that generates a security configuration assessment report. This report details each check's current state, recommended state, and a compliance score. It also calculates an overall compliance score based on the results of the individual assessments.

### Overall Compliance Level:
- The script primarily targets Level 1 (L1) recommendations, focusing on settings that offer significant security improvements without extensive modifications to system functionality.