# ServicePermissionAudit (Plain Text Edition)

A PowerShell module for auditing Windows service permissions with clean, parseable output designed for security assessments and automation.

## 🎯 Overview

ServicePermissionAudit identifies Windows services where the current user has elevated permissions that could be exploited for privilege escalation. This plain text version provides structured output similar to PowerView, making it ideal for integration with other security tools and automated workflows.

## ✨ Key Features

- **Clean Text Output** - No colors or formatting, perfect for parsing
- **PowerView-Style Interface** - Familiar `[*]`, `[+]`, `[!]` prefixes
- **Structured Data Format** - Each property on its own line for easy processing
- **Risk Classification** - Critical/High/Medium/ReadOnly/NoAccess levels
- **File System Testing** - Identifies services with executable write access
- **Service Control Testing** - Optional start/stop permission verification
- **Automation Friendly** - Silent mode and non-interactive operation
- **Security Focus** - Designed for penetration testing and red team assessments

## 📋 Installation

```powershell
# Download and import the module
Import-Module .\ServicePermissionAuditPlain.psm1

# Verify installation
Get-Command -Module ServicePermissionAuditPlain
```

## 🚀 Quick Start

```powershell
# Basic audit - shows all services with risk assessment
Invoke-ServicePermissionAudit

# Find only high-risk services (Critical + High)
Invoke-ServicePermissionAudit -ShowOnlyRisks

# Find file system vulnerabilities (Critical only)
Invoke-ServicePermissionAudit -ShowOnlyFileSystemRisks

# Quick vulnerable services check
Get-VulnerableServices

# Test start/stop permissions (automated)
Get-VulnerableServices -TestStartStop
```

## 📊 Command Reference

### `Invoke-ServicePermissionAudit`

Main audit function with comprehensive service analysis.

```powershell
Invoke-ServicePermissionAudit [-ShowOnlyRisks] [-ShowOnlyFileSystemRisks] [-TestStartStop] [-Quiet]
```

**Parameters:**
- `-ShowOnlyRisks` - Display only Critical and High risk services
- `-ShowOnlyFileSystemRisks` - Display only services with file system write access
- `-TestStartStop` - Test start/stop permissions (no confirmation required)
- `-Quiet` - Suppress banner and progress messages

### `Get-VulnerableServices`

Quick function for identifying file system vulnerabilities.

```powershell
Get-VulnerableServices [-TestStartStop] [-Quiet]
```

## 📈 Output Examples

### Basic Audit Output
```
[*] ServicePermissionAudit v1.0
[*] Current User: pentester
[*] Domain: TARGET
[*] Timestamp: 2024-01-15 14:30:25

[*] Scanning 313 services...

[+] AUDIT SUMMARY
    Total Services: 313
    Critical Risk: 2
    High Risk: 1
    Medium Risk: 3
    Read Only: 305
    No Access: 2

ServiceName      : VulnerableService
DisplayName      : Vulnerable Application Service
Status           : Running
RiskLevel        : Critical
ExecutablePath   : C:\Program Files\VulnApp\service.exe
LogOnAs          : LocalSystem
StartMode        : Auto

ServiceName      : ConfigurableService
DisplayName      : User Configurable Service
Status           : Stopped
RiskLevel        : High
ExecutablePath   : C:\Windows\System32\example.exe
LogOnAs          : LocalService
StartMode        : Manual

[!] SECURITY FINDINGS
    CRITICAL: 2 services have file system write access
    HIGH: 1 services allow configuration changes
    MEDIUM: 3 services allow start operations
```

### Detailed Risk Analysis Output
```
ServiceName      : VulnerableService
DisplayName      : Vulnerable Application Service
Status           : Running
RiskLevel        : Critical
ExecutablePath   : C:\Program Files\VulnApp\service.exe
LogOnAs          : LocalSystem
StartMode        : Auto
CanChangeConfig  : True
CanWriteToExe    : False
CanWriteToDir    : True
CanReplaceExe    : True
StartStopTested  : False
```

### Start/Stop Testing Output
```
[!] WARNING: TestStartStop enabled - this may actually start/stop services!
[!] Only testing services that match your filter criteria...

[*] Testing start/stop permissions on 2 services...

ServiceName      : VulnerableService
DisplayName      : Vulnerable Application Service
Status           : Running
RiskLevel        : Critical
ExecutablePath   : C:\Program Files\VulnApp\service.exe
LogOnAs          : LocalSystem
StartMode        : Auto
CanChangeConfig  : True
CanWriteToExe    : False
CanWriteToDir    : True
CanReplaceExe    : True
CanStart         : False
CanStop          : True
StartStopTested  : True

[!] SECURITY FINDINGS
    CRITICAL: 1 services have file system write access
    STOP: 1 services can be stopped
```

## 🔍 Risk Classification

| Risk Level | Description | Security Impact |
|------------|-------------|-----------------|
| **Critical** | Can modify service executable files or directories | **IMMEDIATE THREAT** - Direct path to privilege escalation |
| **High** | Can modify service configuration | **HIGH RISK** - Service manipulation possible |
| **Medium** | Can start stopped services | **MODERATE RISK** - Limited service control |
| **ReadOnly** | Can only view service information | **LOW RISK** - Information disclosure only |
| **NoAccess** | Cannot interact with service | **NO RISK** - Service properly secured |

## 🔧 Parsing and Integration

### Extracting Critical Services
```powershell
# Get all Critical risk services
Invoke-ServicePermissionAudit -ShowOnlyFileSystemRisks -Quiet | 
    Select-String "ServiceName" | 
    ForEach-Object { ($_ -split ":")[1].Trim() }
```

### CSV Export
```powershell
# Convert output to structured data
$output = Invoke-ServicePermissionAudit -ShowOnlyRisks -Quiet
# Parse and export to CSV (custom parsing required)
```

### Integration with Other Tools
```powershell
# Silent mode for scripting
$results = Invoke-ServicePermissionAudit -ShowOnlyFileSystemRisks -Quiet

# Process results with other security tools
$results | Out-File "service_vulns.txt"
```

## 🛡️ Security Use Cases

### Penetration Testing
```powershell
# Quick vulnerability assessment
Get-VulnerableServices -Quiet

# Comprehensive privilege escalation check
Invoke-ServicePermissionAudit -ShowOnlyRisks -TestStartStop -Quiet
```

### Red Team Operations
```powershell
# Silent enumeration
Invoke-ServicePermissionAudit -ShowOnlyFileSystemRisks -Quiet

# Automated service abuse testing
Get-VulnerableServices -TestStartStop -Quiet
```

### Blue Team Assessment
```powershell
# Full environment audit
Invoke-ServicePermissionAudit

# Focus on immediate threats
Invoke-ServicePermissionAudit -ShowOnlyFileSystemRisks
```

## ⚠️ Operational Security

### TestStartStop Considerations
- **Automated execution** - No user confirmation required
- **Service disruption** - May temporarily affect running services
- **Stealth concerns** - Service stop/start events are logged
- **Restoration attempts** - Module tries to restore original service state

### Detection Considerations
- Service configuration queries are normal administrative activity
- File system access tests may trigger security monitoring
- Start/stop operations generate Windows Event Log entries
- Consider using `-Quiet` mode to reduce output verbosity

## 🔄 Common Workflows

### Initial Assessment
```powershell
# 1. Quick critical vulnerability check
Get-VulnerableServices

# 2. Comprehensive risk assessment
Invoke-ServicePermissionAudit -ShowOnlyRisks

# 3. Full service inventory (if needed)
Invoke-ServicePermissionAudit -Quiet > full_audit.txt
```

### Privilege Escalation Research
```powershell
# 1. Find file system vulnerabilities
Invoke-ServicePermissionAudit -ShowOnlyFileSystemRisks

# 2. Test service control capabilities
Get-VulnerableServices -TestStartStop

# 3. Document findings
Invoke-ServicePermissionAudit -ShowOnlyRisks -Quiet > privesc_vectors.txt
```

## 📝 Output Field Reference

| Field | Description | Values |
|-------|-------------|---------|
| `ServiceName` | Internal service name | String |
| `DisplayName` | Human-readable service name | String |
| `Status` | Current service state | Running, Stopped, etc. |
| `RiskLevel` | Security risk assessment | Critical, High, Medium, ReadOnly, NoAccess |
| `ExecutablePath` | Service executable location | File path or "NotFound" |
| `LogOnAs` | Service account context | LocalSystem, NetworkService, etc. |
| `StartMode` | Service startup configuration | Auto, Manual, Disabled |
| `CanChangeConfig` | Can modify service settings | True/False |
| `CanWriteToExe` | Can modify executable file | True/False |
| `CanWriteToDir` | Can write to executable directory | True/False |
| `CanReplaceExe` | Can replace service executable | True/False |
| `CanStart` | Can start stopped service | True/False (if tested) |
| `CanStop` | Can stop running service | True/False (if tested) |
| `StartStopTested` | Whether start/stop was tested | True/False |

## 🎛️ Environment Compatibility

- **PowerShell 5.0+** required
- **Windows 7/Server 2008+** supported
- **Standard user context** - Works without admin privileges
- **Domain environments** - Compatible with AD-joined systems
- **Workgroup systems** - Functions on standalone machines

## 🤝 Contributing

Contributions welcome! Areas of interest:
- Output format improvements
- Additional parsing utilities
- Integration examples
- Performance optimizations

## 📄 License

Provided for educational and authorized security testing purposes. Use responsibly and only on systems you own or have explicit permission to test.

## 🔗 Related Tools

Works well with:
- **PowerView** - Active Directory enumeration
- **PrivEsc scripts** - Windows privilege escalation
- **BloodHound** - Attack path analysis
- **WinPEAS** - Windows privilege escalation assessment

---

**Note:** This tool identifies potential privilege escalation vectors. Always follow responsible disclosure practices and obtain proper authorization before testing.
