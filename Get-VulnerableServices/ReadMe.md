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


# Get-VulnerableService .psm1 module 

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

# Get-VulnerableService .ps1 script

## Quick Start

```powershell
# Download and run
.\Get-VulnerableService.ps1

# Show help
.\Get-VulnerableService.ps1 -Help

# Quick vulnerability check
.\Get-VulnerableService.ps1 -VulnerableServicesOnly

# Test high-risk services
.\Get-VulnerableService.ps1 -ShowAll -TestStartStop
```

## Usage

### Basic Commands

```powershell
# Complete system audit (all services)
.\Get-VulnerableService.ps1

# All services + detailed analysis for Critical/High risk only  
.\Get-VulnerableService.ps1 -ShowAll

# Critical file system risks only
.\Get-VulnerableService.ps1 -ShowOnlyFileSystemRisks

# Quick vulnerable services check
.\Get-VulnerableService.ps1 -VulnerableServicesOnly

# Silent mode for automation
.\Get-VulnerableService.ps1 -VulnerableServicesOnly -Quiet
```

### Advanced Testing

```powershell
# Test start/stop permissions (WARNING: May affect services)
.\Get-VulnerableService.ps1 -ShowAll -TestStartStop

# File system risks with start/stop testing
.\Get-VulnerableService.ps1 -VulnerableServicesOnly -TestStartStop
```


## 📈 Output Example

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
