# Get-ServicePaths

A PowerShell tool for identifying Windows unquoted service path vulnerabilities and testing write permissions for privilege escalation.

## Overview

UnquotedServicePaths identifies Windows services with unquoted executable paths containing spaces, and tests current user's write permissions to intermediate directories that could be exploited for privilege escalation. Available as both a standalone script and PowerShell module.

## Vulnerability Explanation

When a Windows service path like `C:\Program Files\My App\service.exe` is not properly quoted, Windows searches for executables in this order:

1. `C:\Program.exe` ← **Exploit opportunity**
2. `C:\Program Files\My.exe` ← **Exploit opportunity**  
3. `C:\Program Files\My App\service.exe` ← **Actual service**

If you can write to `C:\` or `C:\Program Files\`, you can place a malicious executable that will run with the service's privileges.

## Features

- **Unquoted Path Detection** - Identifies vulnerable service configurations
- **Write Permission Testing** - Tests actual user permissions to exploit directories
- **Exploit Path Generation** - Shows exactly where to place malicious executables
- **Risk Prioritization** - Sorts by exploitability and service privilege level
- **Clean Output** - PowerView-style structured text for easy parsing
- **Multiple Interfaces** - Available as script (.ps1) or module (.psm1)

## Requirements

- PowerShell 5.0 or later
- Windows 7/Server 2008 or later
- No administrative privileges required

---

# Get-ServicePaths.ps1 script

### Installation

```powershell
# Download and run directly
.\UnquotedServicePaths.ps1
```

### Usage

```powershell
# Basic vulnerability scan
.\UnquotedServicePaths.ps1

# Test actual write permissions
.\UnquotedServicePaths.ps1 -TestWriteAccess

# Show all services including non-vulnerable
.\UnquotedServicePaths.ps1 -ShowAllServices

# Silent mode for automation
.\UnquotedServicePaths.ps1 -Quiet

# Display help
.\UnquotedServicePaths.ps1 -Help
```

### Script Parameters

| Parameter | Description |
|-----------|-------------|
| `-ShowAllServices` | Display all services including non-vulnerable ones |
| `-TestWriteAccess` | Test actual write permissions by creating temporary files |
| `-Quiet` | Suppress banner and progress messages |
| `-Help` | Display comprehensive help menu |

### Script Examples

```powershell
# Find vulnerabilities and test exploitability
.\UnquotedServicePaths.ps1 -TestWriteAccess

# Complete service inventory with vulnerability status
.\UnquotedServicePaths.ps1 -ShowAllServices

# Export results for analysis
.\UnquotedServicePaths.ps1 -Quiet > unquoted_vulns.txt
```

---

# Get-ServicePaths.psm1 module

The module version for importing and reusing functions.

### Installation

```powershell
# Import the module
Import-Module .\UnquotedServicePaths.psm1

# Verify installation
Get-Command -Module UnquotedServicePaths
```

### Module Functions

#### `Get-AllServices`
Shows ALL services on the system with vulnerability analysis.

```powershell
# Display complete service inventory
Get-AllServices

# Silent mode
Get-AllServices -Quiet
```

#### `Get-WriteAccess`  
Finds vulnerable services and tests actual write permissions.

```powershell
# Test write access on vulnerable paths
Get-WriteAccess

# Silent testing for automation
Get-WriteAccess -Quiet
```

#### `Get-UnquotedServicePaths`
Basic vulnerability scan showing only vulnerable services.

```powershell
# Quick vulnerability identification
Get-UnquotedServicePaths

# Minimal output
Get-UnquotedServicePaths -Quiet
```

### Module Examples

```powershell
# Import and run comprehensive scan
Import-Module .\UnquotedServicePaths.psm1
Get-WriteAccess

# Get help for specific function
Get-Help Get-WriteAccess -Full

# Automation workflow
Import-Module .\UnquotedServicePaths.psm1
$vulns = Get-WriteAccess -Quiet
$vulns | Where-Object { $_.WritablePaths -ne "None" }
```

---

## Sample Output

```
[*] UnquotedServicePaths v1.0
[*] Current User: pentester
[*] Domain: TARGET
[*] Timestamp: 2024-01-15 14:30:25

[*] Scanning 313 services for unquoted path vulnerabilities...

[+] SCAN SUMMARY
    Total Services: 313
    Vulnerable Services: 3
    Exploitable Services: 1
    Non-Vulnerable: 310

[+] UNQUOTED SERVICE PATH VULNERABILITIES (3 services)

ServiceName      : VulnService
DisplayName      : Vulnerable Application Service
Status           : Running
StartMode        : Auto
ServicePath      : C:\Program Files\My App\service.exe
Vulnerable       : True
WritablePaths    : C:\Program Files
ExploitPaths     : C:\Program.exe; C:\Program Files\My.exe
LogOnAs          : LocalSystem

[!] SECURITY FINDINGS
    3 services have unquoted paths with spaces
    1 services have writable exploit paths
    1 high-privilege services are vulnerable
    1 auto-start services are immediately exploitable

[!] EXPLOITATION NOTES
    - Focus on services with WritablePaths containing values
    - SYSTEM services provide highest privilege escalation
    - Place malicious executable at ExploitPaths locations
```

## Output Fields

| Field | Description |
|-------|-------------|
| `ServiceName` | Internal service name |
| `DisplayName` | Human-readable service name |
| `Status` | Current service state (Running/Stopped) |
| `StartMode` | Service startup configuration (Auto/Manual/Disabled) |
| `ServicePath` | Full unquoted service path |
| `Vulnerable` | True if exploitable paths found |
| `WritablePaths` | Directories where user can write |
| `ExploitPaths` | Specific executable paths to target |
| `LogOnAs` | Service account context |


## Script vs Module

### Use the **Script** (.ps1) when:
- One-time assessments
- Simple command-line usage
- Standalone security testing
- Integration with other scripts

### Use the **Module** (.psm1) when:
- Repeated assessments
- PowerShell automation workflows
- Integration with other modules
- Custom security frameworks

## Contributing

Contributions welcome! Areas of interest:
- Additional service path parsing edge cases
- Performance optimizations for large environments
- Integration with other privilege escalation tools
- Enhanced output formats

## License

Provided for educational and authorized security testing purposes. Use responsibly and only on systems you own or have explicit permission to test.

---

**⚠️ Disclaimer:** This tool is for authorized security testing only. Users are responsible for ensuring proper authorization before use.
