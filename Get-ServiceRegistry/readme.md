# Get-ServiceRegistry

A PowerShell security tool for auditing Windows service registry permissions to identify potential privilege escalation vulnerabilities.

## Overview

Get-ServiceRegistry scans all Windows services in the registry to find services where low privilege users or groups have been granted full control permissions. This can be a security concern as it may allow privilege escalation attacks.


## Files

- **`Get-ServiceRegistry.ps1`** - Standalone PowerShell script
- **`Get-ServiceRegistry.psm1`** - PowerShell module version

## Installation

### Option 1: Standalone Script
1. Download `Get-ServiceRegistry.ps1`
2. Run directly in PowerShell

### Option 2: PowerShell Module
1. Create a module directory:
   ```powershell
   $modulePath = "$env:USERPROFILE\Documents\PowerShell\Modules\Get-ServiceRegistry"
   New-Item -ItemType Directory -Path $modulePath -Force
   ```

2. Copy `Get-ServiceRegistry.psm1` to the module directory

3. Import the module:
   ```powershell
   Import-Module Get-ServiceRegistry
   ```

## Usage

### Standalone Script
```powershell
.\Get-ServiceRegistry.ps1
```

### PowerShell Module
```powershell
# Import the module (if not already imported)
Import-Module Get-ServiceRegistry

# Run the audit
Get-ServiceRegistry

# Get help
Get-Help Get-ServiceRegistry -Full
```

## Sample Output

```
Checking for services with low privilege full control access...

Found 2 services with low privilege full control:

ServiceName    Identity              Permissions
-----------    --------              -----------
VulnService1   BUILTIN\Users         FullControl
VulnService2   NT AUTHORITY\Authenticated Users FullControl

Detailed Results:
Service: VulnService1
  Path: Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VulnService1
  Identity: BUILTIN\Users
  Permissions: FullControl

Service: VulnService2
  Path: Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VulnService2
  Identity: NT AUTHORITY\Authenticated Users
  Permissions: FullControl
```

## Security Implications

Services with improper permissions can be exploited for:
- **Privilege Escalation**: Modifying service binaries or configurations
- **Persistence**: Creating backdoors through service modifications
- **Lateral Movement**: Accessing sensitive system resources

## Requirements

- **PowerShell**: Version 5.1 or later
- **Permissions**: Must be run with sufficient privileges to read service registry keys
- **Operating System**: Windows (registry-based services)

## Excluded Accounts

The tool automatically excludes these expected high privilege accounts:
- `NT AUTHORITY\SYSTEM`
- `BUILTIN\Administrators`
- `NT SERVICE\TrustedInstaller`
- `CREATOR OWNER`


## License

This project is provided as-is for educational and security auditing purposes.

## Disclaimer

This tool is intended for legitimate security auditing purposes only. Users are responsible for ensuring they have proper authorization before running security scans on any system.

**⚠️ Important**: Always test in a controlled environment before running on production systems.
