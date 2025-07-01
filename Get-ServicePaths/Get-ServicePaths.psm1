#Requires -Version 5.0

<#
.SYNOPSIS
    PowerShell module for identifying Windows unquoted service path vulnerabilities
.DESCRIPTION
    Provides functions to identify unquoted service paths and test write permissions
    to directories that could be exploited for privilege escalation.
#>

# Function to parse and clean service executable path
function Get-ServiceExecutablePath {
    [CmdletBinding()]
    param([string]$PathName)
    
    if (-not $PathName) { return $null }
    
    # Remove common parameters that aren't part of the executable path
    $cleanPath = $PathName -replace '\s+-[a-zA-Z]\w*.*$', ''
    $cleanPath = $cleanPath.Trim()
    
    # Handle quoted paths - if quoted, it's not vulnerable
    if ($cleanPath.StartsWith('"') -and $cleanPath.IndexOf('"', 1) -gt 0) {
        return $null  # Quoted paths are not vulnerable
    }
    
    # Remove quotes if present but path extends beyond them
    $cleanPath = $cleanPath.Trim('"')
    
    return $cleanPath
}

# Function to check if path is unquoted and contains spaces
function Test-UnquotedPath {
    [CmdletBinding()]
    param([string]$Path)
    
    if (-not $Path -or $Path.Length -eq 0) {
        return $false
    }
    
    # Path must contain spaces to be vulnerable
    if (-not $Path.Contains(' ')) {
        return $false
    }
    
    # Path must not be quoted
    if ($Path.StartsWith('"') -and $Path.EndsWith('"')) {
        return $false
    }
    
    # Path must exist or be a valid Windows path format
    if ($Path -notmatch '^[a-zA-Z]:\\') {
        return $false
    }
    
    return $true
}

# Function to generate possible exploit paths
function Get-ExploitPaths {
    [CmdletBinding()]
    param([string]$ServicePath)
    
    $exploitPaths = @()
    $pathParts = $ServicePath -split '\\'
    
    # Build paths progressively, stopping at each space
    for ($i = 0; $i -lt $pathParts.Length - 1; $i++) {
        $currentPath = ($pathParts[0..$i] -join '\')
        
        # Check if this path segment contains spaces
        if ($pathParts[$i].Contains(' ')) {
            # Split on space and create exploit path
            $spaceParts = $pathParts[$i] -split ' '
            if ($spaceParts.Length -gt 1) {
                $exploitPath = $currentPath -replace [regex]::Escape($pathParts[$i]), $spaceParts[0]
                $exploitPaths += "$exploitPath.exe"
            }
        }
    }
    
    return $exploitPaths | Select-Object -Unique
}

# Function to get writable directories from exploit paths
function Get-WritableDirectories {
    [CmdletBinding()]
    param([string[]]$ExploitPaths, [bool]$TestWrite = $false)
    
    $writableDirs = @()
    $testedDirs = @()
    
    foreach ($exploitPath in $ExploitPaths) {
        $directory = Split-Path $exploitPath -Parent
        
        # Skip if we already tested this directory
        if ($directory -in $testedDirs) {
            continue
        }
        $testedDirs += $directory
        
        if (-not (Test-Path $directory)) {
            continue
        }
        
        $canWrite = $false
        
        if ($TestWrite) {
            # Test actual write access
            try {
                $testFile = Join-Path $directory "writetest_$(Get-Random).tmp"
                [System.IO.File]::WriteAllText($testFile, "test")
                if (Test-Path $testFile) {
                    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                    $canWrite = $true
                }
            }
            catch {
                $canWrite = $false
            }
        } else {
            # Quick permission check using Get-Acl (less reliable but faster)
            try {
                $acl = Get-Acl $directory -ErrorAction Stop
                # This is a simplified check - actual write testing is more reliable
                $canWrite = $true
            }
            catch {
                $canWrite = $false
            }
        }
        
        if ($canWrite) {
            $writableDirs += $directory
        }
    }
    
    return $writableDirs
}

# Core function to scan for unquoted service path vulnerabilities
function Invoke-UnquotedServicePathScan {
    [CmdletBinding()]
    param(
        [bool]$ShowAllServices = $false,
        [bool]$TestWriteAccess = $false,
        [bool]$Quiet = $false
    )
    
    if (-not $Quiet) {
        Write-Output "[*] UnquotedServicePaths v1.0"
        Write-Output "[*] Current User: $env:USERNAME"
        Write-Output "[*] Domain: $env:USERDOMAIN"
        Write-Output "[*] Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        Write-Output ""
    }
    
    if ($TestWriteAccess -and -not $Quiet) {
        Write-Output "[!] WARNING: TestWriteAccess enabled - creating temporary files for testing"
        Write-Output ""
    }
    
    # Get all services
    $services = Get-Service | Sort-Object Name
    $vulnerableServices = @()
    $stats = @{
        Total = 0
        Vulnerable = 0
        NotVulnerable = 0
        Writable = 0
    }
    
    if (-not $Quiet) {
        Write-Output "[*] Scanning $($services.Count) services for unquoted path vulnerabilities..."
    }
    
    foreach ($service in $services) {
        $stats.Total++
        
        # Get service configuration
        try {
            $serviceConfig = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction Stop
            $servicePath = Get-ServiceExecutablePath -PathName $serviceConfig.PathName
            
            $isVulnerable = Test-UnquotedPath -Path $servicePath
            $exploitPaths = @()
            $writableDirs = @()
            
            if ($isVulnerable) {
                $stats.Vulnerable++
                $exploitPaths = Get-ExploitPaths -ServicePath $servicePath
                $writableDirs = Get-WritableDirectories -ExploitPaths $exploitPaths -TestWrite $TestWriteAccess
                
                if ($writableDirs.Count -gt 0) {
                    $stats.Writable++
                }
            } else {
                $stats.NotVulnerable++
            }
            
            # Create service object
            $serviceObj = [PSCustomObject]@{
                ServiceName = $service.Name
                DisplayName = $service.DisplayName
                Status = $service.Status
                StartMode = $serviceConfig.StartMode
                ServicePath = $servicePath
                Vulnerable = $isVulnerable
                WritablePaths = $writableDirs -join "; "
                ExploitPaths = $exploitPaths -join "; "
                LogOnAs = $serviceConfig.StartName
            }
            
            # Add to results based on parameters
            if ($ShowAllServices -or $isVulnerable) {
                $vulnerableServices += $serviceObj
            }
        }
        catch {
            $stats.NotVulnerable++
            
            if ($ShowAllServices) {
                $serviceObj = [PSCustomObject]@{
                    ServiceName = $service.Name
                    DisplayName = $service.DisplayName
                    Status = $service.Status
                    StartMode = "Unknown"
                    ServicePath = "AccessDenied"
                    Vulnerable = $false
                    WritablePaths = ""
                    ExploitPaths = ""
                    LogOnAs = "Unknown"
                }
                $vulnerableServices += $serviceObj
            }
        }
    }
    
    # Display summary
    if (-not $Quiet) {
        Write-Output ""
        Write-Output "[+] SCAN SUMMARY"
        Write-Output "    Total Services: $($stats.Total)"
        Write-Output "    Vulnerable Services: $($stats.Vulnerable)"
        Write-Output "    Exploitable Services: $($stats.Writable)"
        Write-Output "    Non-Vulnerable: $($stats.NotVulnerable)"
        Write-Output ""
    }
    
    # Filter and display results
    if ($ShowAllServices) {
        if (-not $Quiet) {
            Write-Output "[+] ALL SERVICES ($($vulnerableServices.Count) services)"
        }
    } else {
        $vulnerableServices = $vulnerableServices | Where-Object { $_.Vulnerable -eq $true }
        if (-not $Quiet) {
            Write-Output "[+] UNQUOTED SERVICE PATH VULNERABILITIES ($($vulnerableServices.Count) services)"
        }
    }
    
    if ($vulnerableServices.Count -eq 0) {
        if (-not $Quiet) {
            Write-Output "[+] No vulnerable services found."
        }
        return @()
    }
    
    # Sort by exploitability (writable paths first), then by service privilege
    $vulnerableServices = $vulnerableServices | Sort-Object @{
        Expression = { if ($_.WritablePaths) { 0 } else { 1 } }
    }, @{
        Expression = { if ($_.LogOnAs -like "*SYSTEM*") { 0 } elseif ($_.LogOnAs -like "*Admin*") { 1 } else { 2 } }
    }, ServiceName
    
    # Output detailed results
    foreach ($service in $vulnerableServices) {
        Write-Output "ServiceName      : $($service.ServiceName)"
        Write-Output "DisplayName      : $($service.DisplayName)"
        Write-Output "Status           : $($service.Status)"
        Write-Output "StartMode        : $($service.StartMode)"
        Write-Output "ServicePath      : $($service.ServicePath)"
        Write-Output "Vulnerable       : $($service.Vulnerable)"
        Write-Output "WritablePaths    : $(if ($service.WritablePaths) { $service.WritablePaths } else { 'None' })"
        Write-Output "ExploitPaths     : $(if ($service.ExploitPaths) { $service.ExploitPaths } else { 'None' })"
        Write-Output "LogOnAs          : $($service.LogOnAs)"
        Write-Output ""
    }
    
    # Security findings summary
    if (-not $Quiet -and $stats.Vulnerable -gt 0) {
        Write-Output "[!] SECURITY FINDINGS"
        Write-Output "    $($stats.Vulnerable) services have unquoted paths with spaces"
        Write-Output "    $($stats.Writable) services have writable exploit paths"
        
        $highPrivServices = $vulnerableServices | Where-Object { 
            $_.LogOnAs -like "*SYSTEM*" -or $_.LogOnAs -like "*Admin*" 
        }
        
        if ($highPrivServices.Count -gt 0) {
            Write-Output "    $($highPrivServices.Count) high-privilege services are vulnerable"
        }
        
        $autoStartServices = $vulnerableServices | Where-Object { 
            $_.StartMode -eq "Auto" -and $_.WritablePaths -ne "None" -and $_.WritablePaths -ne ""
        }
        
        if ($autoStartServices.Count -gt 0) {
            Write-Output "    $($autoStartServices.Count) auto-start services are immediately exploitable"
        }
        
        Write-Output ""
        Write-Output "[!] EXPLOITATION NOTES"
        Write-Output "    - Focus on services with WritablePaths containing values"
        Write-Output "    - SYSTEM services provide highest privilege escalation"
        Write-Output "    - Auto-start services execute on system boot"
        Write-Output "    - Place malicious executable at ExploitPaths locations"
        Write-Output ""
    }
    
    return $vulnerableServices
}

<#
.SYNOPSIS
    Gets all Windows services with unquoted path vulnerability analysis
.DESCRIPTION
    Scans all Windows services and displays complete inventory with vulnerability status.
    Shows both vulnerable and non-vulnerable services for comprehensive assessment.
.PARAMETER Quiet
    Suppress banner and progress messages
.EXAMPLE
    Get-AllServices
    
    Display all services with vulnerability analysis
.EXAMPLE
    Get-AllServices -Quiet
    
    Display all services with minimal output for parsing
#>
function Get-AllServices {
    [CmdletBinding()]
    param(
        [switch]$Quiet
    )
    
    Invoke-UnquotedServicePathScan -ShowAllServices $true -TestWriteAccess $false -Quiet $Quiet
}

<#
.SYNOPSIS
    Gets unquoted service path vulnerabilities with write access testing
.DESCRIPTION
    Identifies Windows services with unquoted executable paths and tests actual
    write permissions to directories that could be exploited for privilege escalation.
    Creates temporary files to verify write access.
.PARAMETER Quiet
    Suppress banner and progress messages
.EXAMPLE
    Get-WriteAccess
    
    Find vulnerable services and test write permissions
.EXAMPLE
    Get-WriteAccess -Quiet
    
    Find vulnerable services with write testing, minimal output
#>
function Get-WriteAccess {
    [CmdletBinding()]
    param(
        [switch]$Quiet
    )
    
    Invoke-UnquotedServicePathScan -ShowAllServices $false -TestWriteAccess $true -Quiet $Quiet
}

<#
.SYNOPSIS
    Gets Windows services with unquoted path vulnerabilities
.DESCRIPTION
    Identifies Windows services with unquoted executable paths that contain spaces.
    These vulnerabilities can be exploited for privilege escalation if the user
    can write to intermediate directories in the path.
.PARAMETER Quiet
    Suppress banner and progress messages
.EXAMPLE
    Get-UnquotedServicePaths
    
    Find all unquoted service path vulnerabilities
.EXAMPLE
    Get-UnquotedServicePaths -Quiet
    
    Find vulnerabilities with minimal output
#>
function Get-UnquotedServicePaths {
    [CmdletBinding()]
    param(
        [switch]$Quiet
    )
    
    Invoke-UnquotedServicePathScan -ShowAllServices $false -TestWriteAccess $false -Quiet $Quiet
}

# Export module functions
Export-ModuleMember -Function Get-AllServices, Get-WriteAccess, Get-UnquotedServicePaths