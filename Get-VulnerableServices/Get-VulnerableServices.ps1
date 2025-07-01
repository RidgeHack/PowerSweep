#Requires -Version 5.0

<#
.SYNOPSIS
    Windows Service Permissions Audit Script (Plain Text Version)
.DESCRIPTION
    Tests current user's actual permissions on services and identifies potential security risks.
    Output formatted for easy parsing and integration with other security tools.
.PARAMETER Help
    Display help menu and exit
.PARAMETER ShowAll
    Only display services with elevated permissions (Critical & High risk)
.PARAMETER ShowOnlyFileSystemRisks
    Only display services with file system write access (Critical risk only)
.PARAMETER VulnerableServicesOnly
    Quick mode - equivalent to Get-VulnerableServices (shows Critical file system risks only)
.PARAMETER TestStartStop
    Test start/stop permissions on filtered services (WARNING: May actually start/stop services!)
.PARAMETER Quiet
    Suppress banner and progress messages
.EXAMPLE
    .\ServicePermissionAudit.ps1 -Help
    
    Display help menu with all options and examples
.EXAMPLE
    .\ServicePermissionAudit.ps1
    
    Shows ALL services with paths and risk levels
.EXAMPLE
    .\ServicePermissionAudit.ps1 -ShowAll
    
    Shows only Critical and High risk services
.EXAMPLE
    .\ServicePermissionAudit.ps1 -VulnerableServicesOnly -TestStartStop
    
    Shows file system risks and tests start/stop permissions
.EXAMPLE
    .\ServicePermissionAudit.ps1 -ShowOnlyFileSystemRisks -Quiet
    
    Shows file system risks with minimal output
#>

param(
    [switch]$ShowAll,
    [switch]$ShowOnlyFileSystemRisks,
    [switch]$VulnerableServicesOnly,
    [switch]$TestStartStop,
    [switch]$Quiet,
    [switch]$Help
)

# Function to display help menu
function Show-Help {
    Write-Output ""
    Write-Output "ServicePermissionAudit v1.0 - Windows Service Permissions Assessment Tool"
    Write-Output ""
    Write-Output "DESCRIPTION:"
    Write-Output "  Tests current user's actual permissions on Windows services and identifies"
    Write-Output "  potential privilege escalation vectors. Provides clean, parseable output"
    Write-Output "  suitable for security assessments and automation."
    Write-Output ""
    Write-Output "USAGE:"
    Write-Output "  .\ServicePermissionAudit.ps1 [OPTIONS]"
    Write-Output ""
    Write-Output "OPTIONS:"
    Write-Output ""
    Write-Output "  -Help"
    Write-Output "    Display this help menu and exit"
    Write-Output ""
    Write-Output "  -ShowAll"
    Write-Output "    Display ALL services with basic info, then detailed analysis for"
    Write-Output "    Critical & High risk services only. Shows complete system inventory"
    Write-Output "    with focus on services requiring immediate attention"
    Write-Output ""
    Write-Output "  -ShowOnlyFileSystemRisks" 
    Write-Output "    Only display services with file system write access (Critical risk only)"
    Write-Output "    These represent the highest priority privilege escalation vectors"
    Write-Output ""
    Write-Output "  -VulnerableServicesOnly"
    Write-Output "    Quick mode - equivalent to Get-VulnerableServices function"
    Write-Output "    Shows only Critical file system risks (same as -ShowOnlyFileSystemRisks)"
    Write-Output ""
    Write-Output "  -TestStartStop"
    Write-Output "    Test start/stop permissions on filtered services"
    Write-Output "    WARNING: This may actually start/stop services on the system!"
    Write-Output "    Only tests services that match your other filter criteria"
    Write-Output ""
    Write-Output "  -Quiet"
    Write-Output "    Suppress banner, progress messages, and summary output"
    Write-Output "    Useful for automation and parsing by other tools"
    Write-Output ""
    Write-Output "EXAMPLES:"
    Write-Output ""
    Write-Output "  Basic Usage:"
    Write-Output ""
    Write-Output "    .\ServicePermissionAudit.ps1"
    Write-Output "      Complete audit showing ALL services with risk assessment"
    Write-Output ""
    Write-Output "    .\ServicePermissionAudit.ps1 -ShowAll"
    Write-Output "      Show only Critical and High risk services"
    Write-Output ""
    Write-Output "    .\ServicePermissionAudit.ps1 -VulnerableServicesOnly"
    Write-Output "      Quick check for file system vulnerabilities (Critical risk only)"
    Write-Output ""
    Write-Output "  Advanced Testing:"
    Write-Output ""
    Write-Output "    .\ServicePermissionAudit.ps1 -ShowOnlyFileSystemRisks -TestStartStop"
    Write-Output "      Test file system risks and their start/stop permissions"
    Write-Output ""
    Write-Output "    .\ServicePermissionAudit.ps1 -ShowAll -TestStartStop"
    Write-Output "      Test all high-risk services for start/stop capabilities"
    Write-Output ""
    Write-Output "  Automation & Parsing:"
    Write-Output ""
    Write-Output "    .\ServicePermissionAudit.ps1 -VulnerableServicesOnly -Quiet"
    Write-Output "      Silent mode for scripting and tool integration"
    Write-Output ""
    Write-Output "    .\ServicePermissionAudit.ps1 -ShowAll -Quiet > results.txt"
    Write-Output "      Export high-risk services to file for analysis"
    Write-Output ""
    Write-Output "RISK LEVELS:"
    Write-Output ""
    Write-Output "  Critical - Can modify service executable files or directories"
    Write-Output "           - IMMEDIATE THREAT: Direct path to privilege escalation"
    Write-Output ""
    Write-Output "  High     - Can modify service configuration"
    Write-Output "           - HIGH RISK: Service manipulation possible"
    Write-Output ""
    Write-Output "  Medium   - Can start stopped services"
    Write-Output "           - MODERATE RISK: Limited service control"
    Write-Output ""
    Write-Output "  ReadOnly - Can only view service information"
    Write-Output "           - LOW RISK: Information disclosure only"
    Write-Output ""
    Write-Output "  NoAccess - Cannot interact with service"
    Write-Output "           - NO RISK: Service properly secured"
    Write-Output ""
    Write-Output "OUTPUT FORMAT:"
    Write-Output ""
    Write-Output "  ServiceName      : ServiceName"
    Write-Output "  DisplayName      : Human-readable service name"
    Write-Output "  Status           : Running/Stopped/etc."
    Write-Output "  RiskLevel        : Critical/High/Medium/ReadOnly/NoAccess"
    Write-Output "  ExecutablePath   : Full path to service executable"
    Write-Output "  LogOnAs          : Service account context"
    Write-Output "  StartMode        : Auto/Manual/Disabled"
    Write-Output "  CanChangeConfig  : True/False"
    Write-Output "  CanWriteToExe    : True/False"
    Write-Output "  CanWriteToDir    : True/False" 
    Write-Output "  CanReplaceExe    : True/False"
    Write-Output "  CanStart         : True/False (if -TestStartStop used)"
    Write-Output "  CanStop          : True/False (if -TestStartStop used)"
    Write-Output ""
    Write-Output "SECURITY NOTES:"
    Write-Output ""
    Write-Output "  - Critical services with file system access are immediate threats"
    Write-Output "  - Use -TestStartStop only in test environments or with caution"
    Write-Output "  - Service start/stop operations are logged in Windows Event Log"
    Write-Output "  - This tool tests actual permissions, not theoretical ones"
    Write-Output "  - Run from different user contexts to assess various privilege levels"
    Write-Output ""
    Write-Output "REQUIREMENTS:"
    Write-Output ""
    Write-Output "  - PowerShell 5.0 or later"
    Write-Output "  - Windows 7/Server 2008 or later"
    Write-Output "  - No administrative privileges required (tests current user context)"
    Write-Output ""
    Write-Output "For more information: https://github.com/your-repo/ServicePermissionAudit"
    Write-Output ""
}

# Check if help is requested or no arguments provided
$allParams = $PSBoundParameters.Keys
$hasArguments = $allParams.Count -gt 0 -and -not ($allParams.Count -eq 1 -and $Help)

if ($Help -or -not $hasArguments) {
    Show-Help
    exit 0
}

# Helper function to parse service executable paths
function Get-ServiceExecutablePath {
    [CmdletBinding()]
    param([string]$PathName)
    
    if (-not $PathName) { return $null }
    
    # Handle quoted paths
    if ($PathName.StartsWith('"')) {
        $endQuote = $PathName.IndexOf('"', 1)
        if ($endQuote -gt 0) {
            return $PathName.Substring(1, $endQuote - 1)
        }
    }
    
    # Check for redirection operators that indicate this isn't a simple file path
    $redirectOperators = @('>', '<', '|', '&', '^')
    foreach ($operator in $redirectOperators) {
        if ($PathName.Contains($operator)) {
            $redirectPos = $PathName.IndexOfAny([char[]]$redirectOperators)
            if ($redirectPos -gt 0) {
                $PathName = $PathName.Substring(0, $redirectPos).Trim()
            } else {
                return $null
            }
            break
        }
    }
    
    # Handle unquoted paths
    $parts = $PathName -split ' '
    $executablePath = $parts[0]
    
    # Additional validation - check for invalid path characters
    $invalidChars = [System.IO.Path]::GetInvalidPathChars() + @('>', '<', '|', '*', '?')
    foreach ($char in $invalidChars) {
        if ($executablePath.Contains($char)) {
            return $null
        }
    }
    
    # Try to find the actual executable if path has spaces
    for ($i = 1; $i -lt $parts.Length; $i++) {
        $testPath = ($parts[0..$i] -join ' ')
        
        $hasInvalidChars = $false
        foreach ($char in $invalidChars) {
            if ($testPath.Contains($char)) {
                $hasInvalidChars = $true
                break
            }
        }
        
        if (-not $hasInvalidChars) {
            try {
                if (Test-Path $testPath -ErrorAction SilentlyContinue) {
                    $executablePath = $testPath
                    break
                }
            }
            catch {
                break
            }
        }
    }
    
    return $executablePath
}

# Test file system permissions on service executables
function Test-ServiceFilePermissions {
    [CmdletBinding()]
    param([string]$ExecutablePath)
    
    $result = @{
        CanWriteToExecutable = $false
        CanWriteToDirectory = $false
        CanReplaceExecutable = $false
        HasRisk = $false
    }
    
    if (-not $ExecutablePath) {
        return $result
    }
    
    try {
        if (-not (Test-Path $ExecutablePath -ErrorAction SilentlyContinue)) {
            return $result
        }
        
        # Test write access to executable
        try {
            $fileStream = [System.IO.File]::OpenWrite($ExecutablePath)
            $fileStream.Close()
            $result.CanWriteToExecutable = $true
            $result.HasRisk = $true
        }
        catch { }
        
        # Test write access to directory
        $directory = Split-Path $ExecutablePath -Parent
        if ($directory -and (Test-Path $directory -ErrorAction SilentlyContinue)) {
            try {
                $testFile = Join-Path $directory "test_$(Get-Random).tmp"
                [System.IO.File]::WriteAllText($testFile, "test")
                if (Test-Path $testFile -ErrorAction SilentlyContinue) {
                    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
                    $result.CanWriteToDirectory = $true
                    $result.CanReplaceExecutable = $true
                    $result.HasRisk = $true
                }
            }
            catch { }
        }
    }
    catch { }
    
    return $result
}

# Test service control permissions
function Test-ServiceControlPermissions {
    [CmdletBinding()]
    param(
        [string]$ServiceName,
        [string]$Status,
        [bool]$TestStartStop = $false
    )
    
    $result = @{
        CanStart = $false
        CanStop = $false
        CanChangeConfig = $false
        HasControlRisk = $false
        StartStopTested = $false
    }
    
    # Test configuration change
    try {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        Set-Service -Name $ServiceName -Description $service.Description -ErrorAction Stop
        $result.CanChangeConfig = $true
        $result.HasControlRisk = $true
    }
    catch { }
    
    # Only test start/stop if explicitly requested
    if ($TestStartStop) {
        $result.StartStopTested = $true
        
        if ($Status -eq "Stopped") {
            try {
                $serviceObj = Get-Service -Name $ServiceName -ErrorAction Stop
                $serviceObj.Start()
                $result.CanStart = $true
                
                Start-Sleep -Milliseconds 500
                $currentStatus = (Get-Service -Name $ServiceName).Status
                if ($currentStatus -eq "Running") {
                    try { 
                        $serviceObj.Stop()
                        Start-Sleep -Milliseconds 500
                    } catch { }
                }
            }
            catch { }
        }
        
        if ($Status -eq "Running") {
            try {
                $serviceObj = Get-Service -Name $ServiceName -ErrorAction Stop
                $serviceObj.Stop()
                $result.CanStop = $true
                
                Start-Sleep -Milliseconds 500
                try {
                    $serviceObj.Start()
                    Start-Sleep -Milliseconds 500
                } catch { }
            }
            catch { }
        }
    }
    
    return $result
}

# Determine risk level
function Get-ServiceRiskLevel {
    [CmdletBinding()]
    param(
        [bool]$CanQuery,
        [hashtable]$FilePerms,
        [hashtable]$ControlPerms
    )
    
    if (-not $CanQuery) { return "NoAccess" }
    
    if ($FilePerms.HasRisk) {
        return "Critical"
    }
    
    if ($ControlPerms.CanChangeConfig) {
        return "High"
    }
    
    if ($ControlPerms.CanStart) {
        return "Medium"
    }
    
    return "ReadOnly"
}

# Main script execution
# Handle VulnerableServicesOnly mode
if ($VulnerableServicesOnly) {
    $ShowOnlyFileSystemRisks = $true
}

if (-not $Quiet) {
    Write-Output "[*] ServicePermissionAudit v1.0"
    Write-Output "[*] Current User: $env:USERNAME"
    Write-Output "[*] Domain: $env:USERDOMAIN"
    Write-Output "[*] Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Output ""
}

if ($TestStartStop -and -not $Quiet) {
    Write-Output "[!] WARNING: TestStartStop enabled - this may actually start/stop services!"
    Write-Output "[!] Only testing services that match your filter criteria..."
    Write-Output ""
}

$services = Get-Service | Sort-Object Name
$riskyServices = @()
$stats = @{
    Total = 0
    Critical = 0
    High = 0
    Medium = 0
    ReadOnly = 0
    NoAccess = 0
}

if (-not $Quiet) {
    Write-Output "[*] Scanning $($services.Count) services..."
}

foreach ($service in $services) {
    $stats.Total++
    
    # Test basic query access
    try {
        $serviceConfig = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction Stop
        $canQuery = $true
    }
    catch {
        $canQuery = $false
    }
    
    if (-not $canQuery) {
        $stats.NoAccess++
        continue
    }
    
    # Get executable path and test permissions
    $execPath = Get-ServiceExecutablePath -PathName $serviceConfig.PathName
    $filePerms = Test-ServiceFilePermissions -ExecutablePath $execPath
    $controlPerms = Test-ServiceControlPermissions -ServiceName $service.Name -Status $service.Status -TestStartStop $false
    
    # Determine risk level
    $riskLevel = Get-ServiceRiskLevel -CanQuery $canQuery -FilePerms $filePerms -ControlPerms $controlPerms
    
    switch ($riskLevel) {
        "Critical" { $stats.Critical++ }
        "High" { $stats.High++ }
        "Medium" { $stats.Medium++ }
        "ReadOnly" { $stats.ReadOnly++ }
        default { $stats.NoAccess++ }
    }
    
    # Collect risky services for detailed output
    if ($riskLevel -in @("Critical", "High", "Medium")) {
        $riskyService = [PSCustomObject]@{
            ServiceName = $service.Name
            DisplayName = $service.DisplayName
            Status = $service.Status
            RiskLevel = $riskLevel
            CanChangeConfig = $controlPerms.CanChangeConfig
            CanStart = $false
            CanStop = $false
            CanWriteToExecutable = $filePerms.CanWriteToExecutable
            CanWriteToDirectory = $filePerms.CanWriteToDirectory
            CanReplaceExecutable = $filePerms.CanReplaceExecutable
            ExecutablePath = $execPath
            StartStopTested = $false
            LogOnAs = $serviceConfig.StartName
            StartMode = $serviceConfig.StartMode
        }
        $riskyServices += $riskyService
    }
}

# Display summary
if (-not $Quiet) {
    Write-Output ""
    Write-Output "[+] AUDIT SUMMARY"
    Write-Output "    Total Services: $($stats.Total)"
    Write-Output "    Critical Risk: $($stats.Critical)"
    Write-Output "    High Risk: $($stats.High)"
    Write-Output "    Medium Risk: $($stats.Medium)"
    Write-Output "    Read Only: $($stats.ReadOnly)"
    Write-Output "    No Access: $($stats.NoAccess)"
    Write-Output ""
}

# Filter services based on parameters
$servicesToShow = @()
if ($ShowOnlyFileSystemRisks) {
    foreach ($svc in $riskyServices) {
        if ($svc.CanWriteToExecutable -eq $true -or $svc.CanWriteToDirectory -eq $true -or $svc.CanReplaceExecutable -eq $true) {
            $servicesToShow += $svc
        }
    }
    if (-not $Quiet) {
        Write-Output "[+] FILE SYSTEM RISKS - CRITICAL ($($servicesToShow.Count) services)"
    }
}
elseif ($ShowAll) {
    # Show all services with basic info, then detailed analysis for Critical and High risk only
    if (-not $Quiet) {
        Write-Output "[+] ALL SERVICES ($($services.Count) total) - DETAILED ANALYSIS FOR CRITICAL & HIGH RISK"
    }
    
    # Create all services data
    $allServices = @()
    foreach ($service in $services) {
        $riskyService = $riskyServices | Where-Object { $_.ServiceName -eq $service.Name }
        
        if ($riskyService) {
            $allServices += $riskyService
        } else {
            try {
                $serviceConfig = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction Stop
                $execPath = Get-ServiceExecutablePath -PathName $serviceConfig.PathName
                $riskLevel = "ReadOnly"
            }
            catch {
                $execPath = $null
                $riskLevel = "NoAccess"
            }
            
            $basicService = [PSCustomObject]@{
                ServiceName = $service.Name
                DisplayName = $service.DisplayName
                Status = $service.Status
                RiskLevel = $riskLevel
                ExecutablePath = $execPath
                LogOnAs = if ($serviceConfig) { $serviceConfig.StartName } else { "Unknown" }
                StartMode = if ($serviceConfig) { $serviceConfig.StartMode } else { "Unknown" }
            }
            $allServices += $basicService
        }
    }
    
    # Sort by risk level then name
    $riskOrder = @{ "Critical" = 1; "High" = 2; "Medium" = 3; "ReadOnly" = 4; "NoAccess" = 5 }
    $allServices = $allServices | Sort-Object { $riskOrder[$_.RiskLevel] }, ServiceName
    
    # Output all services in structured format
    foreach ($svc in $allServices) {
        $pathDisplay = if ($svc.ExecutablePath) { $svc.ExecutablePath } else { "NotFound" }
        Write-Output "ServiceName      : $($svc.ServiceName)"
        Write-Output "DisplayName      : $($svc.DisplayName)"
        Write-Output "Status           : $($svc.Status)"
        Write-Output "RiskLevel        : $($svc.RiskLevel)"
        Write-Output "ExecutablePath   : $pathDisplay"
        Write-Output "LogOnAs          : $($svc.LogOnAs)"
        Write-Output "StartMode        : $($svc.StartMode)"
        Write-Output ""
    }
    
    # Set servicesToShow to only Critical and High risk services for detailed analysis
    $servicesToShow = $riskyServices | Where-Object { $_.RiskLevel -in @("Critical", "High") }
    if ($servicesToShow.Count -gt 0 -and -not $Quiet) {
        Write-Output "[+] DETAILED RISK ANALYSIS FOR CRITICAL & HIGH RISK SERVICES ($($servicesToShow.Count) services)"
    }
}
else {
    # Show all services with basic info, then detailed risky services
    if (-not $Quiet) {
        Write-Output "[+] ALL SERVICES ($($services.Count) total)"
    }
    
    # Create all services data
    $allServices = @()
    foreach ($service in $services) {
        $riskyService = $riskyServices | Where-Object { $_.ServiceName -eq $service.Name }
        
        if ($riskyService) {
            $allServices += $riskyService
        } else {
            try {
                $serviceConfig = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction Stop
                $execPath = Get-ServiceExecutablePath -PathName $serviceConfig.PathName
                $riskLevel = "ReadOnly"
            }
            catch {
                $execPath = $null
                $riskLevel = "NoAccess"
            }
            
            $basicService = [PSCustomObject]@{
                ServiceName = $service.Name
                DisplayName = $service.DisplayName
                Status = $service.Status
                RiskLevel = $riskLevel
                ExecutablePath = $execPath
                LogOnAs = if ($serviceConfig) { $serviceConfig.StartName } else { "Unknown" }
                StartMode = if ($serviceConfig) { $serviceConfig.StartMode } else { "Unknown" }
            }
            $allServices += $basicService
        }
    }
    
    # Sort by risk level then name
    $riskOrder = @{ "Critical" = 1; "High" = 2; "Medium" = 3; "ReadOnly" = 4; "NoAccess" = 5 }
    $allServices = $allServices | Sort-Object { $riskOrder[$_.RiskLevel] }, ServiceName
    
    # Output all services in structured format
    foreach ($svc in $allServices) {
        $pathDisplay = if ($svc.ExecutablePath) { $svc.ExecutablePath } else { "NotFound" }
        Write-Output "ServiceName      : $($svc.ServiceName)"
        Write-Output "DisplayName      : $($svc.DisplayName)"
        Write-Output "Status           : $($svc.Status)"
        Write-Output "RiskLevel        : $($svc.RiskLevel)"
        Write-Output "ExecutablePath   : $pathDisplay"
        Write-Output "LogOnAs          : $($svc.LogOnAs)"
        Write-Output "StartMode        : $($svc.StartMode)"
        Write-Output ""
    }
    
    # Set servicesToShow to risky services for detailed analysis
    $servicesToShow = $riskyServices
    if ($servicesToShow.Count -gt 0 -and -not $Quiet) {
        Write-Output "[+] DETAILED RISK ANALYSIS ($($servicesToShow.Count) elevated services)"
    }
}

if ($servicesToShow.Count -eq 0) {
    if (-not $Quiet) {
        Write-Output "[+] No services found matching criteria."
    }
    exit 0
}

# Test start/stop permissions if requested
if ($TestStartStop -and $servicesToShow.Count -gt 0) {
    if (-not $Quiet) {
        Write-Output "[*] Testing start/stop permissions on $($servicesToShow.Count) services..."
    }
    
    $updatedServices = @()
    for ($i = 0; $i -lt $servicesToShow.Count; $i++) {
        $service = $servicesToShow[$i]
        
        $startStopPerms = Test-ServiceControlPermissions -ServiceName $service.ServiceName -Status $service.Status -TestStartStop $true
        
        $updatedService = [PSCustomObject]@{
            ServiceName = $service.ServiceName
            DisplayName = $service.DisplayName
            Status = $service.Status
            RiskLevel = $service.RiskLevel
            CanChangeConfig = $service.CanChangeConfig
            CanStart = $startStopPerms.CanStart
            CanStop = $startStopPerms.CanStop
            CanWriteToExecutable = $service.CanWriteToExecutable
            CanWriteToDirectory = $service.CanWriteToDirectory
            CanReplaceExecutable = $service.CanReplaceExecutable
            ExecutablePath = $service.ExecutablePath
            StartStopTested = $startStopPerms.StartStopTested
            LogOnAs = $service.LogOnAs
            StartMode = $service.StartMode
        }
        $updatedServices += $updatedService
    }
    
    $servicesToShow = $updatedServices
    
    if (-not $Quiet) {
        Write-Output "[+] Start/Stop testing completed."
    }
}

# Output detailed service information
if ($ShowOnlyFileSystemRisks -or $ShowAll -or ($servicesToShow.Count -gt 0 -and $servicesToShow[0].RiskLevel -in @("Critical", "High", "Medium"))) {
    foreach ($service in $servicesToShow) {
        Write-Output "ServiceName      : $($service.ServiceName)"
        Write-Output "DisplayName      : $($service.DisplayName)"
        Write-Output "Status           : $($service.Status)"
        Write-Output "RiskLevel        : $($service.RiskLevel)"
        Write-Output "ExecutablePath   : $(if ($service.ExecutablePath) { $service.ExecutablePath } else { 'NotFound' })"
        Write-Output "LogOnAs          : $($service.LogOnAs)"
        Write-Output "StartMode        : $($service.StartMode)"
        Write-Output "CanChangeConfig  : $($service.CanChangeConfig)"
        Write-Output "CanWriteToExe    : $($service.CanWriteToExecutable)"
        Write-Output "CanWriteToDir    : $($service.CanWriteToDirectory)"
        Write-Output "CanReplaceExe    : $($service.CanReplaceExecutable)"
        
        if ($service.StartStopTested) {
            Write-Output "CanStart         : $($service.CanStart)"
            Write-Output "CanStop          : $($service.CanStop)"
            Write-Output "StartStopTested  : True"
        } else {
            Write-Output "StartStopTested  : False"
        }
        Write-Output ""
    }
}

# Summary of findings
if (-not $Quiet -and ($stats.Critical -gt 0 -or $stats.High -gt 0 -or $stats.Medium -gt 0)) {
    Write-Output "[!] SECURITY FINDINGS"
    if ($stats.Critical -gt 0) {
        Write-Output "    CRITICAL: $($stats.Critical) services have file system write access"
    }
    if ($stats.High -gt 0) {
        Write-Output "    HIGH: $($stats.High) services allow configuration changes"
    }
    if ($stats.Medium -gt 0) {
        Write-Output "    MEDIUM: $($stats.Medium) services allow start operations"
    }
    
    if ($TestStartStop) {
        $canStartServices = $servicesToShow | Where-Object { $_.CanStart -eq $true }
        $canStopServices = $servicesToShow | Where-Object { $_.CanStop -eq $true }
        
        if ($canStartServices.Count -gt 0) {
            Write-Output "    START: $($canStartServices.Count) services can be started"
        }
        if ($canStopServices.Count -gt 0) {
            Write-Output "    STOP: $($canStopServices.Count) services can be stopped"
        }
    }
    Write-Output ""
}