# Simple Service Full Control Checker
# Finds services where low privilege users have full control

Write-Host "Checking for services with low privilege full control access..." 
Write-Host ""

# Get all services from registry
$servicesPath = "HKLM:\SYSTEM\CurrentControlSet\Services"
$services = Get-ChildItem -Path $servicesPath

$results = @()

foreach ($service in $services) {
    $serviceName = $service.PSChildName
    $servicePath = $service.PSPath
    
    try {
        # Get ACL for the service
        $acl = Get-Acl -Path $servicePath -ErrorAction Stop
        
        foreach ($rule in $acl.Access) {
            # Only check Allow rules
            if ($rule.AccessControlType -eq "Allow") {
                
                # Check if this rule grants FullControl
                if ($rule.RegistryRights -match "FullControl") {
                    
                    $identity = $rule.IdentityReference.Value
                    
                    # Check if this is a low privilege user/group
                    # Exclude high privilege accounts
                    if ($identity -notmatch "NT AUTHORITY\\SYSTEM" -and
                        $identity -notmatch "BUILTIN\\Administrators" -and 
                        $identity -notmatch "NT SERVICE\\TrustedInstaller" -and
                        $identity -notmatch "CREATOR OWNER") {
                        
                        # This is potentially a low privilege user with full control
                        $result = [PSCustomObject]@{
                            ServiceName = $serviceName
                            ServicePath = $servicePath
                            Identity = $identity
                            Permissions = $rule.RegistryRights.ToString()
                        }
                        
                        $results += $result
                    }
                }
            }
        }
        
    } catch {
        # Skip services we can't read (access denied is normal for many system services)
        continue
    }
}

# Output results
if ($results.Count -eq 0) {
    Write-Host "No services found with low privilege full control access." 
} else {
    Write-Host "Found $($results.Count) services with low privilege full control:" 
    Write-Host ""
    
    $results | Format-Table ServiceName, Identity, Permissions -AutoSize
    
    Write-Host ""
    Write-Host "Detailed Results:" 
    foreach ($result in $results) {
        Write-Host "Service: $($result.ServiceName)" 
        Write-Host "  Path: $($result.ServicePath)" 
        Write-Host "  Identity: $($result.Identity)" 
        Write-Host "  Permissions: $($result.Permissions)"
        Write-Host ""
    }
}