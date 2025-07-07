function Get-ServiceRegistry {
    <#
    .SYNOPSIS
        Finds services where low privilege users have full control access.
    
    .DESCRIPTION
        This function checks all Windows services in the registry to find services where 
        low privilege users or groups have been granted full control permissions. This 
        can be a security concern as it may allow privilege escalation.
    
    .EXAMPLE
        Get-ServiceRegistry
        
        Checks all services and displays any that have low privilege full control access.
    
    .NOTES
        Requires PowerShell to be run with sufficient privileges to read service registry keys.
        Some services may be inaccessible due to permissions, which is normal behavior.
    #>
    
    [CmdletBinding()]
    param()
    
    begin {
        Write-Host "Checking for services with low privilege full control access..."
        Write-Host ""
    }
    
    process {
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
            }
            catch {
                # Skip services we can't read (access denied is normal for many system services)
                continue
            }
        }

        # Output results
        if ($results.Count -eq 0) {
            Write-Host "No services found with low privilege full control access."
        }
        else {
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
    }
}

# Export the function
Export-ModuleMember -Function Get-ServiceRegistry