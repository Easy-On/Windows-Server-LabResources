[CmdletBinding()]
param (
    [Parameter()]
    [switch]
    $SkipDependencies
)

#region constants

$adminUsername = @{
    adatum = 'Administrator@ad.adatum.com'
    local = '.\Administrator'
}
$defaultPassword = 'Pa$$w0rd'
$defaultSecurePassword = `
    ConvertTo-SecureString -String $defaultPassword -AsPlainText -Force
$adminCredential = @{
    adatum = New-Object `
        -TypeName pscredential `
        -ArgumentList $adminUsername.adatum, $defaultSecurePassword
    local = New-Object `
        -TypeName pscredential `
        -ArgumentList $adminUsername.local, $defaultSecurePassword
}

#endregion constants

$startDate = Get-Date

#region Helper functions
function Connect-PSSession {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]
        $ComputerName,
        [pscredential]
        $Credential
    )

    $parameters = $PSBoundParameters

    $psSession = Get-PSSession | Where-Object { 
        $PSItem.Availability -eq 'Available' -and `
        $PSItem.ComputerName -in $ComputerName
    }

    
    $parameters.ComputerName = $parameters.ComputerName | Where-Object {
        $PSItem -notin $psSession.ComputerName
    }

    if ($parameters.ComputerName) {
        $newPSSession = New-PSSession @parameters
        $psSession += $newPSSession
    }
    return $psSession
}

function Wait-WSMan {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Position = 0)]
        [string]
        $ComputerName,
        [ValidateSet(
            'Basic', 
            'ClientCertificate', 
            'Credssp',
            'Default',
            'Digest',
            'Kerberos',
            'Negotiate',
            'None'
        )]
        [string]
        $Authentication,
        [int32]
        $Port,
        [switch]
        $UseSSL,
        [string]
        $ApplicationName,
        [pscredential]
        $Credential,
        [String]
        $CertificateThumbprint,
        [Int32]
        $Timeout,
        [Int16]
        $Delay = 5
    )
    $parameters = $PSBoundParameters
    $null = $parameters.Remove('Timeout')
    $null = $parameters.Remove('Delay')
    $start = (Get-Date)
    while (
        -not (Test-WSMan @parameters -ErrorAction SilentlyContinue)
    ) {
        if ($Timeout -and $start.AddSeconds($Timeout) -lt (Get-Date)) {
            break
        }
        Start-Sleep $Delay
    }
    # Repeat test, in case we got an error

    $null = Test-WSMan @parameters
}

#endregion Helper functions

#region Prerequisites

if (-not $SkipDependencies) {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-Dependencies.ps1') `
        -Script $MyInvocation.MyCommand `
        -Confirm:$false
}

$trustedHostsPath = 'wsman:\localhost\Client\TrustedHosts'
$trustedHosts = Get-Item -Path $trustedHostsPath
Set-Item `
    -Path $trustedHostsPath `
    -Value `
        '10.1.2.16, VN1-SRV1.ad.adatum.com, VN1-SRV5.ad.adatum.com, VN2-SRV1.ad.adatum.com, VN2-SRV2.ad.adatum.com, CL1.ad.adatum.com, CL3.ad.adatum.com' `
    -Force

<#
    Change the local DNS client server address to ensure resolution of server
    names in all cases. The final DNS client server address is configured later
    in this script.
#>

$interfaceIndex = (
    Get-DnsClientServerAddress -AddressFamily IPv4 |
    Where-Object { $PSItem.ServerAddresses }
).InterfaceIndex[0]

Set-DnsClientServerAddress `
    -InterfaceIndex $interfaceIndex -ServerAddress '10.1.1.8'

#endregion Prerequisites

Write-Host 'Lab: Deploying domain controllers'

#region Exercise 1: Deploy additional domain controllers

Write-Host '    Exercise 1: Deploy additional domain controllers'

#region Task 1: Install the Remote Server Administration DNS Server Tools

Write-Host '        Task 1: Install the Remote Server Administration DNS Server Tools'

& $PSScriptRoot\Install-RSATModule.ps1 `
    -Name DNS `
    -ComputerName CL1.ad.adatum.com `
    -Credential $adminCredential.adatum

#endregion Task 1: Install the Remote Server Administration DNS Server Tools

#region Task 2: Install Active Directory Domain Services

Write-Host '        Task 2: Install Active Directory Domain Services'

$computerName = 'VN1-SRV5.ad.adatum.com', 'VN2-SRV1.ad.adatum.com'
$name = 'AD-Domain-Services'

$psSession = Connect-PSSession `
    -ComputerName $computerName -Credential $adminCredential.adatum

$windowsFeature = Invoke-Command -Session $psSession -ScriptBlock { 
    Get-WindowsFeature -Name $using:name 
}

$computerName = `
    ($windowsFeature | Where-Object { -not $PSItem.Installed }).PSComputerName

if ($computerName) {
    Write-Verbose "Install the windows feature Active Directory Domain Services on $computerName."
    $featureOperationResult = Invoke-Command `
        -Session $psSession -ScriptBlock { `
            Install-WindowsFeature -Name $using:name -IncludeManagementTools
        }
    
    $computerName = (
        $featureOperationResult | 
        Where-Object { $PSItem.RestartNeeded -eq 'Yes' }
    ).PSComputerName
    
    

    if ($computerName) {
        Write-Verbose "Restart $computerName."
        $psSession | Remove-PSSession
        Restart-Computer `
            -ComputerName $computerName `
            -WsmanAuthentication Default `
            -Credential $adminCredential.adatum `
            -Wait -For WinRM `
            -TimeOut 600 `
            -Force
    }
}


#endregion Task 2: Install Active Directory Domain Services

#region Task 3: Configure Active Directory Domain Services as an additional domain controller in an existing domain

Write-Host '        Task 3: Configure Active Directory Domain Services as an additional domain controller in an existing domain'
$dcDeploymentSuccess = $false

$computerName = 'VN1-SRV5.ad.adatum.com'
$psSession = Connect-PSSession `
    -ComputerName $computerName -Credential $adminCredential.adatum
$aDDomainController = Invoke-Command -Session $psSession -ScriptBlock {
    $securePassword = ConvertTo-SecureString `
        -String $using:defaultPassword -AsPlainText -Force
    $credential = New-Object `
        -TypeName pscredential `
        -ArgumentList `
            $using:adminUsername.adatum, $securePassword
    Get-ADDomainController -Filter * -Credential $credential
}

$computerName = 'VN1-SRV5', 'VN2-SRV1'
$computerName = $computerName | 
    Where-Object { $PSItem -notin $aDDomainController.Name } | ForEach-Object { "$PSItem.ad.adatum.com" }

$dcDeploymentSuccess = $true
if ($computerName) {
    Write-Verbose "Promoting $computerName as additional domain controller in $domainName"
    try {
        $psSession = Connect-PSSession `
            -ComputerName $computerName -Credential $adminCredential.adatum
        $result = Invoke-Command `
            -Session $psSession -ErrorAction Stop -ScriptBlock { `
                $securePassword = ConvertTo-SecureString `
                    -String $using:defaultPassword -AsPlainText -Force
                $safeModeAdministratorPassword = $securePassword
                $credential = New-Object `
                    -TypeName pscredential `
                    -ArgumentList `
                        $using:adminUsername.adatum, $securePassword
                $domainName = 'ad.adatum.com'

                Install-ADDSDomainController `
                    -DomainName $domainName `
                    -Credential $credential `
                    -SafeModeAdministratorPassword `
                        $safeModeAdministratorPassword `
                    -InstallDns `
                    -Force `
                    -NoRebootOnCompletion
            }
    }
    catch {
        $dcDeploymentSuccess = $false
        Write-Error $Error[0]
    }
    finally {
        $computerName = (
            $result | Where-Object { $PSItem.RebootRequired }
        ).PSComputerName
    
        if ($computerName) {
            Write-Verbose "Restart $computerName"
            $psSession | Remove-PSSession
            Restart-Computer `
                -ComputerName $computerName `
                -WsmanAuthentication Default `
                -Credential $adminCredential.adatum `
                -Wait -For WinRM `
                -TimeOut 600 `
                -Force
        }
    }

}
#endregion Task 3: Configure Active Directory Domain Services as an additional domain controller in an existing domain

#region Task 4: Configure forwarders

Write-Host '        Task 4: Configure forwarders'

if ($dcDeploymentSuccess) {
    foreach ($computerName in @(
        'VN1-SRV5.ad.adatum.com', 'VN2-SRV1.ad.adatum.com'
    )) {
        $psSession = Connect-PSSession `
            -ComputerName $computerName -Credential $adminCredential.adatum

        Write-Verbose `
            "Waiting for DNS service to start on $computerName"
        Invoke-Command -Session $psSession -ScriptBlock {
            $name = 'DNS'
            Get-Service -Name $name |
            Where-Object { $PSItem.Status -ne 'Running' } |
            Start-Service
        }

        $dnsServerForwarder = Invoke-Command -Session $psSession -ScriptBlock {
            Get-DnsServerForwarder
        }

        $desiredIPAddresses = @('8.8.8.8', '8.8.4.4')

        # Add forwarders

        $ipAddress = $desiredIPAddresses |
            Where-Object { $PSItem -notin $dnsServerForwarder.IPAddress }
        
        if ($ipAddress) {
            Write-Verbose "Add DNS forwarders $ipAddress on $computerName"

            Invoke-Command -Session $psSession -ScriptBlock {
                Add-DnsServerForwarder -IPAddress $using:ipAddress
            }
        }
        
        # Remove obsolete forwarders

        $ipAddress = $dnsServerForwarder.IPAddress | 
            Where-Object { $PSItem -notin $desiredIPAddresses }

        if ($ipAddress) {
            Write-Verbose "Remove DNS forwarders $ipAddress on $computerName"
    
            Invoke-Command -Session $psSession -ScriptBlock {
                Remove-DnsServerForwarder -IPAddress $using:ipAddress -Force
            }    
        }
    }
}
else {
    Write-Warning 'Additional domain controllers not deployed, skipping task.'
}

#endregion Task 4: Configure forwarders

#region Task 5: Configure DNS client settings

Write-Host '        Task 5: Configure DNS client settings'

if ($dcDeploymentSuccess) {
    $computerName = 'VN1-SRV5.ad.adatum.com'
    $desiredServerAddresses = '10.1.2.8', '127.0.0.1'
    $psSession = Connect-PSSession `
        -ComputerName $computerName -Credential $adminCredential.adatum

    $interfaceIndex = Invoke-Command -Session $psSession -ScriptBlock {
        (
            Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $PSItem.IPAddress -like '10.1.1.*' }
        ).InterfaceIndex
    }

    $dnsClientServerAddress = Invoke-Command -Session $psSession -ScriptBlock { 
        Get-DnsClientServerAddress `
            -InterfaceIndex $using:interfaceIndex -AddressFamily IPv4
    }

    # Determine if DNS client server addresses need to be changed

    $serverAddresses = (
        $dnsClientServerAddress.ServerAddresses | 
        Where-Object { $PSItem -notin $desiredServerAddresses }
    ) -join (
        $desiredServerAddress |
        Where-Object { $PSItem -notin $dnsClientServerAddresses.ServerAddresses }
    )

    if ($serverAddresses) {
        Write-Verbose "Set DNS client server addresses to $desiredServerAddresses on $computerName"
        Invoke-Command -Session $psSession -ScriptBlock {
            Set-DnsClientServerAddress `
                -InterfaceIndex $using:interfaceIndex `
                -ServerAddresses $using:desiredServerAddresses `
        }
    }
} else {
    Write-Warning 'Additional domain controllers not deployed, skipping task.'
}

#endregion Task 5: Configure DNS client settings

#endregion Exercise 1: Deploy additional domain controllers

#region Exercise 2: Check domain controller health

Write-Host '    Exercise 2: Check domain controller health'

#region Task 1: Verify DNS entries for Active Directory
    
Write-Host '        Task 1: Verify DNS entries for Active Directory'

if ($dcDeploymentSuccess) {
    $timeout = 600 # timeout in seconds
    
    Write-Verbose 'Verify CNAME records _msdcs.ad.adatum.com pointing to VN1-SRV5 and VN2-SRV1'
    $endDate = (Get-Date).AddSeconds($timeout)
    $computerName = 'VN1-SRV5.ad.adatum.com'
    $psSession = Connect-PSSession `
        -ComputerName $computerName -Credential $adminCredential.adatum
    Write-Verbose "Waiting for CNAME records until $endDate."
    while (
        (
            Invoke-Command `
                -Session $psSession -ScriptBlock {
                    Get-DnsServerResourceRecord `
                        -ZoneName _msdcs.ad.adatum.com `
                        -RRType CName |
                    Select-Object -ExpandProperty RecordData |
                    Where-Object {
                        $PSItem.HostNameAlias -in @(
                            'VN1-SRV5.ad.adatum.com.'
                            'VN2-SRV1.ad.adatum.com.'
                        )
                    }
                }
        ).Count -ne 2 -and (Get-Date) -le $endDate
    ) {
        Start-Sleep -Seconds 5                
    }

    if ((Get-Date) -gt $endDate) {
        Write-Warning 'CNAME records missing.'
        $dcDeploymentSuccess = $false
    }
    
    Write-Verbose 'Verify SRV records in ad.adatum.com pointing to VN1-SRV5 and VN2-SRV1.'
    $endDate = (Get-Date).AddSeconds($timeout)
    Write-Verbose "Waiting for SRV records until $endDate."
    while (
        (
            Invoke-Command `
                -Session $psSession -ScriptBlock {
                    Get-DnsServerResourceRecord `
                        -ZoneName ad.adatum.com `
                        -RRType SRV |
                    Select-Object -ExpandProperty RecordData |
                    Where-Object { 
                        $PSItem.DomainName -like '*VN1-SRV5.ad.adatum.com.' -or `
                        $PSItem.DomainName -like '*VN2-SRV1.ad.adatum.com.'
                    }
                }
        ).Count -lt 21 -and (Get-Date) -le $endDate
    ) {
        Start-Sleep -Seconds 5    
    }
    
    if ((Get-Date) -gt $endDate) {
        Write-Warning 'SRV records missing.'
        $dcDeploymentSuccess = $false
    }
} else {
    Write-Warning 'Additional domain controllers not deployed, skipping task.'
}
    
#endregion Task 1: Verify DNS entries for Active Directory

#region Task 2: Verify shares for Active Directory

Write-Host '        Task 2: Verify shares for Active Directory'

if ($dcDeploymentSuccess) {
    Write-Verbose 'Verify NETLOGON and SYSVOL Shares on VN1-SRV5'

    $computerName = 'VN1-SRV5.ad.adatum.com', 'VN2-SRV1.ad.adatum.com'
    $psSession = Connect-PSSession `
        -ComputerName $computerName -Credential $adminCredential.adatum

    $name = 'NETLOGON', 'SYSVOL'
    Write-Verbose "Verify $name share on $computerName"
    $smbShares = Invoke-Command -Session $psSession -ScriptBlock {
        Get-SmbShare -Name $using:name -ErrorAction SilentlyContinue
    }

    foreach ($item in $computerName) {
        $smbSharesOnComputer = $smbShares | 
            Where-Object { $PSItem.PSComputerName -eq $computerName }

        $missingShareName = $name | Where-Object {
            $PSItem -notin $smbSharesOnComputer.Name
        }
        if ($missingShares) {
            Write-Warning "$missingShareName share missing on $item"
            $dcDeploymentSuccess = $false
        }
    }
}
else {
    Write-Warning 'Additional domain controllers not deployed, skipping task.'
}

#endregion Task 2: Verify shares for Active Directory

#endregion Exercise 2: Check domain controller health

#region Exercise 3: Transfer flexible single master operation roles

Write-Host '    Exercise 3: Transfer flexible single master operation roles'

#region Task 1: Transfer the domain-wide flexible single master operation roles

Write-Host '        Task 1: Transfer the domain-wide flexible single master operation roles'

if ($dcDeploymentSuccess) {
    $operationMasterRoles = 'RIDMaster', 'InfrastructureMaster', 'PDCEmulator'
    $domain = 'ad.adatum.com'

    # FQDN of the server to receive the FSMO roles
    $identity = 'vn1-srv5'

    $computerName = 'VN1-SRV5.ad.adatum.com'
    $psSession = Connect-PSSession `
        -ComputerName $computerName -Credential $adminCredential.adatum
    
    Write-Verbose 'Get the properties of the AD domain.'
    $aDDomain = Invoke-Command -Session $psSession -ScriptBlock  {
        Get-ADDomain
    }

    foreach ($operationMasterRole in $operationMasterRoles) {
        if ($aDDomain.$operationMasterRole -ne "$identity.$domain") {
            Write-Verbose "Move the role $operationMasterRole to $identity."
            Invoke-Command -Session $psSession -ScriptBlock {
                Move-ADDirectoryServerOperationMasterRole `
                    -Identity $using:identity `
                    -OperationMasterRole $using:operationMasterRole `
                    -Confirm:$false
            }
        }
    }
} else {
    Write-Warning 'Additional domain controllers not deployed, skipping task.'
}

#endregion Task 1: Transfer the domain-wide flexible single master operation roles

#region Task 2: Transfer the forest-wide flexible single master operation roles

Write-Host '        Task 2: Transfer the forest-wide flexible single master operation roles'

if ($dcDeploymentSuccess) {
    $operationMasterRoles = 'SchemaMaster', 'DomainNamingMaster'
    $rootDomain = 'ad.adatum.com'

    # FQDN of the server to receive the FSMO roles
    $identity = 'vn1-srv5'

    $computerName = 'VN1-SRV5.ad.adatum.com'
    $psSession = Connect-PSSession `
        -ComputerName $computerName -Credential $adminCredential.adatum
    Write-Verbose 'Get the properties of the AD forest.'
    $aDForest = Invoke-Command -Session $psSession -ScriptBlock { Get-ADForest }

    foreach ($operationMasterRole in $operationMasterRoles) {
        if ($aDForest.$operationMasterRole -ne "$identity.$rootDomain") {
            Write-Verbose "Move the role $operationMasterRole to $identity."
            Invoke-Command -Session $psSession -ScriptBlock {
                Move-ADDirectoryServerOperationMasterRole `
                    -Identity $using:identity `
                    -OperationMasterRole $using:operationMasterRole `
                    -Confirm:$false
            }
        }
    }
}
else {
    Write-Warning 'Additional domain controllers not deployed, skipping task.'
}

#endregion Task 2: Transfer the forest-wide flexible single master operation roles
  
#endregion Exercise 3: Transfer flexible single master operation roles

#region Exercise 4: Decommission a domain controller

Write-Host '    Exercise 4: Decommission a domain controller'

#region Task 1: Change the DNS client server addresses

Write-Host '        Task 1: Change the DNS client server addresses'

if ($dcDeploymentSuccess) {
    $desiredServerAddresses = '10.1.1.40', '10.1.2.8'
    $interfaceIndex = (
        Get-DnsClientServerAddress -AddressFamily IPv4 |
        Where-Object { $PSItem.ServerAddresses }
    ).InterfaceIndex[0]

    $dnsClientServerAddress = Get-DnsClientServerAddress `
                -InterfaceIndex $interfaceIndex -AddressFamily IPv4 `

    # Determine if DNS client server addresses need to be changed

    $serverAddresses = (
        $dnsClientServerAddress.ServerAddresses | 
        Where-Object { $PSItem -notin $desiredServerAddresses }
    ) -join (
        $desiredServerAddresses |
        Where-Object { $PSItem -notin $dnsClientServerAddress.ServerAddresses }
    )

    if ($serverAddresses) {
        Write-Verbose "Set DNS client server addresses to $desiredServerAddresses on local computer"
        Set-DnsClientServerAddress `
            -InterfaceIndex $interfaceIndex `
            -ServerAddresses $desiredServerAddresses `
    }
} else {
    Write-Warning 'Additional domain controllers not deployed, skipping task.'
}

#endregion Task 1: Change the DNS client server addresses

#region Task 2: Change the IP address of the domain controller to decommission

Write-Host '        Task 2: Change the IP address of the domain controller to decommission'

if ($dcDeploymentSuccess) {
    $computerName = 'VN1-SRV1.ad.adatum.com'
    $newIPAddress = '10.1.1.9'
    $oldIPAddress = '10.1.1.8'
    
    $psSession = Connect-PSSession `
        -ComputerName $computerName `
        -Credential $adminCredential.adatum `
        -ErrorAction SilentlyContinue

    $addIPAddressSuccess = $false

    if ($psSession) {
        # Find netIPAddress on right subnet

        $netIPAddress = Invoke-Command `
            -Session $psSession -ErrorAction Stop -ScriptBlock {
                Get-NetIPAddress |
                Where-Object { $PSItem.IPAddress -like '10.1.1.*' }
            }

        # Set DNS Client server addresses

        $desiredServerAddresses = '10.1.1.40', '10.1.2.8'
    
        $dnsClientServerAddress = Invoke-Command `
            -Session $psSession -ScriptBlock { 
                Get-DnsClientServerAddress `
                    -InterfaceIndex $using:netIPAddress[0].InterfaceIndex `
                    -AddressFamily IPv4
            }
        
        # Determine if DNS client server addresses need to be changed
    
        $serverAddresses = (
            $dnsClientServerAddress.ServerAddresses | 
            Where-Object { $PSItem -notin $desiredServerAddresses }
        ) -join (
            $desiredServerAddresses |
            Where-Object { $PSItem -notin $dnsClientServerAddress.ServerAddresses }
        )
    
        if ($serverAddresses) {
            Write-Verbose "Set DNS client server addresses to $desiredServerAddresses on $computerName"
            Invoke-Command -Session $psSession -ScriptBlock {
                Set-DnsClientServerAddress `
                    -InterfaceIndex $using:netIPAddress[0].InterfaceIndex `
                    -ServerAddresses $using:desiredServerAddresses `
            }
        }

        # Add new IP address

        try {
            $addIPAddressSuccess = $true
    
            # If new IP address is not added yet
            if (
                -not ($netIPAddress |
                Where-Object { $PSItem.IPAddress -eq $newIPAddress })
            ) {
                Write-Verbose "Add the IP address $newIPAddress with the prefix length of 24 to $computerName."
                $null = Invoke-Command `
                    -Session $psSession -ErrorAction Stop -ScriptBlock {
                        New-NetIPAddress `
                            -InterfaceIndex $using:netIPAddress[0].InterfaceIndex `
                            -IPAddress $using:newIPAddress `
                            -PrefixLength 24 `
                    }
            }
            $psSession | Remove-PSSession
        }
        catch {
            $addIPAddressSuccess = $false
            Write-Error $Error[0]
        }
    
    }
    else {
        Write-Warning "Could not connect to $computerName. Is it decommissioned already?"
    }

    
    # Remove DNS A record

    if ($addIPAddressSuccess) {

        $zoneName = 'ad.adatum.com'
        $name = 'VN1-SRV1'
        while (
            (
                Resolve-DnsName `
                    -Name "$name.$zoneName" `
                    -Type A `
                    -ErrorAction SilentlyContinue
            ).IPAddress -ne '10.1.1.9'
        ) {
            $computerName = 'VN1-SRV5.ad.adatum.com'
            $psSession = Connect-PSSession `
                -ComputerName $computerName -Credential $adminCredential.adatum
    
            $dnsServerResourceRecord = Invoke-Command `
                -Session $psSession -ScriptBlock {
                    Get-DnsServerResourceRecord `
                        -ZoneName $using:zoneName `
                        -RRType A `
                        -Name $using:name `
                        -ErrorAction SilentlyContinue |
                    Where-Object { 
                        $PSItem.RecordData.IPv4Address -eq $using:oldIPAddress 
                    }
                }
    
            if ($dnsServerResourceRecord) {
                Write-Verbose `
                    "Remove the A record $dnsServerResourceRecord from DNS."
    
                Invoke-Command -Session $psSession -ScriptBlock {
                    $using:dnsServerResourceRecord | 
                    Remove-DnsServerResourceRecord `
                        -ZoneName $using:zoneName -Force
                }
            }                
            
            Write-Verbose 'Clear the DNS client cache.'
            Clear-DnsClientCache
        }



    }

    # Remove old IP address

    $removeIPAddressSuccess = $false
    $computerName = 'VN1-SRV1.ad.adatum.com'

    # TODO: Resolve-DnsName : VN1-SRV1.ad.adatum.com : DNS name does not exist

    if ( $addIPAddressSuccess -and `
        (
            Resolve-DnsName -Name $computerName -Type A
        ).IPAddress -ne $oldIPAddress
    ) {
        $psSession | Remove-PSSession
        $psSession = Connect-PSSession `
            -ComputerName $computerName `
            -Credential $adminCredential.adatum `
            -ErrorAction SilentlyContinue
    
        if ($psSession) {
            try {
                $netIPAddress = Invoke-Command `
                    -Session $psSession -ErrorAction Stop -ScriptBlock {
                        $using:netIPAddress |
                        Where-Object { $PSItem.IPAddress -eq $using:oldIPAddress }
                    }
                $removeIPAddressSuccess = $true
                if ($netIPAddress) {
                    Write-Verbose `
                        "Remove the IP address $oldIPAddress from $computerName."

                    Invoke-Command `
                        -Session $psSession -ErrorAction Stop -ScriptBlock {
                            $using:netIPAddress |
                            Remove-NetIPAddress -Confirm: $false
                        }
                }            
            }  
            catch {
                $removeIPAddressSuccess = $false
                Write-Error $Error[0]
            }
        }
        else {
            Write-Warning "Could not connect to $computerName. Is it decommissioned already?"
        }     
    }
}
else {
    Write-Warning 'Additional domain controllers not deployed, skipping task.'
}

#endregion Task 2: Change the IP address of the domain controller to decommission

#region Task 3: Add the IP address of the decommissioned domain controller to the new domain controller

Write-Host '        Task 3: Add the IP address of the decommissioned domain controller to the new domain controller'

$addIPAddressSuccess = $false
$computerName = 'VN1-SRV5.ad.adatum.com'

if ($removeIPAddressSuccess) {
    $psSession = Connect-PSSession `
        -ComputerName $computerName -Credential $adminCredential.adatum

    $addIPAddressSuccess = $true
    Write-Verbose 'Find the IP addresses of subnet 10.1.1.0'
    try {
        $netIPAddress = Invoke-Command `
            -Session $psSession -ErrorAction Stop -ScriptBlock {
                Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
                    $PSItem.IPAddress -like '10.1.1.*' 
                }
            }

        $ipAddress = '10.1.1.8'
        if (-not (
            $netIPAddress | Where-Object { $PSItem.IPAddress -eq $ipAddress }
        )) {
            Write-Verbose "Add the IP address $ipAddress with the prefix length of 24 to the interface."
            $null = Invoke-Command `
                -Session $psSession -ErrorAction Stop -ScriptBlock {
                    New-NetIPAddress `
                        -InterfaceIndex $using:netIPAddress[0].InterfaceIndex `
                        -IPAddress $using:ipAddress `
                        -PrefixLength 24
                }
        }

        $computerName = 'VN1-SRV5.ad.adatum.com', 'VN2-SRV1.ad.adatum.com'
        Write-Verbose "Clear the DNS client cache on $computerName"
        Invoke-Command `
            -Session $psSession -ErrorAction Stop -ScriptBlock {
                Clear-DnsClientCache
            }
    }
    catch {
        $addIPAddressSuccess = $false
        Write-Error $Error[0]
    }
}
else {
    Write-Warning `
        "Removal of $oldIPAddress from VN1-SRV1 failed, skipping task."
}

            
#endregion Task 3: Add the IP address of the decommissioned domain controller to the new domain controller

#region Task 4: Demote the old domain controller

Write-Host '        Task 4: Demote the old domain controller'

$uninstallDomainControllerSuccess = $false

if ($dcDeploymentSuccess -and $addIPAddressSuccess) {
    $uninstallDomainControllerSuccess = $true
    $psSession = Connect-PSSession `
        -ComputerName 'VN1-SRV5.ad.adatum.com' `
        -Credential $adminCredential.adatum
    if (
        Invoke-Command -Session $psSession -ScriptBlock {
                $securePassword = ConvertTo-SecureString `
                    -String $using:defaultPassword -AsPlainText -Force
                $credential = New-Object `
                    -TypeName pscredential `
                    -ArgumentList `
                        $using:adminUsername.adatum, $securePassword
                    Get-ADDomainController -Filter * -Credential $credential
            } | 
        Where-Object { $PSItem.Name -eq 'VN1-SRV1' }
    ) {
        $computerName = 'VN1-SRV1.ad.adatum.com'
        Write-Verbose "Demote the domain controller $computerName"
        $psSession = Connect-PSSession `
            -ComputerName $computerName `
            -Credential $adminCredential.adatum `
    
        if ($psSession) {
            try {
                $job = Invoke-Command `
                    -Session $psSession -AsJob -ErrorAction Stop -ScriptBlock {
                        $localAdministratorPassword = ConvertTo-SecureString `
                            -String 'Pa$$w0rd' -AsPlainText -Force
                        Uninstall-ADDSDomainController `
                            -LocalAdministratorPassword `
                                $localAdministratorPassword `
                            -Confirm:$false 
                }
                $null = $job | Wait-Job -ErrorAction Stop
            }
            catch {
                $uninstallDomainControllerSuccess = $false
                Write-Error $Error[0]
            }
        }
        else {
            Write-Warning "Could not connect to $computerName. Is it decommissioned already?"
        }     
    }
}
else {
    Write-Warning "$oldIPAddress not added to VN1-SRV5 or domain controller deployment not successful, skipping task."
}

#endregion Task 4: Demote the old domain controller

#region Task 5: Remove roles from the decommissioned domain controller

Write-Host '        Task 5: Remove roles from the decommissioned domain controller'

if ($uninstallDomainControllerSuccess) {
    $computerName = 'VN1-SRV1.ad.adatum.com'
    $name = 'AD-Domain-Services', 'DNS', 'FS-FileServer'

    $endDate = (Get-Date).AddMinutes(10)

    Write-Verbose "Waiting for $computerName to become available until $endDate"
    Wait-WSMan `
        -ComputerName $computerName `
        -Authentication Default `
        -Credential $adminCredential.adatum `
        -Timeout 600

    Start-Sleep -Seconds 60

    $psSession = Connect-PSSession `
        -ComputerName $computerName `
        -Credential $adminCredential.adatum `
        -ErrorAction SilentlyContinue

    if ($psSession) {
        $windowsFeature = Invoke-Command `
            -Session $psSession -ErrorAction Stop -ScriptBlock {
                Get-WindowsFeature -Name $using:name |
                Where-Object { $PSItem.Installed }
            }

        if ($windowsFeature) {
            Write-Verbose "Uninstall the features $($windowsFeature.Name) from $computerName."

            try {
                $null = Invoke-Command `
                    -Session $psSession -ErrorAction Stop -ScriptBlock {
                        $using:windowsFeature | Uninstall-WindowsFeature
                    }
    
                Write-Verbose "Shut down $computerName."
        
                Stop-Computer `
                    -ComputerName $computerName `
                    -WsmanAuthentication Default `
                    -Credential $adminCredential.local
            }
            catch {
                Write-Error $Error[0]
            }        
        }
    }
    else {
        Write-Warning "Could not connect to $computerName. Is it decommissioned already?"
    }

    $psSession | Remove-PSSession
}
else {
    Write-Warning "VN1-SRV1 not demoted as DC, skipping task"
}

#endregion Task 5: Remove roles from the decommissioned domain controller

#endregion Exercise 5: Decommission a domain controller

#region Exercise 5: Raise the domain and forest functional level

Write-Host '    Exercise 5: Raise the domain and forest functional level'

#region Task 1: Raise the domain functional level

Write-Host '        Task 1: Raise the domain functional level'

if ($dcDeploymentSuccess) {
    $domainMode = 'Windows2016Domain'
    $computerName = 'VN1-SRV5.ad.adatum.com'
    $psSession = Connect-PSSession `
        -ComputerName $computerName -Credential $adminCredential.adatum

    $aDDomain = Invoke-Command -Session $psSession -ScriptBlock { Get-ADDomain }
    if ($aDDomain.DomainMode -ne $domainMode) {
        Write-Verbose 'Set the domain mode to Windows Server 2016.'
        Invoke-Command -Session $psSession -ScriptBlock {
            Set-ADDomainMode `
                -Identity ad.adatum.com `
                -DomainMode $domainMode `
                -Confirm:$false
        }
    }
}
else {
    Write-Warning 'Additional domain controllers not deployed, skipping task.'
}


#endregion Task 1: Raise the domain functional level

#region Task 2: Raise the forest functional level

Write-Host '        Task 2: Raise the forest functional level'

if ($dcDeploymentSuccess) {
    $forestMode = 'Windows2016Forest'
    $computerName = 'VN1-SRV5.ad.adatum.com'
    $psSession = Connect-PSSession `
        -ComputerName $computerName -Credential $adminCredential.adatum
    $aDForest = Invoke-Command -Session $psSession -ScriptBlock { Get-ADForest }
        if ($aDForest.ForestMode -ne $forestMode) {
            Write-Verbose 'Set the forest mode to Windows Server 2016.'
            Invoke-Command -Session $psSession -ScriptBlock {
                Set-ADForestMode `
                    -Identity ad.adatum.com `
                    -ForestMode $forestMode `
                    -Confirm:$false
            }
        }
}
else {
    Write-Warning 'Additional domain controllers not deployed, skipping task.'
}

#endregion Task 2: Raise the forest functional level

#endregion Exercise 6: Raise the domain and forest functional level

Get-PSSession | Remove-PSSession

Set-Item -Path $trustedHostsPath -Value $trustedHosts.Value -Force
$endDate = Get-Date
$timeElapsed = $endDate - $startDate
Write-Verbose "Time elapsed: $timeElapsed"

# CL3 may need a restart at the end to complete domain join

if ($domainJoinSuccess -and $env:COMPUTERNAME -eq 'CL3') {
    Write-Host 'The local computer needs a restart'
    Read-Host 'Press ENTER to restart'
    Restart-Computer
}

