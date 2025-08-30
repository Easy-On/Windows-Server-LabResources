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
function Request-PSSession {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]
        $ComputerName,
        [pscredential]
        $Credential
    )

    # Find existing sessions to the computers

    $psSession = @()
    $psSession += Get-PSSession | Where-Object { 
        $PSItem.Availability -eq 'Available' -and `
        $PSItem.ComputerName -in $ComputerName
    }

    # Filter computer names without available session

    $ComputerName = $ComputerName | Where-Object {
        $PSItem -notin $psSession.ComputerName
    }

    if ($ComputerName) {
        $newPSSession = New-PSSession `
            -ComputerName $ComputerName -Credential $Credential
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

#endregion Prerequisites

Write-Host 'Lab: Finalizing Active Directory upgrade'

#region Exercise 1: Decommission a domain controller

Write-Host '    Exercise 1: Decommission a domain controller'

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
        Write-Verbose "Set DNS client server addresses to $(
            $desiredServerAddresses
        ) on local computer"
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
    
    $psSession = Request-PSSession `
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
            Where-Object { 
                $PSItem -notin $dnsClientServerAddress.ServerAddresses 
            }
        )
    
        if ($serverAddresses) {
            Write-Verbose "Set DNS client server addresses to $(
                $desiredServerAddresses
            ) on $(
                $computerName
            )"
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
                Write-Verbose `
                    "Add the IP address $(
                        $newIPAddress
                    ) with the prefix length of 24 to $(
                        $computerName
                    )."
                $null = Invoke-Command `
                    -Session $psSession -ErrorAction Stop -ScriptBlock {
                        New-NetIPAddress `
                            -InterfaceIndex `
                                $using:netIPAddress[0].InterfaceIndex `
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
        Write-Warning `
            "Could not connect to $computerName. Is it decommissioned already?"
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
            $psSession = Request-PSSession `
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

    if ( $addIPAddressSuccess -and `
        (
            Resolve-DnsName -Name $computerName -Type A
        ).IPAddress -ne $oldIPAddress
    ) {
        $psSession | Remove-PSSession
        $psSession = Request-PSSession `
            -ComputerName $computerName `
            -Credential $adminCredential.adatum `
            -ErrorAction SilentlyContinue
    
        if ($psSession) {
            try {
                $netIPAddress = Invoke-Command `
                    -Session $psSession -ErrorAction Stop -ScriptBlock {
                        $using:netIPAddress |
                        Where-Object { 
                            $PSItem.IPAddress -eq $using:oldIPAddress 
                        }
                    }
                $removeIPAddressSuccess = $true
                if ($netIPAddress) {
                    Write-Verbose `
                        "Remove the IP address $(
                            $oldIPAddress
                        ) from $(
                            $computerName
                        )."

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
            Write-Warning `
                "Could not connect to $(
                    $computerName
                ). Is it decommissioned already?"
        }     
    }
}

if (-not $dcDeploymentSuccess) {
    Write-Warning 'Additional domain controllers not deployed, skipping task.'
}

#endregion Task 2: Change the IP address of the domain controller to decommission

#region Task 3: Add the IP address of the decommissioned domain controller to the new domain controller

Write-Host '        Task 3: Add the IP address of the decommissioned domain controller to the new domain controller'

$addIPAddressSuccess = $false
$computerName = 'VN1-SRV5.ad.adatum.com'

if ($removeIPAddressSuccess) {
    $psSession = Request-PSSession `
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
            Write-Verbose `
                "Add the IP address $(
                    $ipAddress
                ) with the prefix length of 24 to the interface."
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
    $psSession = Request-PSSession `
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
        $psSession = Request-PSSession `
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
                $result = Receive-Job -Job $job
                if ($result.Status -eq 'Error') {
                    Write-Error $result.Message
                    $uninstallDomainControllerSuccess = $false
                }
            }
            catch {
                $uninstallDomainControllerSuccess = $false
                Write-Error $Error[0]
            }
        }
        else {
            Write-Warning `
                "Could not connect to $(
                    $computerName
                ). Is it decommissioned already?"
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

    $psSession = Request-PSSession `
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
            Write-Verbose `
                "Uninstall the features $(
                    $windowsFeature.Name
                ) from $(
                    $computerName
                )."

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
        Write-Warning `
            "Could not connect to $computerName. Is it decommissioned already?"
    }

    $psSession | Remove-PSSession
}
else {
    Write-Warning "VN1-SRV1 not demoted as DC, skipping task"
}

#endregion Task 5: Remove roles from the decommissioned domain controller

#endregion Exercise 1: Decommission a domain controller

#region Exercise 2: Raise the domain and forest functional level

Write-Host '    Exercise 2: Raise the domain and forest functional level'

#region Task 1: Raise the domain functional level

Write-Host '        Task 1: Raise the domain functional level'

if ($dcDeploymentSuccess) {
    $domainMode = 'Windows2016Domain'
    $computerName = 'VN1-SRV5.ad.adatum.com'
    $psSession = Request-PSSession `
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
    $psSession = Request-PSSession `
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

#endregion Exercise 2: Raise the domain and forest functional level

#region Exercise 3: Enable database 32K pages

Write-Host '    Exercise 3: Enable database 32K pages'

#region Task 1: Verify that the domain has a 32k page capable database

Write-Host `
    '        Task 1: Verify that the domain has a 32k page capable database'

$psSession = Request-PSSession `
    -Computername 'VN1-SRV5.ad.adatum.com' -Credential $adminCredential.adatum


$properties = 'msDS-JetDBPageSize'
$jetDBPageSize = Invoke-Command -Session $psSession -ScriptBlock {
    $domainDN = (Get-ADDomain).DistinguishedName
    Get-ADObject `
        -LDAPFilter '(ObjectClass=nTDSDSA)' `
        -SearchBase "CN=Configuration,$domainDN" `
        -Properties $using:properties |
    Select-Object -ExpandProperty $using:properties
}

Write-Host "$using:properties is $jetDBPageSize"

#endregion Task 1: Verify that the domain has a 32k page capable database

#region Task 2: Enable the Database 32K pages optional feature

Write-Host '        Task 2: Enable the Database 32K pages optional feature'

$psSession = Request-PSSession `
    -Computername 'VN1-SRV5.ad.adatum.com' -Credential $adminCredential.adatum

if ($jetDBPageSize -eq 32768) {
    Write-Verbose 'Enabling Database 32k pages feature'
    Invoke-Command -Session $psSession -ScriptBlock {
    $target = (Get-ADDomain).DistinguishedName
        Enable-ADOptionalFeature `
            -Identity 'Database 32k pages feature' `
            -Scope 'ForestOrConfigurationSet' `
            -Target $target
    }
}

if ($jetDBPageSize -ne 32768) {
    Write-Error `
        "$(
            $properties
        ) is not 32768. Did the forest functional level get raised?"
}


#endregion Task 2: Enable database 32K pages

#endregion Exercise 3: Enable database 32K pages

Get-PSSession | Remove-PSSession

Set-Item -Path $trustedHostsPath -Value $trustedHosts.Value -Force
$endDate = Get-Date
$timeElapsed = $endDate - $startDate
Write-Verbose "Time elapsed: $timeElapsed"