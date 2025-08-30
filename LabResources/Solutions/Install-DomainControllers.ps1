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
    contoso = 'Administrator@ad.contoso.com'
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
function Recycle-PSSession {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]
        $ComputerName,
        [pscredential]
        $Credential
    )

    $parameters = $PSBoundParameters

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

Write-Host `
    '        Task 1: Install the Remote Server Administration DNS Server Tools'

& $PSScriptRoot\Install-RSATModule.ps1 `
    -Name DNS `
    -ComputerName CL1.ad.adatum.com `
    -Credential $adminCredential.adatum

#endregion Task 1: Install the Remote Server Administration DNS Server Tools

#region Task 2: Disable network adapters

Write-Host '        Task 2: Disable network adapters'

Write-Verbose `
    'Disabling all network interfaces not connected to the 10.1.1.0 subnet'
$cimSession = New-CimSession -ComputerName 'VN1-SRV5'
Get-NetIPAddress -CimSession $cimSession |
Where-Object { 
    $PSItem.IPAddress -notlike '10.1.1.*' `
    -and $PSItem.PrefixOrigin -eq 'Manual' } |
Select-Object -ExpandProperty InterfaceAlias -Unique |
ForEach-Object {
    Disable-NetAdapter -Name $PSItem -CimSession $cimSession -Confirm:$false
}
Remove-CimSession $cimSession

#endregion Task 2: Disable network adapters

#region Task 3: Install Active Directory Domain Services

Write-Host '        Task 3: Install Active Directory Domain Services'

$computerName = 'VN1-SRV5.ad.adatum.com', 'VN2-SRV1.ad.adatum.com'
$name = 'AD-Domain-Services'

$psSession = Recycle-PSSession `
    -ComputerName $computerName -Credential $adminCredential.adatum

$windowsFeature = Invoke-Command -Session $psSession -ScriptBlock { 
    Get-WindowsFeature -Name $using:name 
}

$computerName = `
    ($windowsFeature | Where-Object { -not $PSItem.Installed }).PSComputerName

if ($computerName) {
    Write-Verbose `
        "Install the windows feature Active Directory Domain Services on $(
            $computerName
        )."
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


#endregion Task 3: Install Active Directory Domain Services

#region Task 4: Configure Active Directory Domain Services as an additional domain controller in an existing domain

Write-Host '        Task 4: Configure Active Directory Domain Services as an additional domain controller in an existing domain'
$dcDeploymentSuccess = $false

$computerName = 'VN1-SRV5.ad.adatum.com'
$psSession = Recycle-PSSession `
    -ComputerName $computerName -Credential $adminCredential.adatum

Write-Verbose 'Getting existing domain controller'
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
    Where-Object { $PSItem -notin $aDDomainController.Name } | 
    ForEach-Object { "$PSItem.ad.adatum.com" }
$domainName = 'ad.adatum.com'

$dcDeploymentSuccess = $true
if ($computerName) {
    $computerName | ForEach-Object {
        try {
            Write-Verbose "Promoting $(
                    $PSItem
                ) as additional domain controller in $(
                    $domainName
                )"
            $psSession = Recycle-PSSession -ComputerName $PSItem `
                -Credential $adminCredential.adatum
            $result = Invoke-Command `
                -Session $psSession `
                -ErrorAction Stop `
                -ThrottleLimit 1 `
                -ScriptBlock { `
                    $securePassword = ConvertTo-SecureString `
                        -String $using:defaultPassword -AsPlainText -Force
                    $safeModeAdministratorPassword = $securePassword
                    $credential = New-Object `
                        -TypeName pscredential `
                        -ArgumentList `
                            $using:adminUsername.adatum, $securePassword

                    Write-Verbose `
                        "Promoting $(
                            $env:hostname
                        ) as additional domain controller."
                    Install-ADDSDomainController `
                        -DomainName $using:domainName `
                        -Credential $credential `
                        -SafeModeAdministratorPassword `
                            $safeModeAdministratorPassword `
                        -Force `
                        -NoRebootOnCompletion
                }
        }
        catch {
            $dcDeploymentSuccess = $false
            Write-Error $Error[0]
        }
        finally {
            if ($result.RebootRequired) {
                Write-Verbose "Restart $PSItem"
                $psSession | Remove-PSSession
                Restart-Computer `
                    -ComputerName $PSItem `
                    -WsmanAuthentication Default `
                    -Credential $adminCredential.adatum `
                    -Wait -For WinRM `
                    -TimeOut 1200 `
                    -Force
            }
        }
    }
}

#endregion Task 4: Configure Active Directory Domain Services as an additional domain controller in an existing domain

#region Task 5: Configure forwarders

Write-Host '        Task 5: Configure forwarders'

if ($dcDeploymentSuccess) {
    foreach ($computerName in @(
        'VN1-SRV5.ad.adatum.com', 'VN2-SRV1.ad.adatum.com'
    )) {
        $psSession = Recycle-PSSession `
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

#endregion Task 5: Configure forwarders

#region Task 6: Configure DNS client settings

Write-Host '        Task 6: Configure DNS client settings'

if ($dcDeploymentSuccess) {
    $computerName = 'VN1-SRV5.ad.adatum.com'
    $desiredServerAddresses = '10.1.2.8', '127.0.0.1'
    $psSession = Recycle-PSSession `
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
        Write-Verbose `
            "Set DNS client server addresses to $(
                $desiredServerAddresses
            ) on $(
                $computerName
            )"
        Invoke-Command -Session $psSession -ScriptBlock {
            Set-DnsClientServerAddress `
                -InterfaceIndex $using:interfaceIndex `
                -ServerAddresses $using:desiredServerAddresses `
        }
    }
} else {
    Write-Warning 'Additional domain controllers not deployed, skipping task.'
}

#endregion Task 6: Configure DNS client settings

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
    $psSession = Recycle-PSSession `
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
    
    Write-Verbose `
        'Verify SRV records in ad.adatum.com pointing to VN1-SRV5 and VN2-SRV1.'
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
                        $PSItem.DomainName -like '*VN1-SRV5.ad.adatum.com.' `
                        -or $PSItem.DomainName -like '*VN2-SRV1.ad.adatum.com.'
                    }
                }
        ).Count -lt 26 -and (Get-Date) -le $endDate
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
    $psSession = Recycle-PSSession `
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
    $psSession = Recycle-PSSession `
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
    $psSession = Recycle-PSSession `
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

#region Exercise 4: Deploy a new forest

#region Task 1: Install Active Directory Domain Services

Write-Host '        Task 1: Install Active Directory Domain Services'

$computerName = 'VN2-SRV2.ad.adatum.com'
$name = 'AD-Domain-Services'

$psSession = Recycle-PSSession `
    -ComputerName $computerName -Credential $adminCredential.adatum

$windowsFeature = Invoke-Command -Session $psSession -ScriptBlock { 
    Get-WindowsFeature -Name $using:name 
}

$computerName = `
    ($windowsFeature | Where-Object { -not $PSItem.Installed }).PSComputerName

if ($computerName) {
    Write-Verbose `
        "Install the windows feature Active Directory Domain Services on $(
            $computerName
        )."
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


#endregion Task 1: Install Active Directory Domain Services

#region Task 2: Configure Active Directory Domain Services as a new forest

Write-Host `
    '        Task 2: Configure Active Directory Domain Services as a new forest'
$dcDeploymentSuccess = $false

$computerName = 'VN2-SRV2.ad.adatum.com'
$psSession = Recycle-PSSession `
    -ComputerName $computerName -Credential $adminCredential.local

Write-Verbose 'Getting existing domain controller'
$aDDomainController = Invoke-Command -Session $psSession -ScriptBlock {
    $securePassword = ConvertTo-SecureString `
        -String $using:defaultPassword -AsPlainText -Force
    $credential = New-Object `
        -TypeName pscredential `
        -ArgumentList `
            $using:adminUsername.contoso, $securePassword
    Get-ADDomainController -Filter * -Credential $credential
}

$computerName = 'VN2-SRV2'
$computerName = $computerName | 
    Where-Object { $PSItem -notin $aDDomainController.Name } | 
    ForEach-Object { "$PSItem.ad.adatum.com" }
$domainName = 'ad.contoso.com'
$domainNetbiosName = 'contoso'

$dcDeploymentSuccess = $true
if ($computerName) {
        try {
            Write-Verbose "Configuring new forest $(
                    $domainName
                ) on $(
                    $computerName
                )"
            $psSession = Recycle-PSSession -ComputerName $PSItem `
                -Credential $adminCredential.contoso
            $result = Invoke-Command `
                -Session $psSession `
                -ErrorAction Stop `
                -ScriptBlock { `
                    $securePassword = ConvertTo-SecureString `
                        -String $using:defaultPassword -AsPlainText -Force
                    $safeModeAdministratorPassword = $securePassword
                    $credential = New-Object `
                        -TypeName pscredential `
                        -ArgumentList `
                            $using:adminUsername.contoso, $securePassword

                    Write-Verbose `
                        "Promoting $(
                            $env:hostname
                        ) as additional domain controller."
                    Install-ADDSForest `
                        -DomainName $using:domainName `
                        -DomainNetbiosName $using:domainNetbiosName `
                        -ForestMode default `
                        -DomainMode default `
                        -DomainNetbiosName $using:domainNetbiosName `
                        -CreateDnsDelegation $false `
                        -InstallDNS `
                        -SafeModeAdministratorPassword `
                            $safeModeAdministratorPassword `
                        -Force `
                        -NoRebootOnCompletion
                }
        }
        catch {
            $dcDeploymentSuccess = $false
            Write-Error $Error[0]
        }
        finally {
            if ($result.RebootRequired) {
                Write-Verbose "Restart $PSItem"
                $psSession | Remove-PSSession
                Restart-Computer `
                    -ComputerName $PSItem `
                    -WsmanAuthentication Default `
                    -Credential $adminCredential.adatum `
                    -Wait -For WinRM `
                    -TimeOut 1200 `
                    -Force
            }
    }
}

#endregion Task 2: Configure Active Directory Domain Services as an additional domain controller in an existing domain

#region Task 3: Configure forwarders

Write-Host '        Task 3: Configure forwarders'

if ($dcDeploymentSuccess) {
    foreach ($computerName in @(
        'VN2-SRV2.ad.adatum.com'
    )) {
        $psSession = Recycle-PSSession `
            -ComputerName $computerName -Credential $adminCredential.contoso

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

#endregion Task 3: Configure forwarders

#region Task 4: Change the DNS client server addresses on CL3

Write-Host '        Task 4: Change the DNS client server addresses on CL3'

if ($dcDeploymentSuccess) {
    $computerName = '3'
    $desiredServerAddresses = '10.1.2.16'
    $psSession = Recycle-PSSession `
        -ComputerName $computerName -Credential $adminCredential.local

    $interfaceIndex = Invoke-Command -Session $psSession -ScriptBlock {
        (
            Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $PSItem.IPAddress -like '10.1.2.*' }
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
        Where-Object { 
            $PSItem -notin $dnsClientServerAddresses.ServerAddresses
        }
    )

    if ($serverAddresses) {
        Write-Verbose `
            "Set DNS client server addresses to $(
                $desiredServerAddresses
            ) on $(
                $computerName
            )"
        Invoke-Command -Session $psSession -ScriptBlock {
            Set-DnsClientServerAddress `
                -InterfaceIndex $using:interfaceIndex `
                -ServerAddresses $using:desiredServerAddresses `
        }
    }
} else {
    Write-Warning 'Additional domain controllers not deployed, skipping task.'
}

#endregion Task 4: Change the DNS client server addresses on CL3

#region Task 5: Join CL3 to the domain ad.contoso.com

Write-Host '        Task 5: Join CL3 to the domain ad.contoso.com'

if ($dcDeploymentSuccess) {
    $computerName = 'CL3'
    $domainName = 'ad.contoso.com'
    $credential = $adminCredential.local
    $restart = $env:COMPUTERNAME -ne $computerName
    $psSession = Recycle-PSSession `
        -ComputerName $computerName -Credential $credential

    Invoke-Command -Session $psSession -ScriptBlock {
        Add-Computer `
            -DomainName $using:domainName `
            -Credential $using:credential `
            -Restart:$using:restart
    }
    $domainJoinSuccess = $true
} else {
    Write-Warning 'Additional domain controllers not deployed, skipping task.'
}

# CL3 may need a restart at the end to complete domain join

if ($domainJoinSuccess -and $env:COMPUTERNAME -eq 'CL3') {
    Write-Host 'The local computer needs a restart'
    Read-Host 'Press ENTER to restart'
    Restart-Computer
}

#endregion Task 5: Join CL3 to the domain ad.contoso.com

#endregion Exercise 4: Deploy a new forest

Get-PSSession | Remove-PSSession

Set-Item -Path $trustedHostsPath -Value $trustedHosts.Value -Force
$endDate = Get-Date
$timeElapsed = $endDate - $startDate
Write-Verbose "Time elapsed: $timeElapsed"


