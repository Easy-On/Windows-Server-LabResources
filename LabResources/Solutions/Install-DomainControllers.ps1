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
    contoso = New-Object `
        -TypeName pscredential `
        -ArgumentList $adminUsername.contoso, $defaultSecurePassword
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

function Install-ADDSFeature {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [string[]]
        $ComputerName,
        [Parameter(Mandatory)]
        [pscredential]
        $Credential
    )
    
    $aDDSfeatureInstalled = $false
    $name = 'AD-Domain-Services'
    
    try {
        $psSession = Request-PSSession `
            -ComputerName $ComputerName `
            -Credential $Credential `
            -ErrorAction Stop
        
        $windowsFeature = Invoke-Command `
            -Session $psSession -ErrorAction Stop -ScriptBlock { 
            Get-WindowsFeature -Name $using:name 
        }
        
        $computerName = (
                $windowsFeature | Where-Object { -not $PSItem.Installed }
            ).PSComputerName
        
        if (-not $computerName) {
            $aDDSfeatureInstalled = $true
        }
        if ($computerName) {
            Write-Verbose `
                "Install the windows feature Active Directory Domain Services on $(
                    $computerName
                )."
            $featureOperationResult = Invoke-Command `
                -Session $psSession -ErrorAction Stop -ScriptBlock  { `
                    Install-WindowsFeature `
                        -Name $using:name -IncludeManagementTools
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
                    -Force `
                    -ErrorAction Stop
            }
            $aDDSfeatureInstalled = $true
        }                
    }
    catch {
        $aDDSfeatureInstalled = $false
        Write-Error $Error[0]
    }

    return $aDDSfeatureInstalled
}

function Start-ADDSInstallDomainControllerJob {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ComputerName,
        [Parameter(Mandatory)]
        [pscredential]
        $Credential,
        [Parameter(Mandatory)]
        [string]
        $DomainName,
        [Parameter(Mandatory)]
        [securestring]
        $SafeModeAdministratorPassword,
        [pscredential]
        $DomainCredential = $Credential
    )

    $job = $null
    $psSession = Request-PSSession `
        -ComputerName $ComputerName `
        -Credential $Credential `
        -ErrorAction Stop

    $plainSafeModeAdministratorPasswordString = `
        [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
                $SafeModeAdministratorPassword
            )
        )

    $plainDomainUsername = $DomainCredential.UserName
    $plainDomainPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
            $DomainCredential.Password
        )
    )
    $job = Invoke-Command `
        -Session $psSession `
        -ErrorAction Stop `
        -AsJob `
        -ScriptBlock { `
            $safeModeAdministratorPassword = ConvertTo-SecureString `
                -String $using:plainSafeModeAdministratorPasswordString `
                -AsPlainText `
                -Force
            $credential = New-Object `
                -TypeName pscredential `
                -ArgumentList `
                    $using:plainDomainUsername, $using:plainDomainPassword
            Install-ADDSDomainController `
                -DomainName $using:DomainName `
                -Credential $credential `
                -SafeModeAdministratorPassword `
                    $safeModeAdministratorPassword `
                -Force
            }
    $psSession | Remove-PSSession
    return $job
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
        'VN1-SRV1.ad.adatum.com, VN1-SRV5.ad.adatum.com, VN2-SRV1.ad.adatum.com, VN2-SRV2.ad.adatum.com, CL1.ad.adatum.com, 10.1.2.16' `
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

$jobDnsServerTools = Start-Job `
    -FilePath (
        Join-Path -Path $PSScriptRoot -ChildPath 'Install-RSATModule.ps1'
    ) `
    -ArgumentList 'DNS', 'CL2.ad.adatum.com', $credential

#endregion Task 1: Install the Remote Server Administration DNS Server Tools

#region Task 2: Disable network adapters

Write-Host '        Task 2: Disable network adapters'

Write-Verbose `
    'Disabling all network interfaces not connected to the 10.1.1.0 subnet'
$cimSession = $null
$networkAdaptersDisabled = $false
$computerName = 'VN1-SRV5.ad.adatum.com'
try {
    $cimSession = New-CimSession -ComputerName $computerName -ErrorAction Stop
    Get-NetIPAddress -CimSession $cimSession -ErrorAction Stop |
    Where-Object { 
        $PSItem.IPAddress -notlike '10.1.1.*' `
        -and $PSItem.PrefixOrigin -eq 'Manual' } |
    Select-Object -ExpandProperty InterfaceAlias -Unique |
    ForEach-Object {
        Disable-NetAdapter `
            -Name $PSItem `
            -CimSession $cimSession `
            -Confirm:$false `
            -ErrorAction Stop
    }
    $networkAdaptersDisabled = $true
}
catch {
    $networkAdaptersDisabled = $false
}
finally {
    $cimSession | Remove-CimSession
}

#endregion Task 2: Disable network adapters

#region Task 3: Install Active Directory Domain Services

Write-Host '        Task 3: Install Active Directory Domain Services'

$aDDSfeatureInstalled = Install-ADDSFeature `
    -ComputerName 'VN1-SRV5.ad.adatum.com', 'VN2-SRV1.ad.adatum.com' `
    -Credential $adminCredential.adatum

#endregion Task 3: Install Active Directory Domain Services

#region Task 4: Configure Active Directory Domain Services as an additional domain controller in an existing domain

Write-Host '        Task 4: Configure Active Directory Domain Services as an additional domain controller in an existing domain'
$dcDeploymentSuccess = $false

if (-not $networkAdaptersDisabled) {
    Write-Error 'Disabling network adapters failed. Skipping deployment of DCs.'
}
if (-not $aDDSfeatureInstalled) {
    Write-Error `
        'Installing Active Directory Domain Services feature failed. Skipping deployment of DCs.'
}
if ($networkAdaptersDisabled -and $aDDSfeatureInstalled) {

    #region Retrieve the list of current domain controllers

    $computerName = 'VN1-SRV5.ad.adatum.com'
    $psSession = Request-PSSession `
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

    #endregion Retrieve the list of current domain controllers

    # Build a list of domain controller to be deployed
    $additionalDomainController = 'VN1-SRV5', 'VN2-SRV1'
    $domainName = 'ad.adatum.com'

    $dcDeploymentSuccess = $false

    if ($additionalDomainController[0] -in $aDDomainController.Name) {
        $dcDeploymentSuccess = $true
    }

    # Deploy first additional domain controller as background job

    if ($additionalDomainController[0] -notin $aDDomainController.Name) {
        Write-Verbose "Promoting $(
                $additionalDomainController[0]
            ) as additional domain controller in $(
                $domainName
            )"
        $additionalDomainControllerJob = `
            Start-ADDSInstallDomainControllerJob `
                -ComputerName `
                    "$($additionalDomainController[0]).ad.adatum.com" `
                -Credential $adminCredential.adatum `
                -DomainName $domainName `
                -SafeModeAdministratorPassword $defaultSecurePassword `
                -DomainCredential $adminCredential.adatum
    }
}

#endregion Task 4: Configure Active Directory Domain Services as an additional domain controller in an existing domain
#endregion Exercise 1: Deploy additional domain controllers


#region Exercise 2: Deploy a new forest

Write-Host '    Exercise 2: Deploy a new forest'

#region Task 1: Install Active Directory Domain Services on VN2-SRV2

Write-Host `
    '        Task 1: Install Active Directory Domain Services on VN2-SRV2'

$computerName = '10.1.2.16' # VN2-SRV2
$aDDSfeatureInstalled = $false
$aDDSfeatureInstalled = Install-ADDSFeature `
    -ComputerName $computerName `
    -Credential $adminCredential.local

#endregion Task 1: Install Active Directory Domain Services on VN2-SRV2

#region Task 2: Configure Active Directory Domain Services as new forest

Write-Host '        Task 2: Configure Active Directory Domain Services as new forest'

$computerName = '10.1.2.16' # VN2-SRV2
$psSession = Request-PSSession `
    -ComputerName $computerName -Credential $adminCredential.local


#region Configure the firewall to allow remote administration from different subnet

$netFirewallAddressFilter = Invoke-Command -Session $psSession -ScriptBlock {
    Get-NetFirewallRule -Name WINRM-HTTP-In-TCP-PUBLIC | 
    Get-NetFirewallAddressFilter
}

if ($netFirewallAddressFilter.RemoteIP -ne 'Any') {
    Write-Verbose 'Configure the firewall to allow remote administration from different subnet'
    Invoke-Command -Session $psSession -ScriptBlock {
        $using:netFirewallAddressFilter |
        Set-NetFirewallAddressFilter -RemoteAddress Any
    }
}

#endregion Configure the firewall to allow remote administration from different subnet

# Install new forest

$dcDeploymentSuccess = $false
if (-not $aDDSfeatureInstalled) {
    Write-Error `
        "Active Directory Domain Services feature could not be installed on $(
            $computerName
        ). Skipping deployment of new forest."
}

if ($aDDSfeatureInstalled) {
    $operatingSystemDC = Invoke-Command -Session $psSession -ScriptBlock {
        Get-WmiObject `
            -Query 'SELECT * from Win32_OperatingSystem where ProductType="2"'
        }
    if ($operatingSystemDC) {
        Write-Verbose `
            "Operating system on $(
                $computerName
            ) is already configured as domain controller."
        $dcDeploymentSuccess = $true
    }
    if (-not $operatingSystemDC) {
        $domainName = 'ad.contoso.com'
        $domainNetbiosName = 'CONTOSO'

        Write-Verbose `
            'Store the Directory Services Restore Mode (DSRM) password in a variable.'

        $safeModeAdministratorPassword = ConvertTo-SecureString `
            -String $defaultPassword -AsPlainText -Force

        Write-Verbose "Promote $computerName as new forest $domainName"
        $newForestJob = Invoke-Command -Session $psSession -AsJob -ScriptBlock {
            Install-ADDSForest `
                -DomainName $using:domainName `
                -DomainNetbiosName $using:domainNetbiosName `
                -SafeModeAdministratorPassword `
                    $using:safeModeAdministratorPassword `
                -InstallDns `
                -Force
        }
    }
}

#endregion Task 2: Configure Active Directory Domain Services as new forest

#endregion Exercise 2: Deploy a new forest

#region Wait for first additional domain controller to be deployed
$additionalDomainControllerJob | Wait-Job
$additionalDomainControllerJobResult = `
    Receive-Job -Job $additionalDomainControllerJob

if (
    $additionalDomainControllerJobResult `
    -and ($additionalDomainControllerJobResult.Status -eq 'Success')
) {
    $dcDeploymentSuccess = $true
    Write-Host $additionalDomainControllerJobResult.Message
}

if (
    -not $additionalDomainControllerJobResult `
    -or -not ($additionalDomainControllerJobResult.Status -eq 'Success')
){
    $dcDeploymentSuccess = $false
    if ($additionalDomainControllerJobResult) {
        Write-Error `
            "Deployment of $(
                $additionalDomainController[0]
            ) failed with error: $(
                $additionalDomainControllerJobResult.Message
            )"
    }
}
#endregion Wait for first additional domain controller to be deployed

if ($dcDeploymentSuccess) {
    #region Exercise 1: Deploy additional domain controllers

    Write-Host '    Exercise 1: Deploy additional domain controllers'

    #region Task 4: Configure Active Directory Domain Services as an additional domain controller in an existing domain

    Write-Host '        Task 4: Configure Active Directory Domain Services as an additional domain controller in an existing domain'

    $additionalDomainControllerJob = $null
    $additionalDomainControllerJob =  `
        $additionalDomainController[
            1..($additionalDomainController.Length - 1)
        ] |
        ForEach-Object {
            if ($PSItem -notin $aDDomainController.Name) {
                Write-Verbose `
                    "Promoting $(
                        $PSItem
                    ) as additional domain controller in $(
                        $domainName
                    )"
                Start-ADDSInstallDomainControllerJob `
                    -ComputerName $PSItem `
                    -Credential $adminCredential.adatum `
                    -DomainName $domainName `
                    -SafeModeAdministratorPassword $defaultSecurePassword `
                    -DomainCredential $adminCredential.adatum
            }
        }

    #endregion Task 4: Configure Active Directory Domain Services as an additional domain controller in an existing domain
}

#region Wait for forest to be deployed

$newForestJob | Wait-Job
$newForestJobResult = `
    Receive-Job -Job $newForestJob

if ($newForestJobResult -and ($newForestJobResult.Status -eq 'Success')) {
    $dcDeploymentSuccess = $true
    Write-Host $newForestJobResult.Message
}

if (
    -not $newForestJobResult -or -not ($newForestJobResult.Status -eq 'Success')
){
    $dcDeploymentSuccess = $false
    if ($newForestJobResult) {
        Write-Error `
            "Deployment of $(
                $additionalDomainController[0]
            ) failed with error: $(
                $newForestJobResult.Message
            )"
    }
}

#endregion Wait for forest to be deployed

#region Exercise 3: Join client to new forest

Write-Host '    Exercise 3: Join client to new forest'

#region Task 1: Change the DNS client settings

Write-Host '        Task 1: Change the DNS client settings'

if ($env:COMPUTERNAME -ne 'CL3') {
    Write-Warning 'Skipped task. Please rerun the script on CL3.'
}
if (-not $dcDeploymentSuccess) {
    Write-Error 'Skipped task. Deployment of new forest failed.'
}
if ($env:COMPUTERNAME -eq 'CL3' -and $dcDeploymentSuccess) {
    $desiredServerAddresses = '10.1.2.16'
    $interfaceIndex = (
        Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $PSItem.IPAddress -like '10.1.2.*' }
    ).InterfaceIndex

    $dnsClientServerAddress = Get-DnsClientServerAddress `
        -InterfaceIndex $interfaceIndex -AddressFamily IPv4

    Write-Verbose `
        "Set DNS client server addresses to $desiredServerAddresses on CL3"

    Set-DnsClientServerAddress `
        -InterfaceIndex $interfaceIndex `
        -ServerAddresses $desiredServerAddresses `
}

#endregion Task 1: Change the DNS client settings

#region Task 2: Connect to domain

Write-Host '        Task 2: Connect to domain'

if ($env:COMPUTERNAME -ne 'CL3') {
    Write-Warning 'Skipped task. Please rerun the script on CL3.'
}
if (-not $dcDeploymentSuccess) {
    Write-Error 'Skipped task. Deployment of new forest failed.'
}
$domainJoinSuccess = $false

if ($env:COMPUTERNAME -eq 'CL3' -and $dcDeploymentSuccess) {
    $interfaceIndex = (
        Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $PSItem.IPAddress -like '10.1.2.*' }
    ).InterfaceIndex

    $dnsClientServerAddress = Get-DnsClientServerAddress `
        -InterfaceIndex $interfaceIndex -AddressFamily IPv4

    $dnsClientServerAddressConfigured = `
        $dnsClientServerAddress.ServerAddresses.Count -eq 1 `
        -and $dnsClientServerAddress.ServerAddresses -contains '10.1.2.16'
    if (-not $dnsClientServerAddressConfigured) {
        Write-Error `
            'DNS client server address is not configured correctly. Skipping domain join.'
    }

    if ($dnsClientServerAddressConfigured) {
        $domainName = 'ad.contoso.com'
        $csDomain = (Get-ComputerInfo).CsDomain
        if ($csDomain -eq $domainName) {
            Write-Verbose "Computer is already a member of the domain $(
                $domainName
            )"
        }
        if ($csDomain -ne $domainName) {
            $seconds = 10
            while (
                -not (
                    Resolve-DnsName `
                        -Type SRV -Name "_kerberos._tcp.dc._msdcs.$domainName"
                )
            ) {
                Write-Verbose `
                    "Waiting $(
                        $seconds
                    ) seconds for domain $(
                        $domainName
                    ) to become available."
                Start-Sleep -Seconds $seconds
            }
        
            Write-Verbose "Add the computer to the domain $domainName."
            try {
                Add-Computer `
                    -DomainName $domainName `
                    -Credential $adminCredential.contoso `
                    -ErrorAction Stop
                $domainJoinSuccess = $true        
            }
            catch {
                $domainJoinSuccess = $false
                Write-Error $error[0]
            }
        }
    }
}

#endregion Task 2: Connect to domain

#endregion Exercise 3: Join client to new forest

#region Wait for additional domain controllers to be deployed

if ($additionalDomainControllerJob) {
    $additionalDomainControllerJob | ForEach-Object {
        $PSItem | Wait-Job
        $additionalDomainControllerJobResult = $null
        $additionalDomainControllerJobResult = `
            Receive-Job -Job $PSItem
    
        if (
            $additionalDomainControllerJobResult `
            -and ($additionalDomainControllerJobResult.Status -eq 'Success')
        ) {
            $dcDeploymentSuccess = $dcDeploymentSuccess -and $true
            Write-Host $additionalDomainControllerJobResult.Message
        }
    
        if (
            -not $additionalDomainControllerJobResult `
            -or -not ($additionalDomainControllerJobResult.Status -eq 'Success')
        ){
            $dcDeploymentSuccess = $false
            if ($additionalDomainControllerJobResult) {
                Write-Error `
                    "Deployment failed with error: $(
                        $additionalDomainControllerJobResult.Message
                    )"
            }
        }
    }
}

#endregion Wait for additional domain controllers to be deployed

#region Exercise 3: Check domain controller health

Write-Host '    Exercise 3: Check domain controller health'

#region Task 1: Verify DNS entries for Active Directory
    
Write-Host '        Task 1: Verify DNS entries for Active Directory'

if ($dcDeploymentSuccess ) {
    $dnsServers = '10.1.1.8', '10.1.1.40', '10.1.2.8'
   
    $domainControllers = 'vn1-srv5.ad.adatum.com', 'vn2-srv1.ad.adatum.com'
    $timeout = 600 # timeout in seconds

    $expectedDNSRecords = Invoke-Command `
        -ComputerName $domainControllers -ScriptBlock {
            Get-Content -Path 'C:\Windows\System32\config\netlogon.dns'
        }

    Write-Verbose "Waiting for DNS SRV records for Domain Controllers $(
        $domainControllers -join ', '
    ) to be available on $(
        $dnsServers -join ', '
    )"
    # Query each DNS server
    foreach ($server in $dnsServers) {

        # Go through the list of all expected DNS records line by line
        foreach ($expectedDNSRecord in $expectedDNSRecords) {

            # Split the line into columns using the space delimiter
            $expectedDNSRecordSplit = $expectedDNSRecord -split ' '

            # First column is the name
            $name = $expectedDNSRecordSplit[0]
            # Fourth column is the type
            $type = $expectedDNSRecordSplit[3]
            # Last column is the target
            $target = $expectedDNSRecordSplit[-1]

            $endDate = (Get-Date).AddSeconds($timeout)

            <# 
                If the target ends with a dot, remove it.
                Resolve-DnsName will return the target without the ending dot.
            #>
            if ($target[-1] -eq '.' ) {
                $target = $target.Substring(0, $target.Length - 1)
            }

            Write-Verbose `
                "Waiting for $(
                    $type
                ) record $(
                    $name
                ) pointing to $(
                    $target
                ) on DNS server $(
                    $dnsServer
                ) until $(
                    $endDate
                )"

            do {
                # Try to resolve the record
                $dnsRecords = Resolve-DnsName `
                    -Name $name `
                    -Type $type `
                    -Server $server `
                    -Verbose:$false `
                    -ErrorAction SilentlyContinue
    
                <# 
                    Check if target is in the result.
                    Unfortunately the property name for the target varies depending
                    on the type. Therefore, we mus handle each type separately.
                #>
                $missingRecord = $false
                switch ($type) { 
                    'A' {  
                        if ($dnsRecords.IPAddress -notcontains $target) {
                            $missingRecord = $true
                        }
                    }
                    'SRV' {  
                        if ($dnsRecords.NameTarget -notcontains $target) {
                            $missingRecord = $true
                        }
                    }
                    'CNAME' {
                        if ($dnsRecords.NameHost -notcontains $target) {
                            $missingRecord = $true
                        }
                    }
                    Default {
                        Write-Warning "Type $type not expected."
                    }
                }
    
            } until (
                -not $missingRecord -or (Get-Date) -gt $endDate
            )
            if ($missingRecord) {
                Write-Error `
                    "$(
                        $type
                    ) record $(
                        $name
                    ) targeting $(
                        $target
                    ) missing on DNS server $(
                        $dnsServer
                    )"
                $dcDeploymentSuccess = $false
            }
        }
        if (-not $dcDeploymentSuccess) {
            break
        }
    }
}

#endregion Task 1: Verify DNS entries for Active Directory

#region Task 2: Verify shares for Active Directory

Write-Host '        Task 2: Verify shares for Active Directory'

if ($dcDeploymentSuccess) {
    $computerName = 'VN1-SRV5.ad.adatum.com', 'VN2-SRV1.ad.adatum.com'
    $name = 'NETLOGON', 'SYSVOL'
    Write-Verbose "Verify $name share on $computerName"
    $psSession = Request-PSSession `
        -ComputerName $computerName -Credential $adminCredential.adatum

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
    Write-Error 'Additional domain controllers not deployed, skipping task.'
}

#endregion Task 2: Verify shares for Active Directory

#endregion Exercise 3: Check domain controller health

#region Exercise 4: Optimize DNS

Write-Host '    Exercise 4: Optimize DNS'

#region Task 1: Configure forwarders on VN1-SRV5 and VN2-SRV1

Write-Host '        Task 1: Configure forwarders on VN1-SRV5 and VN2-SRV1'

if ($dcDeploymentSuccess) {
    foreach ($computerName in @(
        'VN1-SRV5.ad.adatum.com', 'VN2-SRV1.ad.adatum.com'
    )) {
        $psSession = Request-PSSession `
            -ComputerName $computerName -Credential $adminCredential.adatum

        Write-Verbose `
            "Waiting for DNS service to start on $computerName"
        Invoke-Command -Session $psSession -ScriptBlock {
            $name = 'DNS'
            Get-Service -Name $name |
            Where-Object { $PSItem.Status -ne 'Running' } |
            Start-Service
        }

        Invoke-Command -Session $psSession -ScriptBlock {
            Set-DnsServerForwarder -IPAddress '8.8.8.8', '8.8.4.4'
        }
    }
}
else {
    Write-Error 'Additional domain controllers not deployed, skipping task.'
}

#endregion Task 1: Configure forwarders on VN1-SRV5 and VN2-SRV1

#region Task 2: Configure DNS client settings

Write-Host '        Task 2: Configure DNS client settings'

if ($dcDeploymentSuccess) {
    $computerName = 'VN1-SRV5.ad.adatum.com'
    $desiredServerAddresses = '10.1.2.8', '127.0.0.1'
    $psSession = Request-PSSession `
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
    Write-Error 'Additional domain controllers not deployed, skipping task.'
}

#endregion Task 2: Configure DNS client settings

#region Task 3: Configure forwarders on VN2-SRV2

Write-Host '        Task 3: Configure forwarders on VN2-SRV2'

if ($dcDeploymentSuccess) {
    $psSession = Request-PSSession `
        -ComputerName $computerName -Credential $adminCredential.contoso

    Write-Verbose `
        "Waiting for DNS service to start on $computerName"

    Invoke-Command -Session $psSession -ScriptBlock {
        $name = 'DNS'
        if ((Get-Service -Name $name) -ne 'Running') {
            Start-Service -Name $name
        }
    }

    Invoke-Command -Session $psSession -ScriptBlock {
        Set-DnsServerForwarder -IPAddress '8.8.8.8', '8.8.4.4'
    }
}

#endregion Task 3: Configure forwarders on VN2-SRV2

#endregion Exercise 4: Optimize DNS

#region Exercise 5: Transfer flexible single master operation roles

Write-Host '    Exercise 5: Transfer flexible single master operation roles'

#region Task 1: Transfer the domain-wide flexible single master operation roles

Write-Host '        Task 1: Transfer the domain-wide flexible single master operation roles'

if ($dcDeploymentSuccess) {
    $operationMasterRoles = 'RIDMaster', 'InfrastructureMaster', 'PDCEmulator'
    $domain = 'ad.adatum.com'

    # FQDN of the server to receive the FSMO roles
    $identity = 'vn1-srv5'

    $computerName = 'VN1-SRV5.ad.adatum.com'
    $psSession = Request-PSSession `
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
    Write-Error 'Additional domain controllers not deployed, skipping task.'
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
    $psSession = Request-PSSession `
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
    Write-Error 'Additional domain controllers not deployed, skipping task.'
}

#endregion Task 2: Transfer the forest-wide flexible single master operation roles
  
#endregion Exercise 5: Transfer flexible single master operation roles


Get-PSSession | Remove-PSSession

# Wait for DNS server tools installation job to complete
Write-Verbose 'Waiting for DNS server tools installation job to complete'
$jobDnsServerTools | Wait-Job
$jobDnsServerToolsResult = Receive-Job -Job $jobDnsServerTools
if ($jobDnsServerToolsResult) {
    Write-Host $jobDnsServerToolsResult.Message
}

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