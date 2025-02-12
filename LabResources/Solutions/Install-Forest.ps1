[CmdletBinding()]
param (
    [Parameter()]
    [switch]
    $SkipDependencies
)

#region constants

$adminUsername = @{
    contoso = 'Administrator@ad.contoso.com'
    local = '.\Administrator'
}
$defaultPassword = 'Pa$$w0rd'
$defaultSecurePassword = `
    ConvertTo-SecureString -String $defaultPassword -AsPlainText -Force
$adminCredential = @{
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
        '10.1.2.16, VN2-SRV2.ad.adatum.com' `
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

#region Exercise 6: Deploy a new forest

Write-Host '    Exercise 6: Deploy a new forest'

#region Task 1: Install Active Directory Domain Services on VN2-SRV2

Write-Host `
    '        Task 1: Install Active Directory Domain Services on VN2-SRV2'

$computerName = '10.1.2.16' # VN2-SRV2
$psSession = Connect-PSSession `
    -ComputerName $computerName -Credential $adminCredential.local

$name = 'AD-Domain-Services'
$windowsFeature = Invoke-Command -Session $psSession -ScriptBlock {
    Get-WindowsFeature -Name $using:name
}

$computerName = `
    ($windowsFeature | Where-Object { -not $PSItem.Installed }).PSComputerName

if ($computerName) {
    Write-Verbose "Install the windows feature Active Directory Domain Services on $computerName."
    $featureOperationResult = Invoke-Command -Session $psSession -ScriptBlock {
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
            -Credential $adminCredential.local `
            -Wait -For WinRM `
            -TimeOut 600 `
            -Force
    }
}

#endregion Task 1: Install Active Directory Domain Services on VN2-SRV2

#region Task 2: Configure Active Directory Domain Services as new forest

Write-Host '        Task 2: Configure Active Directory Domain Services as new forest'

$computerName = '10.1.2.16' # VN2-SRV2
$psSession = Connect-PSSession `
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

if (-not (
    Invoke-Command -Session $psSession -ScriptBlock {
         Get-WmiObject `
            -Query 'SELECT * from Win32_OperatingSystem where ProductType="2"'
    }
)) {
    $domainName = 'ad.contoso.com'
    $domainNetbiosName = 'CONTOSO'

    Write-Verbose 'Store the Directory Services Restore Mode (DSRM) password in a variable.'

    $safeModeAdministratorPassword = ConvertTo-SecureString `
        -String $defaultPassword -AsPlainText -Force

    Write-Verbose "Install a new forest with the domain name $domainName and the NetBIOS name $domainNetbiosName"
    
    $job = Invoke-Command -Session $psSession -AsJob -ScriptBlock {
        Install-ADDSForest `
            -DomainName $using:domainName `
            -DomainNetbiosName $using:domainNetbiosName `
            -SafeModeAdministratorPassword `
                $using:safeModeAdministratorPassword `
            -InstallDns `
            -Force
    }

    $null = $job | Wait-Job
    $psSession | Remove-PSSession
    Wait-WSMan `
        -ComputerName $computerName `
        -Authentication Default `
        -Credential $adminCredential.contoso `
        -Timeout 600
}

#endregion Task 2: Configure Active Directory Domain Services as new forest

#region Task 3: Change the DNS client settings

Write-Host '        Task 3: Change the DNS client settings'

if ($env:COMPUTERNAME -eq 'CL3') {
    $desiredServerAddresses = '10.1.2.16'
    $interfaceIndex = (
        Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $PSItem.IPAddress -like '10.1.2.*' }
    ).InterfaceIndex

    $dnsClientServerAddress = Get-DnsClientServerAddress `
        -InterfaceIndex $interfaceIndex -AddressFamily IPv4

    # Determine if DNS client server addresses need to be changed

    $serverAddresses = (
        $dnsClientServerAddress.ServerAddresses | 
        Where-Object { $PSItem -notin $desiredServerAddresses }
    ) -join (
        $desiredServerAddresses |
        Where-Object { $PSItem -notin $dnsClientServerAddress.ServerAddresses }
    )

    if ($serverAddresses) {
        Write-Verbose `
            "Set DNS client server addresses to $desiredServerAddresses on CL3"

        Set-DnsClientServerAddress `
            -InterfaceIndex $interfaceIndex `
            -ServerAddresses $desiredServerAddresses `
    }
}
else {
    Write-Warning 'Skipped task. Please rerun the script on CL3.'
}

#endregion Task 3: Change the DNS client settings

#region Task 4: Connect to domain

Write-Host '        Task 4: Connect to domain'

$domainJoinSuccess = $false

if ($env:COMPUTERNAME -eq 'CL3') {
    $domainName = 'ad.contoso.com'

    if ((Get-ComputerInfo).CsDomain -ne $domainName) {
        $seconds = 10
        while (
            -not (
                Resolve-DnsName `
                    -Type SRV -Name "_kerberos._tcp.dc._msdcs.$domainName"
            )
        ) {
            Write-Verbose "Waiting $seconds seconds for domain $domainName to become available."
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
else {
    Write-Warning 'Skipped task. Please rerun the script on CL3.'
}

#endregion Task 4: Connect to domain


#region Task 5: Configure forwarders

Write-Host '        Task 5: Configure forwarders'

$psSession = Connect-PSSession `
    -ComputerName $computerName -Credential $adminCredential.contoso

Write-Verbose `
    "Waiting for DNS service to start on $computerName"

Invoke-Command -Session $psSession -ScriptBlock {
    $name = 'DNS'
    if ((Get-Service -Name $name) -ne 'Running') {
        Start-Service -Name $name
    }
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


#endregion Task 5: Configure forwarders

#endregion Exercise 6: Deploy a new forest


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

