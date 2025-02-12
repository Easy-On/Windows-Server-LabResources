[CmdletBinding()]
param (
    # Name of VM to move
    [Parameter(Mandatory)]
    [string]
    $VMName,
    
    # Original name of switch the VM is currently connected to
    [Parameter(Mandatory)]
    [string]
    $SwitchName,
    
    # Name of new switch the VM should be connected to
    [Parameter(Mandatory)]
    [string]
    $NewSwitchName,
    
    # Index of octet indicating the subnet
    [Parameter()]
    [ValidateRange(0, 2)]
    [byte]
    $SubnetOctet = 2,

    # New value for octet indicating the subnet
    [Parameter(Mandatory)]
    [byte]
    $SubnetValue,

    # Credentials of account with local administrator rights in VM
    [Parameter()]
    [pscredential]
    $Credential = (
        Get-Credential `
            -Message `
                "Enter the password of the local Administrator account of $(
                    $VMName
                )" `
            -UserName 'Administrator'
    )
)

function Set-Octet {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $IPAddress,

        # Index of octect to replace
        [Parameter(Mandatory)]
        [ValidateRange(0, 2)]
        [byte]
        $Octet,
        
        # New value for octet
        [Parameter(Mandatory)]
        [byte]
        $Value
    )

    $iPAddressSplit = $iPAddress -split '\.'
    $iPAddressSplit[$Octet] = $Value
    return $iPAddressSplit -join '.'
}

#region Connect to switch

Write-Verbose "Retrieving the network adapter of $VMName connected to virtual switch $SwitchName"
$vMNetworkAdapter = Get-VMNetworkAdapter -VMName $VMName | 
    Where-Object { $PSItem.SwitchName -eq $SwitchName }

if (-not $vMNetworkAdapter) {
    Write-Warning "No network adapter connected to $SwitchName found. Are you using the correct parameters or is $VMName already connected to $($NewSwitchName)?"
    exit
}


Write-Verbose "Connecting network adapter $($vMNetworkAdapter.MacAddress) $VMName to switch $NewSwitchName"
$vMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $NewSwitchName

#endregion Connect to switch

#region Set IP address

Write-Verbose "Opening a PowerShell session to $VMName"
$pSSession = New-PSSession -VMName $VMName -Credential $Credential

Write-Verbose "Retrieving the network adapter $($vMNetworkAdapter.MacAddress)"
$netAdapter = Invoke-Command -Session $pSSession -ScriptBlock { 
    Get-NetAdapter | 
    Where-Object { 
        ($PSItem.MacAddress -replace '-', '') `
            -eq $using:vMNetworkAdapter.MacAddress 
    } 
}

$interfaceIndex = $netAdapter.InterfaceIndex
Write-Verbose "The interface index of network adapter $($netAdapter.MacAddress) is $interfaceIndex"

# Get current IP configuration of net adapter

Write-Verbose "Retrieving the IP configuration from interface $interfaceIndex"
$netIPConfiguration = Invoke-Command -Session $pSSession -ScriptBlock {
    Get-NetIPConfiguration -InterfaceIndex $using:interfaceIndex
}

# Remove current IP address and default gateway

Write-Verbose "Removing IP addresses and routes from interface $interfaceIndex"
Invoke-Command -Session $pSSession -ScriptBlock {
    Remove-NetIPAddress -InterfaceIndex $using:interfaceIndex -Confirm:$false
    
    Get-NetRoute -InterfaceIndex $using:interfaceIndex | 
    Remove-NetRoute -Confirm:$false
}

# Set new IP configuration

$defaultGateway = $netIPConfiguration.IPv4DefaultGateway | 
    Select-Object -ExpandProperty NextHop -First 1
Write-Verbose "The old default gateway was $defaultGateway"

$defaultGateway = Set-Octet `
    -IPAddress $defaultGateway -Octet $SubnetOctet -Value $SubnetValue
Write-Verbose "The new default gateway will be $defaultGateway"

foreach ($iPv4Address in $netIPConfiguration.IPv4Address) {
    $iPAddress = $iPv4Address.IPAddress
    Write-Verbose "The old IP address was $iPAddress"
    $iPAddress = Set-Octet `
        -IPAddress $iPAddress -Octet $SubnetOctet -Value $SubnetValue
    Write-Verbose "The new IP address will be $iPAddress"
    $prefixLength = $iPv4Address.PrefixLength        

    Write-Verbose "Adding the IP address $iPAddress/$prefixLength with default gateway $defaultGateway to interface $interfaceIndex"
    Invoke-Command -Session $pSSession -ScriptBlock {
        New-NetIPAddress `
            -InterfaceIndex $using:interfaceIndex `
            -IPAddress $using:iPAddress `
            -DefaultGateway $using:defaultGateway `
            -PrefixLength $using:prefixLength 
    }
}

#endregion Set IP address

Write-Verbose 'Removing the PowerShell session'
Remove-PSSession $pSSession