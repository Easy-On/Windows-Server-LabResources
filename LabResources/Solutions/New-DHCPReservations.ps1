[CmdletBinding()]
param (
    [Parameter()]
    [switch]
    $SkipDependencies
)

#region Prerequisites

if (-not $SkipDependencies) {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-Dependencies.ps1') `
        -Script $MyInvocation.MyCommand `
        -Confirm:$false
}

#endregion Prerequisites

#region Practice: Add DHCP reservations

Write-Host 'Practice: Add DHCP reservations'

Write-Verbose @'
For all computers starting with VN1-SRV*, get the MAC addresses and IP addresses 
of all net adapters on VNet1.
'@

$computerName = Invoke-Command -ComputerName 'VN1-SRV1' -ScriptBlock {
    (Get-ADComputer -Filter 'Name -like "VN1-SRV*"').DNSHostName
}
    
$vNet1ServerAddresses = Invoke-Command `
    -ComputerName $computerName `
    -ScriptBlock { 
        Get-NetAdapter | ForEach-Object { 
            # Save macAddress and interfaceAlias for later use
            $macAddress = $PSItem.MacAddress
            $interfaceAlias = $PSItem.InterfaceAlias
            

            Get-NetIPAddress -InterfaceIndex $PSItem.InterfaceIndex |
            Where-Object { $PSItem.IPAddress -like '10.1.1.*' } | 
            Select-Object `
                @{ 
                    Name = 'InterfaceAlias'
                    Expression = { $interfaceAlias } 
                }, `
                @{
                    Name = 'ClientId'
                    Expression = { $macAddress } 
                }, `
                IPAddress
        } 
    } |
    Select-Object `
        @{ 
            Name = 'Name'
            Expression = { $PSItem.PSComputerName } 
        },
        InterfaceAlias,
        ClientId,
        IPAddress

Write-Verbose 'Create the reservations for all computers on VNet1.'

$pSSession = New-PSSession -ComputerName 'VN1-SRV6'

Write-Verbose 'Remove existing reservations.'

Invoke-Command -Session $pSSession -ScriptBlock {
    $scopeId = '10.1.1.0'
    $vNet1ServerAddresses = $using:vNet1ServerAddresses
    Get-DhcpServerv4Reservation -ScopeId $scopeId |
    Where-Object { $PSItem.ClientId -in $vNet1ServerAddresses.ClientId } |
    Remove-DhcpServerv4Reservation
}

Invoke-Command -Session $pSSession -ScriptBlock {
    Get-DhcpServerv4Reservation -ScopeId $scopeId |
    Where-Object { $PSItem.IPAddress -in $vNet1ServerAddresses.IPAddress } |
    Remove-DhcpServerv4Reservation
}

Write-Verbose 'Add reservations.'
Invoke-Command -Session $pSSession -ScriptBlock {
    $vNet1ServerAddresses |
    Add-DhcpServerv4Reservation -ScopeId $scopeId    
}

Remove-PSSession -Session $pSSession

#endregion Practice: Add DHCP reservations