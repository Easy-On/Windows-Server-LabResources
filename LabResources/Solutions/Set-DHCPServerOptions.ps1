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

#region Practice: Configure DHCP server options

Write-Host 'Practice: Configure DHCP server options'

Invoke-Command -ComputerName 'VN1-SRV6', 'VN1-SRV7', 'VN2-SRV2' {
    Set-DhcpServerv4OptionValue -DnsServer 10.1.1.8 -DnsDomain ad.adatum.com
}
#endregion Practice: Configure DHCP server options