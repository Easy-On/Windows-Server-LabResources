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

#region Practice: Authorize DHCP server and activate scope

Write-Host 'Practice: Authorize DHCP server and activate scope'

& $PSScriptRoot\Install-RSATModule.ps1 -Name DHCP
$computerName = 'VN1-SRV6'
$scopeId = '10.1.1.0'

Write-Verbose "Authorize DHCP server $computerName."
Add-DhcpServerInDC -DnsName $computerName

Write-Verbose "Activate scope $scopeId."
Set-DhcpServerv4Scope `
    -ComputerName $computerName -ScopeId $scopeId -State Active    

#endregion Practice: Authorize DHCP server and activate scope