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

#region Practice: Install the Remote Server Administration DHCP Server Tools

Write-Host `
    'Practice: Install the Remote Server Administration DHCP Server Tools'

& $PSScriptRoot\Install-RSATModule.ps1 -Name DHCP -ComputerName 'CL1'

#endregion Practice: Install the Remote Server Administration DHCP Server Tools