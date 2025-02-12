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

#region Practice: Install Group Policy Management

Write-Host 'Practice: Install Group Policy Management'

& $PSScriptRoot\Install-RSATModule.ps1 -Name GPMC -ComputerName 'CL1'


#endregion Practice: Install File Server Resource Manager and Tools