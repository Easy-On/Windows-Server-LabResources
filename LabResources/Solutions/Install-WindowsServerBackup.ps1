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

#region Practice: Manage roles using PowerShell

Write-Host 'Practice: Manage roles using PowerShell'

$name = 'Windows-Server-Backup'

@('VN1-SRV1', 'VN1-SRV2', 'VN1-SRV4', 'VN1-SRV5', 'VN1-SRV10') | ForEach-Object {
    $computerName = $PSItem
    $null = Get-WindowsFeature -Name $name -ComputerName $computerName |
    Where-Object { $PSItem.InstallState -ne 'Installed' } |
    Install-WindowsFeature -ComputerName $computerName -Restart
}

#endregion Practice: Manage roles using PowerShell