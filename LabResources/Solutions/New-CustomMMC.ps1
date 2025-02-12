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

#region Practice: Create a custom Microsoft Management Console

Write-Host 'Practice: Create a custom Microsoft Management Console'

Invoke-Command -ComputerName CL1 -ScriptBlock {
    $path = Join-Path `
        -Path $using:PSScriptRoot `
        -ChildPath 'Basic Administration.msc'
    Copy-Item -Path $path -Destination C:\Users\Public\Desktop
}

#endregion Practice: Create a custom Microsoft Management Console