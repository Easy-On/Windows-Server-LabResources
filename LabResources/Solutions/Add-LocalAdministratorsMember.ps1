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

#region Practice: Manage local users

Write-Host 'Practice: Manage local users'

$computername = @('cl1', 'cl2', 'VN1-SRV5')
Invoke-Command -ComputerName $computername -ScriptBlock {
    Add-LocalGroupMember -Group Administrators -Member LocalAdmin
}

#endregion Practice: Manage local users