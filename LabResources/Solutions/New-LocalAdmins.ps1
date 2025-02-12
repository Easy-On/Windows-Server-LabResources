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

Write-Verbose 'Practice: Manage local users'

$computername = @('cl1', 'cl2', 'VN1-SRV5')
$password = ConvertTo-SecureString -String 'Pa$($MyInvocation.MyCommand)w0rd' -AsPlainText -Force
Invoke-Command -ComputerName $computername -ScriptBlock {
    New-LocalUser `
        -Name 'LocalAdmin' `
        -FullName 'Local Administrator' `
        -Description 'Account for administering the computer' `
        -Password $using:password
}

#endregion Practice: Manage local users
