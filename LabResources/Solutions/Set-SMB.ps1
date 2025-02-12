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

#region Practice: Harden SMB

Write-Host 'Practice: Harden SMB'

$computerName = 'VN1-SRV10'
$cimSession = New-CimSession -ComputerName $computerName

Set-SmbServerConfiguration `
    -EnableSMB1Protocol $false `
    -Force `
    -CimSession $cimSession
Set-SmbShare -Name IT -EncryptData $true -Force -CimSession $cimSession

Remove-CimSession $cimSession

$null = Remove-WindowsFeature -Name FS-SMB1 -ComputerName $computerName

$computerName = 'VN1-SRV5'
$cimSession = New-CimSession -ComputerName $computerName
Set-SmbServerConfiguration -EncryptData $true -Force -CimSession $cimSession
Remove-CimSession $cimSession

#endregion Practice: Harden SMB