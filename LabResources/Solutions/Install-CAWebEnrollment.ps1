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

#region Practice: Install Roles using Windows Admin Center

Write-Host 'Practice: Install Roles using Windows Admin Center'

$computerName = 'VN1-SRV2'
$name = 'ADCS-Enroll-Web-Svc' `

$windowsFeature = Get-WindowsFeature -Name $name -ComputerName $computerName
if ($windowsFeature.InstallState -ne 'Installed') {
    $null = Install-WindowsFeature `
        -Name $name `
        -Restart `
        -ComputerName $computerName
}



#endregion Practice: Install Roles using Windows Admin Center