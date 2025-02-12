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

#region Practice: Install Roles using Server Manager

Write-Host 'Practice: Install Roles using Server Manager'

$computerName = 'VN1-SRV10'
$windowsFeature = Get-WindowsFeature -ComputerName VN1-SRV10 -Name FS-FileServer
if ($windowsFeature.InstallState -ne 'Installed') {
    $null = $windowsFeature | 
        Install-WindowsFeature -ComputerName $computerName -Restart

    $seconds = 10
    while (
        $null -eq 
        (Test-WSMan -ComputerName $computerName -ErrorAction SilentlyContinue)
    ) {
        Write-Warning @"
Waiting for $computerName to become available for $seconds seconds.
"@
        Start-Sleep -Seconds 10
    } 
}


#endregion Practice: Install Roles using Server Manager
