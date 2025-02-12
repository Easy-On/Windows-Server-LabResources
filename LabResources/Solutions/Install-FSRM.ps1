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

#region Practice: Install File Server Resource Manager and Tools

Write-Host 'Practice: Install File Server Resource Manager and Tools'

$computerName = 'VN1-SRV10'

$windowsFeature = Get-WindowsFeature `
    -Name FS-Resource-Manager `
    -ComputerName $computerName

if ($windowsFeature.InstallState -ne 'Installed') {
    $null = `
        $windowsFeature | 
        Install-WindowsFeature `
            -ComputerName $computerName `
            -IncludeManagementTools


    <# 
        Despite what Install-WindowsFeature thinks, after installing FSRM,
        a restart is required for all PowerShell cmdlets to work correctly.
    #>
    Restart-Computer -ComputerName $computerName

    $computerName = 'VN1-SRV10'
    # $seconds = 10
    do {
        Write-Warning @"
Waiting for $computerName to become available.
"@
        # Start-Sleep -Seconds 10
    } until (
        Test-WSMan -ComputerName $computerName -ErrorAction SilentlyContinue
    )
}

<#
    '@FirewallAPI.dll,-53631' is the group 
    Remote File Server Server Resource Manager Management
#>

$cimSession = New-CimSession $computerName

Set-NetFirewallRule `
    -Group '@FirewallAPI.dll,-53631' `
    -Enabled True `
    -Profile Domain `
    -CimSession $cimSession

Remove-CimSession $cimSession

#endregion Practice: Install File Server Resource Manager and Tools