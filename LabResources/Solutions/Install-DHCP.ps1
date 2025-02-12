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

#region Practice: Install the DHCP server role

Write-Host 'Practice: Install the DHCP server role'

$computerName = 'VN1-SRV6', 'VN1-SRV7', 'VN2-SRV2'

Write-Verbose "Install DHCP role on $computerName"

Invoke-Command -ComputerName $computerName -ScriptBlock {
    $windowsFeature = Get-WindowsFeature -Name 'DHCP'
    if ($windowsFeature.InstallState -ne 'Installed') {
        $null = $windowsFeature |
            Install-WindowsFeature -IncludeManagementTools -Restart
    }
}

$computerName | ForEach-Object {
    do {
        Write-Warning "Waiting for $PSItem to become available"
    } until (
        Test-WSMan -ComputerName $PSItem -ErrorAction SilentlyContinue
    )    
    
    Write-Verbose "Add security groups to DHCP server $PSItem"

    Invoke-Command -ComputerName $PSItem -ScriptBlock {
        Add-DhcpServerSecurityGroup
    }
    Write-Verbose @"
Notify Server Manager on $PSItem that post-install DHCP configuration
is complete.
"@

    Invoke-Command -ComputerName $computerName -ScriptBlock {
        Set-ItemProperty `
            -Path HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12 `
            -Name ConfigurationState `
            -Value 2
    }
}

#endregion Practice: Install the DHCP server role