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

#region Lab: Manage servers remotely using Microsoft Management Console

Write-Host 'Lab: Manage servers remotely using Microsoft Management Console'

#region Exercise 2: Configure Windows Defender Firewall rules for remote administration

Write-Host '    Exercise 2: Configure Windows Defender Firewall rules for remote administration'

#region Task 1: Enable firewall rules to allow for remote event log and volume management

Write-Host '        Task 1: Enable firewall rules to allow for remote event log and volume management'

$cimSession = New-CimSession -ComputerName VN1-SRV10, CL2

# Set-NetFirewallRule `
#     -Name ComPlusRemoteAdministration-DCOM-In `
#     -Enabled True `
#     -Profile Domain `
#     -CimSession $cimSession

# Remote Event Log Management
Get-NetFirewallRule -Group '@FirewallAPI.dll,-29252' -CimSession $cimSession | 
Set-NetFirewallRule -Enabled True -Profile Domain
# Remote Volume Management
Get-NetFirewallRule -Group '@FirewallAPI.dll,-34501' -CimSession $cimSession | 
Set-NetFirewallRule -Enabled True -Profile Domain

Remove-CimSession $cimSession

#endregion Task 1: Enable firewall rules to allow for remote event log and volume management


#region Task 2: Enable firewall rules to allow remote volume management

Write-Host '        Task 2: Enable firewall rules to allow remote volume management'

$cimSession = New-CimSession CL1

Get-NetFirewallRule -Group '@FirewallAPI.dll,-34501' -CimSession $cimSession |
Where-Object { $PSItem.Profile -eq 'Domain' } |
Set-NetFirewallRule -Enabled True -CimSession $cimSession

Remove-CimSession $cimSession

#endregion Task 2: Enable firewall rules to allow remote volume management

#endregion Exercise 2: Configure Windows Defender Firewall rules for remote administration

#endregion Lab: Manage servers remotely using Microsoft Management Console
