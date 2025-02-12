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

#region Practice: Configure a classification schedule

$session = New-PSSession -ComputerName VN1-SRV10

Write-Host 'Practice: Configure a classification schedule'


$schedule = Invoke-Command -Session $session -ScriptBlock {
    New-FsrmScheduledTask -Time 18:00:00 -Weekly Friday -RunDuration 60
}

Invoke-Command -Session $session -ScriptBlock {
    Set-FsrmClassification -Schedule $using:schedule -Continuous 
}   

Remove-PSSession $session

#endregion #region Practice: Configure a classification schedule
