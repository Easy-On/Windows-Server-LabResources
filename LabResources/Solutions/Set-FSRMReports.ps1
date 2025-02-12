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

#region Practice: Configure storage report options

Write-Host 'Practice: Configure storage report options'

$computerName = 'VN1-SRV10'
$reportLocation = 'd:\Shares\IT\StorageReports'
$reportLocationIncident = "$reportLocation\Incident"
$reportLocationScheduled = "$reportLocation\Scheduled"
$reportLocationOnDemand = "$reportLocation\Interactive"

$reportLocationIncident, $reportLocationScheduled, $reportLocationOnDemand |
ForEach-Object {
    $remotePath = $PSItem -replace '^(.):\\', "\\$computername\`$1$\"
    if (-not (Test-Path $remotePath)) {
        $null = New-Item -Type Directory -Path $remotePath
    }
}

$session = New-PSSession -ComputerName $computerName

Invoke-Command -Session $session -ScriptBlock {
    Set-FsrmSetting `
        -ReportLargeFileMinimum 1MB `
        -ReportLocationIncident $using:reportLocationIncident `
        -ReportLocationScheduled $using:reportLocationScheduled `
        -ReportLocationOnDemand $using:reportLocationOnDemand
}

Remove-PSSession $session

#endregion Practice: Configure storage report options
