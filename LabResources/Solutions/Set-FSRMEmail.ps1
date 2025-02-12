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

#region Practice: Configure e-mail notifications in FSRM

Write-Host 'Practice: Configure e-mail notifications in FSRM'

Invoke-Command -ComputerName VN1-SRV10 -ScriptBlock {
    Set-FsrmSetting `
        -SmtpServer mail.adatum.com `
        -FromEmailAddress 'fsrm@adatum.com' `
        -AdminEmailAddress 'fsm@adatum.com'
}