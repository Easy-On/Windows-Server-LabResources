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

#region Practice: Enable the Active Directory Recycle Bin

Write-Host 'Practice: Enable the Active Directory Recycle Bin'

$domainFQDN = 'ad.adatum.com'
$domainDN = `
    (
        $domainFQDN -split '\.' | ForEach-Object { "DC=$PSItem" }
    ) -join ','
$identity = "CN=Recycle Bin Feature, CN=Optional Features, CN=Directory Service, CN=Windows NT, CN=Services, CN=Configuration, $domainDN"

$aDOptionalFeature = Get-ADOptionalFeature -Identity $identity

if ($aDOptionalFeature.EnabledScopes.Count -eq 0) {
    $aDOptionalFeature | Enable-ADOptionalFeature `
        -Scope ForestOrConfigurationSet `
        -Target $domainFQDN `
        -Confirm:$false

}

#endregion Practice: Enable the Active Directory Recycle Bin