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

$gatewayEndPoint = 'admincenter.ad.adatum.com'

#endregion Prerequisites

#region Lab: Explore Windows Admin Center

Write-Host 'Lab: Explore Windows Admin Center/Practice: Configure Windows Admin Center'

$computerName = 'CL1'

if ($computerName -ne $env:COMPUTERNAME) {
    Write-Warning @"
This script can only run on $computerName.
Please run $($MyInvocation.MyCommand) on $computerName.
"@
    return
}

#region Exercise 1: Connect

Write-Host '    Exercise 1: Connect'

#region Task 3: Add https://admincenter.ad.adatum.com to the Intranet zone

Write-Host `
    '        Task 3: Add https://admincenter.ad.adatum.com to the Intranet zone'

$path = `
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\admincenter.ad.adatum.com'
$null = New-Item -Path $path -Force
$null = New-ItemProperty `
    -Path $path -Name 'https' -Value 1 -PropertyType DWORD -Force

#endregion Task 3: Add https://admincenter.ad.adatum.com to the Intranet zone

#endregion Exercise 1: Connect

#region Exercise 2: Manage connections

Write-Host '    Exercise 2: Manage connections'

#region Task: In Windows Admin Center, add connections

Write-Host '        Task: In Windows Admin Center, add connections'

Write-Verbose 'Create a CSV file with all server computers.'
$path = '~\Documents\computers.csv'
Get-ADComputer -Filter { Name -like 'VN*-*' -or Name -like 'PM-*' } |
Select-Object `
    @{ name = 'name'; expression = { $PSItem.DNSHostName } }, `
    @{
        name = 'type'
        expression = { 'msft.sme.connection-type.server' }
    }, `
    @{ name = 'tags'; expression = {} }, `
    @{ name = 'groupId'; expression = { } } |
Export-Csv -Path $path -NoTypeInformation -Force

Write-Verbose 'Append all client computers to the CSV file.'
Get-ADComputer -Filter { Name -like 'CL*' } |
Select-Object `
    @{ name = 'name'; expression = { $PSItem.DNSHostName } }, `
    @{ 
        name = 'type'
        expression = { 'msft.sme.connection-type.windows-client' }
    }, `
    @{ name = 'tags'; expression = {} }, `
    @{ name = 'groupId'; expression = { } } |
Export-Csv -Path $path -Append

$computerName = 'VN1-SRV4'
Write-Verbose "Create a remote PowerShell session to $computerName"
$pSSession = New-PSSession -ComputerName $computerName

Write-Verbose `
    'Copy the Windows Admin Center Connection Tools module to the client.'
$destination = '~\Documents\WindowsPowerShell\Modules\'
if (-not (Test-Path -Path $destination)) {
    New-Item -Path $destination -ItemType Directory
}
Copy-Item `
    -FromSession $pSSession `
    -Path `
        "$env:ProgramFiles\Windows Admin Center\PowerShell\Modules\*\" `
    -Destination $destination `
    -Container `
    -Recurse `
    -Force

Write-Verbose 'Remove the remote PowerShell session'
Remove-PSSession $pSSession
    
Write-Verbose 'Import connections'
Import-Connection -GatewayEndpoint $gatewayEndPoint -fileName $path

#endregion Task: In Windows Admin Center, add connections

#endregion Exercise 2: Manage connections

#region Exercise 3: Install extensions

Write-Host '    Exercise 3: Install extensions'

#region Task: Install the Active Directory extension

Write-Host '        Task: Install the Active Directory extension'

Write-Warning @'
Extension cannot be installed by script. Please install the Active Directory extension manually.
'@

#endregion Task: Install the Active Directory extension
#endregion Exercise 3: Install extensions
