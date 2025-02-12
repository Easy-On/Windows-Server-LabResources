# [CmdletBinding()]
# param (
#     [Parameter()]
#     [switch]
#     $SkipDependencies
# )

# if (-not $SkipDependencies) {
#     . (Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-Dependencies.ps1') `
#         -Script $MyInvocation.MyCommand `
#         -Confirm:$false
# }

Write-Host 'Create a Users share with some folders'

$computerName = 'VN1-SRV10'

#region Create share


$sharesPath = 'D:\Shares'
$shareName = 'Users'
$path = "$sharesPath\$shareName"

#region Create folder

$remotePath = $path -replace '^(.):\\', "\\$computername\`$1$\"

if (-not (Test-Path($remotePath))) {
    $null = New-Item $remotePath -ItemType Directory
}
#endregion Create folder

#region Set permissions

$acl = Get-Acl $remotePath

# Disable Inheritance

$acl.SetAccessRuleProtection($true, $true)

<# 
    Remove all permission entries except for those for principals 
    Administrators, SYSTEM, and CREATOR OWNER
#>

$acl.Access | 
Where-Object { 
    $PSItem.IdentityReference -notin @(
        'BUILTIN\Administrators', 
        'NT AUTHORITY\SYSTEM', 
        'CREATOR OWNER'
    ) 
} | 
ForEach-Object { $null = $acl.RemoveAccessRule($PSItem) }

#region Grant the permissions to the groups

$inheritanceFlags = 'None'
$propagationFlags = 'None'
$type = 'Allow'

# Create the create folders rule

$accessRule = New-Object `
    -TypeName `
        System.Security.AccessControl.FileSystemAccessRule `
    -ArgumentList `
        'BUILTIN\Users', `
        'AppendData, ReadAndExecute, Synchronize', `
        $inheritanceFlags, `
        $propagationFlags, `
        $type

$acl.AddAccessRule($accessRule)

#endregion Grant the permissions to the groups

$acl | Set-Acl -Path $remotePath

#endregion Set permissions

# Create the share

$cimSession = New-CimSession -ComputerName $computerName

if ($null -eq (
    Get-SmbShare `
        -Name $shareName `
        -CimSession $cimSession `
        -ErrorAction SilentlyContinue
)) {
    $null = New-SmbShare `
        -Name $shareName `
        -Path $path `
        -FullAccess 'BUILTIN\Users' `
        -FolderEnumerationMode AccessBased `
        -EncryptData $true `
        -CimSession $cimSession
}

Remove-CimSession $cimSession

#endregion

# region Simulate user folders

$sharePath = Join-Path -Path "\\$computerName" -ChildPath $shareName

for ($i = 1; $i -lt 11; $i++) {
    $path = Join-Path -Path $sharePath -ChildPath "User$i"
    if (-not (Test-Path($path))) {
        $null = New-Item $path -ItemType Directory
    }
}

# endregion