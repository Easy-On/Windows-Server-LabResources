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

#region Prerequisites

#region Lab: Manage file sharing

Write-Host 'Lab: Manage file sharing'

$computerName = 'VN1-SRV10'
$pSSession = New-PSSession $computerName
$cimSession = New-CimSession $computerName


#region Exercise 1: Manage file shares and permissions

Write-Host '    Exercise 1: Manage file shares and permissions'

$shares = @(
    @{
        Name = 'Finance'
        Modify = 'Managers'
        CachingMode = 'None'
    }
    @{
        Name = 'IT'
        Read = 'Managers'
        Modify = 'IT'
        CachingMode = 'Manual'
    }
    @{
        Name = 'Marketing'
        Read = 'Sales', 'Managers'
        Modify = 'Marketing'
        CachingMode = 'Documents'

    }
)


#region Task 1: Create an organization unit

Write-Host '        Task 1: Create an organization unit'

$path = 'dc=ad, dc=adatum, dc=com'
$name = 'Entitling groups'

try {
    $null = Get-ADOrganizationalUnit -Identity "ou=$name, $path"
}
catch {
    $null = New-ADOrganizationalUnit -Path $path -Name $name
}

#endregion

#region Task 2: Create domain local groups and add members

Write-Host '        Task 2: Create domain local groups and add members'

$groupPath = "OU=$name, $path"

foreach ($share in $shares) {
    $shareName = $share.Name

    'Read', 'Modify' | ForEach-Object {
        $name = "$shareName $PSItem"

        try {
            $adGroup = Get-AdGroup -Identity "cn=$name, $groupPath"
        }
        catch {
            $adGroup = New-ADGroup `
                -Name $name `
                -Path $groupPath `
                -GroupScope DomainLocal `
                -PassThru
        }

        $members = $aDGroup | Get-ADGroupMember

        foreach ($member in $share[$PSItem]) {
            if ($member -notin $members.Name) {
                $aDGroup | Add-ADGroupMember -Members $member
            }
        }

    }
}

#endregion Task 2: Create domain local groups and add members


#region Task 3: Create shares and configure file system and share permissions

Write-Host '        Task 3: Create shares and configure file system and share permissions'

$sharesPath = 'D:\Shares'

foreach ($share in $shares) {

    $shareName = $share.Name
    $path = "$sharesPath\$shareName"
    $remotePath = $path -replace '^(.):\\', "\\$computername\`$1$\"

    #region Create folder


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

    # Typical flags for access rules

    $inheritanceFlags = 'ContainerInherit, ObjectInherit'
    $propagationFlags = 'None'
    $type = 'Allow'
    
    # Create the Read rule

    $accessRule = New-Object `
        -TypeName `
            System.Security.AccessControl.FileSystemAccessRule `
        -ArgumentList `
            "ad\$shareName Read", `
            'ReadAndExecute', `
            $inheritanceFlags, `
            $propagationFlags, `
            $type
    
    $null = $acl.AddAccessRule($accessRule)

    # Create the Modify rule

    $accessRule = New-Object `
        -TypeName `
            System.Security.AccessControl.FileSystemAccessRule `
        -ArgumentList `
            "ad\$shareName Modify", `
            "Modify", `
            $inheritanceFlags, `
            $propagationFlags, `
            $type
    
    $acl.AddAccessRule($accessRule)

    #endregion Grant the permissions to the groups

    $acl | Set-Acl -Path $remotePath

    #endregion Set permissions

    # Create the share

    if ($null -eq (
        Get-SmbShare `
            -Name $shareName `
            -CimSession $cimSession `
            -ErrorAction SilentlyContinue
    )) {
        $null = New-SmbShare `
            -Name $shareName `
            -Path $path `
            -FullAccess 'BUILTIN\Administrators' `
            -ReadAccess "ad\$shareName Read" `
            -ChangeAccess "ad\$shareName Modify" `
            -FolderEnumerationMode AccessBased `
            -EncryptData $false `
            -CachingMode $share.CachingMode `
            -CimSession $cimSession
    }        

    #endregion

}

#region Task 4: Copy the contents of the folders with the respective names

Write-Host '        Task 4: Copy the contents of the folders with the respective names'

foreach ($share in $shares) {
    $shareName = $share.Name
    $path = "C:\LabResources\Sample Documents\$shareName\*" `
        -replace '^(.):\\', "\\$computername\`$1$\"
    $destination = ("$sharesPath\$shareName") `
        -replace '^(.):\\', "\\$computername\`$1$\"

    Copy-Item -Path $path -Destination $destination -Recurse -Force
}

#endregion

#endregion Lab: Manage file sharing

#region Exercise 2: Explore offline files

Write-Host '    Exercise 2: Explore offline files'

#region Task 1: Configure shares for offline access

Write-Host '        Task 1: Configure shares for offline access'

$shareCachingMode = @(
    @{ Name = 'Finance'; CachingMode = 'None' }
    @{ Name = 'IT'; CachingMode = 'Manual' }
    @{ Name = 'Marketing'; CachingMode = 'Documents' }
)
    
    
$shareCachingMode | ForEach-Object {
    Set-SmbShare `
        -Name $PSItem.Name `
        -CachingMode $PSItem.CachingMode `
        -Force `
        -CimSession $cimSession
}

#endregion Task 1: Configure shares for offline access

#endregion Exercise 2: Explore offline files

#region Exercise 3: Configure Volume Shadow Copies

Write-Host '    Exercise 3: Configure Volume Shadow Copies'

#region Task 1: Configure Volume Shadow Copies

Write-Host '        Task 1: Configure Volume Shadow Copies'

<#
Script from 
https://fixyacloud.wordpress.com/2020/01/26/how-to-enable-volume-shadow-copy-using-powershell/

Edited by Roman Korecky
#>

$volumeName = 'D:\'
$wmiObject = `
    Get-WmiObject `
        -Class Win32_Volume `
        -Namespace root/cimv2 `
        -ComputerName $computerName | 
    Where-Object { $PSItem.Name -eq $volumeName }

$deviceID = $wmiObject.DeviceID.ToUpper().Replace(
    '\\?\VOLUME', ''
).Replace('\', '')

$taskName = "ShadowCopyVolume" + $deviceID

if (
    $null -eq 
    (
        Get-ScheduledTask `
            -TaskName $taskName `
            -CimSession $cimSession `
            -ErrorAction SilentlyContinue
    )
) {

    $for = '\\?\Volume' + $deviceID + '\'
    $execute = 'C:\Windows\system32\vssadmin.exe'
    $argument = "Create Shadow /AutoRetry=15 /For=$for"
    $workingDirectory = '%systemroot%\system32'

    $action = New-ScheduledTaskAction `
        -Execute $execute `
        -WorkingDirectory $workingDirectory `
        -Argument $argument `
        -CimSession $cimSession

    $trigger = @()
    $trigger += `
        New-ScheduledTaskTrigger -Daily -At 07:00 -CimSession $cimSession
    $trigger += `
        New-ScheduledTaskTrigger -Daily -At 12:00 -CimSession $cimSession
    $settings = New-ScheduledTaskSettingsSet `
        -Compatibility V1 `
        -DontStopOnIdleEnd `
        -ExecutionTimeLimit (New-TimeSpan -Days 3) `
        -Priority 5 `
        -CimSession $cimSession

    $inputObject = New-ScheduledTask `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -CimSession $cimSession
    $null = Register-ScheduledTask `
        -TaskName $taskName `
        -InputObject $inputObject `
        -User 'NT AUTHORITY\SYSTEM' `
        -CimSession $cimSession
}

#endregion Task 1: Configure Volume Shadow Copies

#endregion Exercise 3: Configure Volume Shadow Copies

Remove-PSSession $pSSession
Remove-CimSession $cimSession

#endregion Lab: Manage file sharing