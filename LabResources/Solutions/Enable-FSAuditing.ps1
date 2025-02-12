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

Write-Host 'Lab: Audit file server events'

#region Exercise 1: Audit access to a folder

Write-Host '    Exercise 1: Audit access to a folder'

#region Task 1: Install the Group Policy Management Console

$computerName = 'CL1'

Write-Host '        Task 1: Install the Group Policy Management Console'

$windowsCapability = Invoke-Command -ComputerName $computerName -ScriptBlock {
    # This array defines the tools to install.

    $names = @('RSAT.GroupPolicy.Management.Tools*')
    $names | ForEach-Object { 
        Get-WindowsCapability -Online -Name $PSItem
    }
}

# Install missing capabilities

$restartNeeded = $false

if ($windowsCapability.State -contains 'NotPresent' ) {

    # If $computerName is an FQDN, extract the first segment

    $computerHostName = ($computerName -split '\.')[0]

    # Check, if script runs on the target computer

    if ($computerHostName -eq $env:COMPUTERNAME) {
        $windowsCapability | 
        Where-Object { $PSItem.State -eq 'NotPresent' } |
        ForEach-Object {
            $restartNeeded = (
                $PSItem | Add-WindowsCapability -Online
            ).RestartNeeded -or $restartNeeded
        }
    }
    
    # If not called locally on CL1, display warning

    if ($computerHostName -ne $env:COMPUTERNAME) {
        Write-Warning @"
Remote server administration tools cannot be installed remotely.
Please run $($MyInvocation.MyCommand) on $computerName.
"@
        exit
    }
}

if ($restartNeeded) {
    Restart-Computer -ComputerName $computerName
}

#region Install GPMC on local computer

$productType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType

# Check for Workstation
if ($productType -eq 1) {
    $names = 'RSAT.GroupPolicy.Management.Tools*'
    $restartNeeded = $false
    $names | ForEach-Object {
        $windowsCapability = Get-WindowsCapability -Online -Name $PSItem
        if ($windowsCapability.State -ne 'Installed') {
            $restartNeeded = $restartNeeded -or (
                $windowsCapability | Add-WindowsCapability -Online
            ).RestartNeeded
        } 
    }
}

# Check for Server
if ($productType -ne 1) {
    $name = 'GPMC'

    $featureOperationResult = `
        Get-WindowsFeature -Name $name |
        Where-Object { $PSItem.InstallState -ne 'Installed' } |
        Install-WindowsFeature

    $restartNeeded = $featureOperationResult.Success `
        -and $featureOperationResult.RestartNeeded -eq 'Yes'
    
    if (-not ($featureOperationResult.Success)) {
        Write-Warning "Feature $name could not be installed. Aborting."
        exit
    }

    if ($restartNeeded) {
        Write-Host @"
The local computer needs a restart.
After the restart, please run $($MyInvocation.MyCommand) again.
"@
        Read-Host 'Press Enter to restart now'
        Restart-Computer
        exit
    }
}

#endregion Install GPMC on local computer



#endregion Task 1: Install the Group Policy Management Console

#region Task 2: Create a group policy object

Write-Host '        Task 2: Create a group policy object'

$gpoName = 'Custom Computer Audit Object Access'

if ($null -eq (Get-GPO -Name $gpoName -ErrorAction SilentlyContinue)) {
    $null = New-GPO -Name $gpoName
}

#endregion Task 2: Create a group policy object

#region Task 3: Edit the audit policy in the group policy object

Write-Host '        Task 3: Edit the audit policy in the group policy object'

Write-Warning @"
The group policy object $gpoName cannot be configured using PowerShell.
Please refer to the lab guide 'Audit-file-server-events.md', Exercise 1, Task 2
to configure the group policy object $gpoName manually.
"@

#endregion Task 3: Edit the audit policy in the group policy object


#region Task 4: Apply the group policy object to file servers

Write-Host '        Task 4: Apply the group policy object to file servers'

$path = 'dc=ad,dc=adatum,dc=com'

'Devices', 'Servers', 'File Servers' | ForEach-Object {
    try {
        $name = $PSItem
        $organizationalUnit = `
            Get-ADOrganizationalUnit -Identity "ou=$name, $path"
    }
    catch {
        $organizationalUnit = `
            New-ADOrganizationalUnit -Path $path -Name $name -Passthru
    }

    $path = $organizationalUnit.DistinguishedName
}

if (
    $null -eq (
        (Get-GPInheritance -Target $path).GpoLinks |
        Where-Object { $PSItem.DisplayName -eq $gpoName}
    )
) {
    $null = New-GPLink -Name $gpoName -Target $path
}

Get-ADComputer 'VN1-SRV10' | 
Move-ADObject -TargetPath $organizationalUnit.DistinguishedName

Invoke-GPUpdate -Computer 'VN1-SRV10' -Force


#endregion Task 4: Apply the group policy object to file servers

#region Task 5: Enable auditing of read access

Write-Host '        Task 5: Enable auditing of read access'

Invoke-Command -ComputerName VN1-SRV10 {
    $path = 'D:\Shares\Finance'
    $acl = Get-Acl -Path $path -Audit

    # Disable inheritance and delete all existing rules

    $acl.SetAuditRuleProtection($true, $false)

    # Typical flags for audit rules

    $inheritanceFlags = 'ContainerInherit, ObjectInherit'
    $propagationFlags = 'None'
    $auditFlags = 'Success'

    # Create the Read rule

    $auditRule = New-Object `
        -TypeName System.Security.AccessControl.FileSystemAuditRule `
        -ArgumentList `
            'Everyone', `
            'ReadAndExecute', `
            $inheritanceFlags, `
            $propagationFlags, `
            $auditFlags
    
    $acl.AddAuditRule($auditRule)

    $acl | Set-Acl -Path $path
}

#endregion Task 5: Enable auditing of read access

#endregion Exercise 1: Audit access to a folder

#region Exercise 2: Use a a global audit policy

Write-Host '    Exercise 2: Use a a global audit policy'

#region Task 1: Edit the group policy object

Write-Host '    Task 1: Edit the group policy object'

Write-Warning @"
The group policy object $gpoName cannot be configured using PowerShell.
Please refer to the lab guide 'Audit-file-server-events.md', Exercise 2, Task 1
to configure the group policy object $gpoName manually.
"@

#endregion Task 1: Edit the group policy object


#endregion Exercise 2: Use a a global audit policy