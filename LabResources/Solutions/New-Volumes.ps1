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

Write-Host 'Lab: Manage local storage'

#region Exercise 1: Manage disks

$computerName = 'VN1-SRV10', 'VN1-SRV5'

Write-Host '    Exercise 1: Manage disks'

$computerName | ForEach-Object {
    $cimSession = New-CimSession $PSItem

    Get-Disk -CimSession $cimSession | 
    Where-Object { $PSItem.OperationalStatus -eq 'Offline' } |
    Set-Disk -IsOffline $false -CimSession $cimSession

    Get-Disk -CimSession $cimSession |
    Where-Object { $PSItem.PartitionStyle -eq 'RAW' } |
    Initialize-Disk -CimSession $cimSession

    Remove-CimSession $cimSession
}

#endregion Exercise 1: Manage disks

#region Exercise 2: Manage volumes

Write-Host '    Exercise 2: Manage volumes'

#region Task 1: Create volumes

Write-Host '        Task 1: Create volumes'

$volumes = @(
    @{
        ComputerName = 'VN1-SRV10'
        Volumes = @(
            @{
                DiskNumber = 1
                FileSystem = 'NTFS'
                FileSystemLabel = 'NTFS 1TB'
                DriveLetter = 'D'
            }
            @{
                DiskNumber = 2
                Size = 512GB
                FileSystem = 'ReFS'
                FileSystemLabel = 'ReFS 512GB'
                DriveLetter = 'E'
            }
        )
    }
    @{
        ComputerName = 'VN1-SRV5'
        Volumes = @(
            @{
                DiskNumber = 1
                Size = 512GB
                FileSystem = 'ReFS'
                FileSystemLabel = 'ReFS 512GB'
                DriveLetter = 'D'
            }
            @{
                DiskNumber = 1
                Size = 128GB
                FileSystem = 'NTFS'
                FileSystemLabel = 'NTFS 128GB'
                DriveLetter = 'E'
            }
        )
    }
)

$volumes | ForEach-Object {
    $cimSession = New-CimSession -ComputerName $PSItem.Computername
    $PSItem.Volumes | ForEach-Object {
        if ($null -eq (
            Get-Volume `
                -FileSystemLabel $PSItem.FileSystemLabel `
                -CimSession $cimSession `
                -ErrorAction SilentlyContinue
        )) {
            $newPartitionParams = @{
                CimSession = $cimSession
                DiskNumber = $PSItem.DiskNumber
            }
    
            if ($PSItem.Size -eq $null) {
                $newPartitionParams.Add('UseMaximumSize', $true)
            }
    
            if ($PSItem.Size -ne $null) {
                $newPartitionParams.Add('Size', $PSItem.Size)
            }
    
            if ($PSItem.DriveLetter -ne $null) {
                $newPartitionParams.Add('DriveLetter', $PSItem.DriveLetter)
            }
    
            $null = New-Partition @newPartitionParams |
            Format-Volume `
                -FileSystem $PSItem.FileSystem `
                -NewFileSystemLabel $PSItem.FileSystemLabel
        }
    }
    Remove-CimSession -CimSession $cimSession
}

#endregion Task 1: Create volumes

#region Task 2: Extend volume

Write-Host '        Task 2: Extend volume'

$cimSession = New-CimSession -ComputerName 'VN1-SRV10'

$size = 768GB
$partition = `
    Get-Partition -DiskNumber 2 -PartitionNumber 2 -CimSession $cimSession
if ($partition.Size -ne $size) {
    $partition | Resize-Partition -Size 768GB -CimSession $cimSession
}

Remove-CimSession $cimSession

#endregion Task 2: Extend volume

#endregion Exercise 2: Manage volumes

#region Exercise 3: Manage mount points

Write-Host '    Exercise 3: Manage mount points'

#region Task 1: Create a mount point

Write-Host '        Task 1: Create a mount point'

$computerName = 'VN1-SRV10'
$path = 'D:\ITData\'
$remotePath = $path -replace '^(.):\\', "\\$computername\`$1$\"

if (-not (Test-Path $remotePath)) {
    $null = New-Item -Type Directory -Path $remotePath
}

$cimSession = New-CimSession -ComputerName $computerName
$partition =  `
    Get-Volume -FileSystemLabel 'ReFS 512GB' -CimSession $cimSession | 
    Get-Partition -CimSession $cimSession

if ($partition.AccessPaths -notcontains $path) {
    $null = `
        $partition | 
        Add-PartitionAccessPath -AccessPath $path -CimSession $cimSession
}

#endregion Task 1: Create a mount point

#region Task 2: Validate mount points

Write-Host '        Task 2: Validate mount points'

$destination = $remotePath
Copy-Item `
    -Path "\\$computerName\C$\Sample Documents\IT\*" `
    -Destination $destination `
    -Recurse `
    -Force

#endregion Task 2: Validate mount points

#endregion Exercise 2: Manage volumes

#region Exercise 4: Manage links and junctions

Write-Host '     Exercise 4: Manage links and junctions'

#region Task 1: Create a hard link

Write-Host '        Task 1: Create a hard link'

Invoke-Command -ComputerName VN1-SRV10 -ScriptBlock {
    $name = 'SetupScript.ps1'
    $path = 'C:\'
    $target = 'C:\BootStrap\BootStrap.ps1'
    if (-not (Test-Path -Path (Join-Path -Path $path -ChildPath $name))) {
        $null = New-Item -ItemType HardLink -Target $target  -Name $name -Path $path
    }
}

#endregion Task 1: Create a hard link

#region Task 6: Create a junction

Write-Host '        Task 6: Create a junction'

Invoke-Command -ComputerName VN1-SRV10 -ScriptBlock {
    $name = 'Setup'
    $path = 'D:\'

    if (-not (Test-Path -Path (Join-Path -Path $path -ChildPath $name))) {
        $target = 'C:\BootStrap\'
        $null = New-Item `
            -ItemType Junction `
            -Target $target `
            -Name $name `
            -Path $path
    }
}

#endregion Task 6: Create a junction

#region Task 8: Create and verify a symbolic link

Write-Host '        Task 8: Create and verify a symbolic link'

$computerName = 'VN1-SRV10'
$name = 'Sysvol'
$path = 'D:\'
$junctionExists = Invoke-Command -ComputerName $computerName -ScriptBlock {
    Test-Path -Path (Join-Path -Path $using:path -ChildPath $using:name)
}

if (-not $junctionExists) {
    # If $computerName is an FQDN, extract the first segment

    $computerHostName = ($computerName -split '\.')[0]

    if ($computerHostName -eq $env:COMPUTERNAME) {
        $target = '\\VN1-SRV1\SYSVOL'
        $null = New-Item `
            -ItemType SymbolicLink `
            -Target $target `
            -Name $name `
            -Path $path
    }

    # If not called locally on $computerName, display warning

    if ($computerHostName -ne $env:COMPUTERNAME) {
        Write-Warning @"
Junction cannot be created.
Please run $($MyInvocation.MyCommand) on $computerName.
"@
    }
}

#endregion Task 8: Create and verify a symbolic link

#endregion Exercise 4: Manage links and junctions
