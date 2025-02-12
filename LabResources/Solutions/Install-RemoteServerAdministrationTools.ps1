[CmdletBinding()]
param (
    [Parameter()]
    [switch]
    $SkipDependencies
)

if (-not $SkipDependencies) {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-Dependencies.ps1') `
        -Script $MyInvocation.MyCommand `
        -Confirm:$false
}

#region Practice: Install Remote Server Administration Tools

Write-Host 'Practice: Install Remote Server Administration Tools'

$computerName = 'CL1'

try {
    $windowsCapability = Invoke-Command `
        -ComputerName $computerName `
        -ErrorAction Stop `
        -ScriptBlock {
            <#
                This array defines the tools to install. With the File Services tools,
                Server Manager is installed automatically
            #>
            # 
            $names = @(
                'Rsat.ActiveDirectory.DS-LDS.Tools*',
                'Rsat.FileServices.Tools*',
                'Rsat.GroupPolicy.Management.Tools*'
            )
            $names | ForEach-Object { 
                Get-WindowsCapability -Online -Name $PSItem
            }
        }
    
}
catch {
    Write-Warning "Could not connect to $computerName. Are you running the script on the right computer?"
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
    }
}

if ($restartNeeded) {
    Write-Host @'
The local computer needs a restart.
After the restart, please run the script again.
'@
    Read-Host 'Press ENTER to restart'
    Restart-Computer
}

#endregion Practice: Install Remote Server Administration Tools