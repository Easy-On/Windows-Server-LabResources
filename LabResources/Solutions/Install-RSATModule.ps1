[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string[]]
    $Name,
    [string]
    $ComputerName = $env:COMPUTERNAME,
    [pscredential]
    $Credential
)

$features = @(
    @{
        ModuleName = 'ActiveDirectory'
        CapabilityName = 'Rsat.ActiveDirectory.DS-LDS.Tools*'
        FeatureName = 'RSAT-AD-PowerShell'
    }
    @{
        ModuleName = 'DNS'
        CapabilityName = 'Rsat.Dns.Tools*'
        FeatureName = 'RSAT-DNS-Server'
    }
    @{
        ModuleName = 'GPMC'
        CapabilityName = 'RSAT.GroupPolicy.Management.Tools*'
        FeatureName = 'GPMC'
    }
    @{
        ModuleName = 'DHCP'
        CapabilityName = 'Rsat.DHCP.Tools*'
        FeatureName = 'RSAT-DHCP'
    }
)

$hostName = ($ComputerName -split '\.')[0]
$remotingParameters = $PSBoundParameters
$null = $remotingParameters.Remove('Name')
$psSession = New-PSSession @remotingParameters


if ($psSession) {
    $productType = Invoke-Command -Session $psSession -ScriptBlock {
        (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
    }
}
$restartNeeded = $false

foreach ($moduleName in $Name) {
    $feature = $features |
        Where-Object { $PSItem.ModuleName -eq $moduleName }
    if ($null -eq $feature) {
        Write-Warning `
            "Module not found. Feature or capability for module $moduleName cannot be installed."
    }

    if ($null -ne $feature) {
        # Check for Workstation
        if ($productType -eq 1) {

            $windowsCapability = Invoke-Command `
                -Session $psSession -ScriptBlock {
                    Get-WindowsCapability `
                        -Online -Name $using:feature.CapabilityName
                }

            if ($windowsCapability.State -ne 'Installed') {
                # Check for local invocation
                if ($env:COMPUTERNAME -eq $hostName) {
                    Write-Verbose "Install $Name on $ComputerName"
                    $restartNeeded = $restartNeeded -or (
                        $windowsCapability | Add-WindowsCapability -Online
                    ).RestartNeeded
                } 
                if ($env:COMPUTERNAME -ne $hostName) {
                    Write-Warning @"
$Name ($($feature.CapabilityName)) cannot be installed remotely.
Please run $($MyInvocation.MyCommand) on $computerName.
"@
                }
            }
        }

        # Check for Server
        if ($productType -ne 1) {
            if ($psSession) {
                $windowsFeature = Invoke-Command `
                    -Session $psSession -ScriptBlock {
                        Get-WindowsFeature `
                            -Name $using:feature.FeatureName |
                        Where-Object { $PSItem.InstallState -ne 'Installed' }
                    }

                if ($windowsFeature) {
                    Write-Verbose `
                        "Install $($windowsFeature.Name) on $ComputerName"
                    $featureOperationResult = Invoke-Command  `
                        -Session $psSession -ScriptBlock {
                            $using:windowsFeature |
                            Install-WindowsFeature -Restart
                        }
                }
            }

            if ($featureOperationResult) {
                if (-not $featureOperationResult.Success) {
                    Write-Warning "Feature $(
                        $feature.FeatureName
                    ) could not be installed."
                }

                # If executed on local computer, postpone restart

                $restartNeeded = $hostName -eq $env:COMPUTERNAME `
                    -and $featureOperationResult.RestartNeeded -eq 'Yes'

                # Remote computers start automatically, just wait for it

                if (
                    -not $restartNeeded `
                    -and $featureOperationResult.RestartNeeded -eq 'Yes'
                ) {
                    Restart-Computer -ComputerName $ComputerName -Protocol WSMan
                    do {
                        Write-Warning `
                            "Waiting for $ComputerName to become available"
                    } until (
                        Test-WSMan `
                            -$remotingParameters `
                            -ErrorAction SilentlyContinue
                    )
                }
                $restartNeeded = $false         
            }
        }
    }
}

$psSession | Remove-PSSession

if ($restartNeeded) {
    Write-Host @"
The local computer needs a restart.
After the restart, please run $($MyInvocation.ScriptName) again.
"@
    Read-Host 'Press Enter to restart now'
    Restart-Computer
    exit
}
