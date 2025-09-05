[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string[]]
    $Name,
    [string]
    $ComputerName = $env:COMPUTERNAME,
    [pscredential]
    $Credential,
    [switch]
    $AsJob
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
$null = $remotingParameters.Remove('AsJob')
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
                    param($name)
                    Get-WindowsCapability `
                        -Online -Name $name
                } `
                -ArgumentList $feature.CapabilityName

            if ($windowsCapability.State -ne 'Installed') {
                # Check for local invocation
                if ($env:COMPUTERNAME -eq $hostName) {
                    Write-Verbose "Install $Name on $ComputerName"
                    $job = Start-Job `
                        -ScriptBlock { 
                            Add-WindowsCapability `
                                -Online -Name $using:feature.CapabilityName 
                        }
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
                        param ($name)
                        Get-WindowsFeature `
                            -Name $name |
                        Where-Object { $PSItem.InstallState -ne 'Installed' }
                    } `
                    -ArgumentList $feature.FeatureName

                if ($windowsFeature) {
                    Write-Verbose `
                        "Install $($windowsFeature.Name) on $ComputerName"
                    $job = Invoke-Command  `
                        -Session $psSession -ScriptBlock -AsJob {
                            param ($windowsFeature)
                            $windowsFeature |
                            Install-WindowsFeature -Restart
                        } `
                        -ArgumentList $windowsFeature
                }
            }
        }
    }
}

$psSession | Remove-PSSession

if (-not $AsJob) {
    $jobResult = $job | Wait-Job | Receive-Job
    if ($jobResult) {
        if (
            $jobResult.RestartNeeded -eq 'Yes' `
            -or $jobResult.RestartNeeded -eq $true
        ) {
            $restartNeeded = $true
        }
    }
    if ($jobResult.Success -eq $false) {
        Write-Error "Feature $($feature.FeatureName) could not be installed."
    }
    if ($restartNeeded) {
        if ($hostName -eq $env:COMPUTERNAME) {
            Write-Host @"
The local computer needs a restart.
After the restart, please run $($MyInvocation.ScriptName) again.
"@
            Read-Host 'Press Enter to restart now'
            Restart-Computer
            exit
        }
        if ($hostName -ne $env:COMPUTERNAME) {
            Restart-Computer `
                -ComputerName $ComputerName `
                -Protocol WSMan `
                -Credential $Credential
                do {
                    Write-Warning `
                        "Waiting for $ComputerName to become available"
                } until (
                    Test-WSMan `
                        -$remotingParameters `
                        -ErrorAction SilentlyContinue
                )
        }
    }
}

if ($AsJob) {
    return $job
}

