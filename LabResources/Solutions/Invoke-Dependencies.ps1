[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param (
    [Parameter(Mandatory, ParameterSetName = 'ID')]
    [string]
    $ID,

    [Parameter(Mandatory, ParameterSetName = 'Script')]
    [string]
    $Script,

    [Parameter(ParameterSetName = 'ID')]
    [Parameter(ParameterSetName = 'Script')]
    [Parameter(ParameterSetName = 'Interactive')]
    [string]
    $ActivitiesPath = $null
)

$null = $PSBoundParameters.Remove('Confirm')
$null = $PSBoundParameters.Remove('WhatIf')

$dependencies = $null
$dependencies = . (
    Join-Path -Path $PSScriptRoot -ChildPath 'Get-Dependencies.ps1'
) `
    @PSBoundParameters

function Invoke-Activity {
    [CmdletBinding()]
    param (
        # IDs of activities
        [Parameter(ValueFromPipeline, ParameterSetName = 'ID')]
        [string[]]
        $ID,
        # Array of activities to search
        [Parameter(ParameterSetName = 'ID')]
        [Activity[]]
        $Activities,

        # Activities to invoke
        [Parameter(ValueFromPipeline, ParameterSetName = 'Activity')]
        [Activity[]]
        $Activity
    )
    
    begin {
    }
    
    process {
        if ($PSCmdlet.ParameterSetName -eq 'ID') {
            $Activity = Get-Activity -ID $ID -Activities $Activities
        }

        foreach ($item in $Activity) {
            if ([String]::IsNullOrWhiteSpace($item.Script)) {
                Write-Warning "Activity $($item.ID) has no script."
            }
            if (-not [String]::IsNullOrWhiteSpace($item.Script)) {
                . (Join-Path -Path $PSScriptRoot -ChildPath $item.Script) `
                    -SkipDependencies
            }
        }
    }
    
    end {
        
    }
}

if ($dependencies -and $PSCmdlet.ShouldProcess(
    "Invoking `n          $($dependencies.Script -join "`n          ")",
    $dependencies.Script -join "`n", 
    'Invoke'
)) {
    $dependencies | Invoke-Activity
}