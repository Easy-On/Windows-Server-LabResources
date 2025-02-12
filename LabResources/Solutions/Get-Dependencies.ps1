[CmdletBinding()]
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

if ([string]::IsNullOrWhiteSpace($ActivitiesPath)) {
    $ActivitiesPath = Join-Path -Path $PSScriptRoot -ChildPath 'Activities.psd1'
}

#region script imports

. (Join-Path -Path $PSScriptRoot -ChildPath 'Activity.ps1')

#endregion script imports

function Get-Activity {
    [CmdletBinding()]
    [OutputType([Activity[]])]
    param (
        [Parameter(ValueFromPipeline, ParameterSetName = 'ID')]
        [String[]]
        $ID,
        
        [Parameter(ParameterSetName = 'Script')]
        [String[]]
        $Script,

        [Parameter(ParameterSetName = 'ID')]
        [Parameter(ParameterSetName = 'Script')]
        [Activity[]]
        $Activities
    )
    begin {

    }
    process {
        $propertyName = $PSCmdlet.ParameterSetName
        switch ($PSCmdlet.ParameterSetName) {
            'ID' { 
                $searchString = $ID
             }
             'Script' {
                $searchString = $Script
             }
            Default {}
        }
        foreach ($item in $searchString) {
            $activity = `
                $Activities | Where-Object { $PSItem.$propertyName -eq $item } 
            
            if ($null -eq $activity) {
                Write-Warning "$item not found."
            }
            $activity
        }   
    }
    end {

    }
}

function Get-Dependencies {
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter(ValueFromPipeline, ParameterSetName = 'ID')]
        [String[]]
        $ID,

        [Parameter(ParameterSetName = 'Script')]
        [String[]]
        $Script,

        [Parameter(ParameterSetName = 'ID')]
        [Parameter(ParameterSetName = 'Script')]
        [Activity[]]
        $Activities
    )
    begin {
        $dependencies = @()
        $selectActivities = Get-Activity @PSBoundParameters
    }

    process {
        # Iterate throug activities
    
        foreach ($activity in $selectActivities) {

            # Iterate through dependencies

            foreach ($dependency in $activity.DependsOn) {
                # Get upper dependencies

                $upperDependencies = Get-Dependencies `
                    -ID $dependency `
                    -Activities $Activities

                # Filter out duplicates and add upper dependencies

                foreach ($upperDependency in $upperDependencies) {
                    if ($upperDependency -notin $dependencies) {
                        $dependencies += $upperDependency
                    }
                }

                # Add dependency, if not already added by upper dependency
                
                if ($dependency -notin $dependencies) {
                    $dependencies += $dependency
                }
            }
        }
    }

    end {
        return $dependencies
    }
}

$activities = (Import-PowerShellDataFile -Path $ActivitiesPath).Activities

#region If ID is not provided, display menu

if ($PSCmdlet.ParameterSetName -eq 'Interactive') {
    Write-Host `
        -Object 'Which activity do you want to run the prerequisites for?' `
        -BackgroundColor Blue `
        -ForegroundColor White
    Write-Host
    do {
        $i = 0
        foreach ($activity in $activities) {
            $i++
            Write-Host ('{0,2}   {1}' -f $i, $activity.DisplayName)
        }
        Write-Host `
            -Object 'Enter the number of the activity to prepare for: ' `
            -NoNewline `
            -BackgroundColor Blue `
            -ForegroundColor White
        $selectionString = Read-Host
        $selection = 0
        $null = [int]::TryParse($selectionString, [ref] $selection)
        $selection -= 1
    } until (
        $selection -gt 0 -and $selection -lt $activities.count
    )
    $activity = $activities[$selection]
    $ID = $activity.ID
}
#endregion If ID is not provided, display menu

if ($PSCmdlet.ParameterSetName -in 'Interactive', 'ID') {
    $dependencies = Get-Dependencies -ID $ID -Activities $activities
}

if ($PSCmdlet.ParameterSetName -eq 'Script') {
    $dependencies = Get-Dependencies -Script $Script -Activities $activities 
}

Get-Activity -ID $dependencies -Activities $activities