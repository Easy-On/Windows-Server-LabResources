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

#region Practice: Install the Microsoft Office Filter Pack

Write-Host 'Practice: Install the Microsoft Office Filter Pack'

Invoke-Command -ComputerName VN1-SRV10 -ScriptBlock {
    $destination = 'D:\Shares\IT\FilterPack64bit.exe'
    if (
        $null -eq 
        (
            Get-Package `
                -Name 'Microsoft Filter Pack 2.0' `
                -ErrorAction SilentlyContinue
        )
    ) {
        if (-not (Test-Path -Path $destination)) {
            Start-BitsTransfer `
                -Source 'https://download.microsoft.com/download/0/A/2/0A28BBFA-CBFA-4C03-A739-30CCA5E21659/FilterPack64bit.exe' `
                -Destination $destination
        }
        Start-Process -FilePath $destination -ArgumentList '/quiet' -Wait
    }
}

#endregion Practice: Install the Microsoft Office Filter Pack