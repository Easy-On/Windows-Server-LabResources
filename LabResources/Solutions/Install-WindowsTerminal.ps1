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

#region Practice: Install Windows Terminal

Write-Host 'Practice: Install Windows Terminal'

Invoke-Command -ComputerName VN2-SRV1 -ScriptBlock {
    $destination = "C:\LabResources"
    Start-BitsTransfer `
        -Source 'https://github.com/microsoft/terminal/releases/download/v1.18.3181.0/Microsoft.WindowsTerminal_1.18.3181.0_8wekyb3d8bbwe.msixbundle_Windows10_PreinstallKit.zip' `
        -Destination $destination
    Start-BitsTransfer `
        -Source 'https://github.com/microsoft/terminal/releases/download/v1.18.3181.0/Microsoft.WindowsTerminal_1.18.3181.0_8wekyb3d8bbwe.msixbundle' `
        -Destination $destination
    
    $path = Join-Path `
        -Path $destination `
        -ChildPath `
            'Microsoft.WindowsTerminal_*.msixbundle_Windows10_PreinstallKit.zip'
    $destinationPath = Join-Path `
        -Path $destination `
        -ChildPath `
            'Microsoft.WindowsTerminal_*.msixbundle_Windows10_PreinstallKit'
    Expand-Archive -Path $path -DestinationPath $destinationPath
    Add-AppPackage (
        Join-Path `
            -Path $destinationPath -ChildPath Microsoft.UI.Xaml.*_x64__*.appx
    )
    Add-AppPackage (
        Join-Path `
            -Path $destination -ChildPath Microsoft.WindowsTerminal_*.msixbundle
    )
}

#endregion Practice: Install Windows Terminal
