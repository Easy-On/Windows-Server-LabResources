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


#region Practice: Explore Server Manager

Write-Host 'Practice: Explore Server Manager'

$computerName = 'CL1'

try {
    $psSession = New-PSSession -ComputerName $computerName -ErrorAction Stop

    Invoke-Command -Session $psSession -ScriptBlock {
        Stop-Process -Name ServerManager -ErrorAction SilentlyContinue
    }
    
        
    #region Create the empty serverlist
    
    $xml = New-Object xml
    $element = $xml.CreateElement('ServerList')
    $element.SetAttribute('xmlns:xsd', 'http://www.w3.org/2001/XMLSchema')
    $element.SetAttribute(
        'xmlns:xsi', 'http://www.w3.org/2001/XMLSchema-instance'
    )
    $element.SetAttribute('localhostName', '')
    $element.SetAttribute('xmlns', 'urn:serverpool-schema')
    $null = $xml.AppendChild($element)
    
    #endregion Create the empty serverlist
    
    if ((Get-ComputerInfo).CsDomainRole -eq 'MemberWorkstation') {
        
        # Install PowerShell module for Active Directory
    
        # & $PSScriptRoot\Install-RSATModule.ps1 -Name ActiveDirectory
    
        # Add servers
    
        $adComputers = `
            Get-ADComputer -Filter 'Name -like ''VN*'' -or Name -like ''PM-*'''
    
        $adComputers | ForEach-Object {
            $element = $xml.CreateElement('ServerInfo', 'urn:serverpool-schema')
            $element.SetAttribute('name', $PSItem.DNSHostName)
            $null = $xml.ServerList.AppendChild($element)
        }
    
    }
    
    # Save XMl file
    
    Invoke-Command -Session $psSession -ScriptBlock {
        $path = "$env:APPDATA\Microsoft\Windows\ServerManager"
        if (-not (Test-Path($path))) {
            $null = New-Item -Path $path -ItemType Directory
        }
        $null = ($using:xml).Save("$path\ServerList.xml")
    
    }
    
    Remove-PSSession $psSession    
}
catch {
    Write-Warning "Could not connect to $computerName. Servers were not added to Server Manager."
}

#endregion Practice: Explore Server Manager