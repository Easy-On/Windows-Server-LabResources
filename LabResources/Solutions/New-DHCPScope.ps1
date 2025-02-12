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

#region Practice: Add a DHCP scope

Write-Host 'Practice: Add a DHCP scope'

$pSSession = New-PSSession -ComputerName 'VN1-SRV6'

if ($null -eq (
    Invoke-Command -Session $pSSession -ScriptBlock {
        $scopeId = '10.1.1.0'
        Get-DhcpServerv4Scope -ScopeId $scopeId -ErrorAction SilentlyContinue
    }
)) {
    $null = Invoke-Command -Session $pSSession -ScriptBlock {
        Add-DhcpServerv4Scope `
            -Name 'VNet1' `
            -StartRange 10.1.1.2 `
            -EndRange 10.1.1.254 `
            -SubnetMask 255.255.255.0 `
            -LeaseDuration  (New-TimeSpan -Hours 2) `
            -State InActive
    }
}

Invoke-Command -Session $pSSession -ScriptBlock {
    Set-DhcpServerv4OptionValue -ScopeId $scopeId -Router 10.1.1.1
}

Remove-PSSession -Session $pSSession

#endregion Practice: Add a DHCP scope