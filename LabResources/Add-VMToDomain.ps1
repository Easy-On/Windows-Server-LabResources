[CmdletBinding()]
param (
    # Name of VM to move
    [Parameter(Mandatory)]
    [string]
    $VMName,
    
    # Name of the domain to add the computer to
    [Parameter()]
    [string]
    $DomainName = 'ad.adatum.com',
    
    # Credentials of account with local administrator rights in VM
    [Parameter()]
    [pscredential]
    $LocalCredential = (
        Get-Credential `
            -Message `
                "Enter the password of the local Administrator account of $(
                    $VMName
                )" `
            -UserName 'Administrator'
    ),
    # Credentials of account with permissions to add the computer to the domain
    [Parameter()]
    [pscredential]
    $Credential = (
        Get-Credential `
            -Message `
                "Enter credentials of an account with permissions to join the computer to domain $(
                    $DomainName
                )" `
            -UserName 'Administrator@ad.adatum.com'
    ),
    # New name for computer
    [Parameter()]
    [string]
    $NewName
)

$pSSession = New-PSSession -VMName $VMName -Credential $LocalCredential

$parameters = @{
    LocalCredential = $LocalCredential
    Credential = $Credential
    DomainName = $DomainName
    Restart = $true
    Force = $true
}

if (-not [string]::IsNullOrWhiteSpace($NewName)) {
    $parameters.NewName = $NewName
}

Invoke-Command -Session $pSSession -ScriptBlock {
    Add-Computer @using:parameters
}

Remove-PSSession $pSSession