[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]
    $Template,
    [Parameter(Mandatory)]
    [string[]]
    $ComputerName
)


# GUID for the extended AD right to enroll certificates
$extendedRightCertificateEnrollment = `
    [GUID]'0e10c968-78fb-11d2-90d4-00c04f79dc55'

& $PSScriptRoot\Install-RSATModule.ps1 -Name ActiveDirectory
Import-Module ActiveDirectory

$configurationNamingContext = `
    (Get-Item -Path 'AD:\').configurationNamingContext

# Path to the certificate template

Write-Verbose "Getting template $template"
$path = `
    "AD:\CN=$template,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configurationNamingContext"

Write-Verbose "Getting ACL"
$acl = Get-Acl -Path $path

foreach ($item in $ComputerName) {
    Write-Verbose "Getting computer account for $item"
    $adComputer = Get-ADComputer -Identity $item
    Write-Verbose "Granting Read and Enroll permissions to $item"
    $accessRule = New-Object `
    -TypeName System.DirectoryServices.ActiveDirectoryAccessRule `
    -ArgumentList `
        $adComputer.SID, `
        'GenericRead,ExtendedRight', `
        'Allow', `
        $extendedRightCertificateEnrollment
    $acl.AddAccessRule($accessRule)
}

Write-Verbose "Setting ACL"
Set-Acl -Path $path -AclObject $acl