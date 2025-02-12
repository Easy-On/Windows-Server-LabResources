# Description: This script installs a service that runs a PowerShell script.

# Download the NSSM utility

if (
    -not (Test-Path 'c:\Labresources\nssm.exe') -and
    -not (Test-Path 'c:\Windows\Temp\nssm.zip')) {
        $bitsTransfer = Start-BitsTransfer `
        -Source 'https://nssm.cc/ci/nssm-2.24-101-g897c7ad.zip' `
        -Destination 'C:\Windows\Temp\nssm.zip' `
        -Asynchronous
}

# Install the Remote Server Administration Tools (RSAT) feature
$windowsFeature = Get-WindowsFeature -Name 'RSAT-AD-PowerShell'

if ($windowsFeature.installState -ne 'Installed') {
    $windowsFeature | Install-WindowsFeature
}

#region Create the service account

$domainFQDN = 'ad.adatum.com'
$oUName = 'Service accounts'
$domainDN = (
    $domainFQDN -split '\.' | ForEach-Object { "DC=$PSItem" }
) -join ','
$identity = "OU=$oUName,$domainDN"

# Create the organizational unit if it does not exist
try {
    $adOrganizationalUnit = `
        Get-ADOrganizationalUnit -Identity $identity -ErrorAction SilentlyContinue
}
catch {
    <#Do this if a terminating exception happens#>
}

if ($null -eq $adOrganizationalUnit) {
    New-ADOrganizationalUnit `
        -Name $oUName `
        -Path $domainDN
}

# Create the service account if it does not exist
$path = "ou=$ouname,$domainDN"
$name = 'PowerShell service'
$samAccountName = 'PSService'
$userPrincipalName = "$samAccountName@$domainFQDN"
$newPassword = ConvertTo-SecureString -String 'Pa$$w0rd' -AsPlainText -Force
$identity = "cn=$name,$path"

$adUser = Get-ADUser -Filter { SamAccountName -eq $samAccountName }

if ($null -eq $adUser) {
    $adUser = New-ADUser `
        -Path $path `
        -Name $name `
        -SamAccountName $samAccountName `
        -UserPrincipalName $userPrincipalName `
        -AccountPassword $newPassword `
        -ChangePasswordAtLogon $false `
        -Enabled $true `
        -PassThru
}

$aDUser | Set-ADAccountPassword -Reset -NewPassword $newPassword
$aDUser | Set-ADUser -ChangePasswordAtLogon $false
$aDUser | Enable-ADAccount

#endregion Create the service account

#region Grant the service account the "Log on as a service" right

$account = "*$($adUser.SID.Value)"
$seceditFile = 'C:\Windows\Temp\secedit.inf'
$seceditLog = 'C:\Windows\Temp\secedit.log'

# Export the current security policy
secedit /export /cfg $seceditFile /areas USER_RIGHTS

# Add the "Log on as a service" right to the service account
$content = Get-Content $seceditFile
$logonAsServiceRight = 'SeServiceLogonRight'
$updatedContent = $content -replace "($logonAsServiceRight\s*=\s*)(.*)", "`$1`$2,$account"
$updatedContent | Set-Content $seceditFile

# Apply the updated security policy
secedit /configure /db $seceditLog /cfg $seceditFile /areas USER_RIGHTS

# Clean up
Remove-Item $seceditFile
Remove-Item $seceditLog

#endregion Grant the service account the "Log on as a service" right

# Wait for the BITS transfer to complete
if ($bitsTransfer) {
    while ($bitsTransfer.JobState -in @('Connecting','Transferring')) {
        Start-Sleep -Seconds 1
    }

    if ($bitsTransfer.JobState) {
        $bitsTransfer | Complete-BitsTransfer
    }
}

#region Extract and copy service files

if (-not (Test-Path 'C:\Windows\Temp\nssm-2.24-101-g897c7ad\win64\nssm.exe')) {
    Expand-Archive `
        -Path 'C:\Windows\Temp\nssm.zip' `
        -DestinationPath 'C:\Windows\Temp' `
        -Force
}

if (-not (Test-Path 'C:\LabResources\nssm.exe')) {
    Copy-Item `
        -Path 'C:\Windows\Temp\nssm-2.24-101-g897c7ad\win64\nssm.exe' `
        -Destination 'C:\LabResources\nssm.exe'
}

if (-not (Test-Path 'C:\LabResources\service.ps1')) {
    Copy-Item `
        -Path 'C:\LabResources\Solutions\service.ps1' `
        -Destination 'C:\LabResources\service.ps1'
}

#endregion Extract and copy service files

#region Install the service

$serviceName = 'PSService'

if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
& 'C:\LabResources\nssm.exe' `
    install $serviceName `
    'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
    '-ExecutionPolicy Bypass -NoProfile -File C:\LabResources\service.ps1'
}


$credential = New-Object `
    -TypeName PSCredential `
    -ArgumentList $userPrincipalName, $newPassword

Set-Service -Name $serviceName -StartupType Automatic -Credential $credential
Restart-Service -Name $serviceName

#endregion Install the service