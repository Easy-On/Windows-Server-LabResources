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

function Use-WindowsFeature {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string[]]
        $Name
    )
    $productType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType

    # Check for server

    if ($productType -ne 1) {
        Write-Verbose "Installing Windows feature $Name"
        $featureOperationResult = `
            Get-WindowsFeature -Name $Name |
            Where-Object { $PSItem.InstallState -ne 'Installed' } |
            Install-WindowsFeature
    
        $restartNeeded = $featureOperationResult.Success -and `
            $featureOperationResult.RestartNeeded -eq 'Yes'
        
        if (-not $featureOperationResult.Success) {
            Write-Warning "Feature $Name could not be installed. Aborting."
            exit
        }
    }    

    if ($restartNeeded) {
        Write-Host @"
The local computer needs a restart.
After the restart, please run $($MyInvocation.MyCommand) again.
"@
        Read-Host 'Press Enter to restart now'
        Restart-Computer
        exit
   }
}

function Get-ComputerCertificate {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $SubjectName,
        [Parameter()]
        [string]
        $ComputerName,
        [string[]]
        $DnsName,
        [string]
        $Template = 'WebServer'
    )

    Write-Verbose "Getting the certificate for $subjectName"

    $certificate = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        $now = Get-Date
        Get-ChildItem 'Cert:\LocalMachine\My' | 
        Where-Object { 
            $PSItem.Subject -eq $using:subjectName `
            -and $now -gt $PSItem.NotBefore `
            -and $now -lt $PSItem.NotAfter `
        } | 
        Sort-Object NotAfter -Descending | Select-Object -First 1
    }


    if ($null -eq $certificate) {

        Write-Verbose "Certificate not found."

        <# 
            Certificates cannot be requested using PowerShell remoting.
            Therefore, we must check, if we are on the local computer.
        #>

        # If $computerName is an FQDN, extract the first segment

        $computerHostName = ($ComputerName -split '\.')[0]

        # If not called locally on WAC gateway, display error message box

        if ($computerHostName -ne $env:COMPUTERNAME) {

            Write-Warning @"
Certificate cannot be requested!
Please run $PSCommandPath on $computerName.
"@
        }

        # Request certificate, if everything is okay

        if ($computerHostName -eq $env:COMPUTERNAME) {

            # Refresh group policies to ensure, the root CA certificate is installed

            Write-Verbose 'Refreshing group policies.'

            gpupdate.exe /force | Out-Null

            Write-Verbose @"
Requesting certificate using the template $template 
with the subject name $subjectName and the DNS name $dnsName
"@

            $params = @{
                Template = $Template
                SubjectName = $SubjectName
                CertStoreLocation = 'Cert:\LocalMachine\My' 
            }

            if ($DnsName) {
                $params.Add('DnsName', $DnsName)
            }

            $certificate = (Get-Certificate @params).Certificate
        }
    }
    return $certificate
}

Write-Host 'Lab: Active Directory Rights Management Service'

$rmsClusterName = 'rms'
$rmsClusterNode = 'VN2-SRV1', 'VN2-SRV2'
$dbServerAlias = 'rmsdb'
$dbServer = 'VN1-SRV3'
$domain = 'ad.adatum.com'
$domainNetBIOS = 'ad'
$serviceAccountSamAccountName = 'SvcRMS'
$serviceAccountName = "$domainNetBIOS\$serviceAccountSamAccountName"
$serviceAccountUserPrincipalName = "$serviceAccountSamAccountName@$domain"
$serviceAccountPassword = ConvertTo-SecureString `
    -String 'Pa$$w0rd' `
    -AsPlainText `
    -Force

$clusterDatabase = @{
    ServerName = "$dbServerAlias.$domain"
#    DatabaseName = 'DRMS_Config_rms_ad_adatum_com_443'
}
$clusterKey = @{
    CentrallyManagedPassword = ConvertTo-SecureString `
        -String 'Pa$$w0rd' `
        -AsPlainText `
        -Force
}
$clusterUrl = "https://$rmsClusterName.$($domain)"
# Server Licensor Certificate name
$sLCName = 'Adatum-RMS-Server-Licensor-Certificate' 

#region Prerequisites

Write-Host '    Setup'

Use-WindowsFeature -Name 'RSAT-AD-PowerShell'

$template = 'WebServer'
$computerName = $rmsClusterNode
Write-Verbose @"
Granting Enroll permissions for Certificate $template to $computername
"@
C:\LabResources\Solutions\Set-CertTemplatePermissions.ps1 `
        -Template $template `
        -ComputerName $computerName `

$mailDomain = 'adatum.com'
Write-Verbose 'Setting e-mail addresses for users'
Get-ADUser -Filter * | ForEach-Object { 
    $PSItem | 
    Set-ADUser -EmailAddress "$($PSItem.SamAccountName)@$mailDomain" 
}

Write-Verbose 'Setting e-mail addresses for groups'
Get-ADGroup -Filter * | ForEach-Object { 
    $PSItem | Set-ADGroup -Replace @{ mail="$($PSItem.Name)@$mailDomain" } 
}

#endregion Prerequisites

#region Exercise 1: Create an Active Directory Rights Management Cluster

Write-Host `
    '    Exercise 1: Create an Active Directory Rights Management Cluster'

#region Task 1: Create a service account

Write-Host '        Task 1: Create a service account'

$domainSplit = $domain -split '\.'
$domainDN = 'DC=' + ($domainSplit -join ', DC=')

$name = 'Service Accounts'
$path = $domainDN
Write-Verbose "Creating organizational unit $name"

try {
    $identity = "ou=$name, $path"
    $organizationalUnit = Get-ADOrganizationalUnit `
        -Identity $identity
}
catch {
    $organizationalUnit = New-ADOrganizationalUnit `
    -Path $path `
    -Name $name `
    -PassThru
}

$name = 'Active Directory Rights Management Service Account'
$path = $organizationalUnit.DistinguishedName
$userPrincipalName = $serviceAccountUserPrincipalName
$samAccountName = $serviceAccountSamAccountName
$accountPassword = $serviceAccountPassword

try {
    $null = Get-ADUser $serviceAccountSamAccountName
}
catch {
    Write-Verbose "Creating user $name"
    New-ADUser `
        -Path $path `
        -Name $name `
        -UserPrincipalName $userPrincipalName `
        -SamAccountName $samAccountName `
        -AccountPassword $accountPassword `
        -PasswordNeverExpires $true `
        -ChangePasswordAtLogon $false `
        -Enabled $true
}

#endregion Task 1: Create a service account

#region Task 2: Create DNS A records

Write-Host '        Task 2: Create DNS A records'
$computerName = 'VN1-SRV1' # DNS server
$zoneName = $domain
Use-WindowsFeature -Name 'RSAT-DNS-Server'

Write-Verbose 'Getting IPv4 address of DB server'

$aRecords = @(
    @{ 
        Name = $dbServerAlias
        IPv4Address = (
            Get-DnsServerResourceRecord `
                -Name $dbServer `
                -ZoneName $zoneName `
                -RRType A `
                -ComputerName $computerName
            ).RecordData.IPv4Address.IPAddressToString
    }
)

Write-Verbose 'Getting IPv4 addresses of RMS cluster nodes'

$aRecords += $rmsClusterNode | ForEach-Object { @{
    Name = $rmsClusterName
    IPv4Address = (
        Get-DnsServerResourceRecord `
            -Name $PSItem `
            -ZoneName $zoneName `
            -RRType A `
            -ComputerName $computerName
        ).RecordData.IPv4Address.IPAddressToString
}}


foreach ($aRecord in $aRecords) {
    if ($null -eq (
        Get-DnsServerResourceRecord `
            -Name $aRecord.Name `
            -ZoneName $zoneName `
            -RRType A `
            -ErrorAction SilentlyContinue `
            -ComputerName $computerName
    )) {
        Write-Verbose @"
Creating A record $($aRecord.Name) pointing to $($aRecord.IPv4Address)
"@
        Add-DnsServerResourceRecordA `
            -Name $aRecord.Name `
            -ZoneName $zoneName `
            -IPv4Address $aRecord.IPv4Address `
            -ComputerName $computerName       
    }
}

#endregion Task 2: Create DNS A records

#region Task 3: Configure a group policy for Internet options to assign all https sites in the domain to the Intranet zone

Write-Host @'
        Task 3: Configure a group policy for Internet options to assign all https sites in the domain to the Intranet zone
'@

Use-WindowsFeature -Name GPMC

$name = 'Custom User Internet Settings'
$gpo = Get-GPO -Name $name -ErrorAction SilentlyContinue
if ($null -eq $gpo) {
    Write-Verbose "Creating GPO $name"
    $gpo = New-GPO -Name $name        
}


$key = `
    'HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'

$registryValues = @(
    @{ 
        Key = ''
        ValueName =  'ListBox_Support_ZoneMapKey'
        Type = 'DWord'
        Value = 1 
    }
    @{ 
        Key = 'ZoneMapKey'
        ValueName =  "https://*.$domain"
        Type = 'String'
        Value = 1
    }
    @{ 
        # Should result in 'ZoneMap\Domains\adatum.com\*.ad'
        Key = "ZoneMap\Domains\$(
            $domainSplit[1..($domainSplit.Length - 1)] -join '.'
        )\*.$($domainSplit[0])"
        ValueName =  'https'
        Type = 'DWord'
        Value = 1 
    }
)

foreach ($registryValue in $registryValues) {
    Write-Verbose @"
Setting in $key\$($registryValue.Key) the value $($registryValue.ValueName) to $($registryValue.Value)
"@
    $null = $gpo | Set-GPRegistryValue `
        -Key "$key\$($registryValue.Key)" `
        -ValueName $registryValue.ValueName `
        -Type $registryValue.Type `
        -Value $registryValue.Value
}

$target = $domainDN

if (
    $null -eq (
        (Get-GPInheritance -Target $target).GpoLinks |
        Where-Object { $PSItem.DisplayName -eq $name }
    )
) {
    Write-Verbose 'Linking GPO to domain'
    $null = New-GPLink -Name $name -Target $target
}

#endregion Task 3: Configure a group policy for Internet options to assign all https sites in the domain to the Intranet zone

#region Task 4: Install Active Directory Rights Managment Server Role

Write-Host `
    '        Task 4: Install Active Directory Rights Managment Server Role'

$computerName = $rmsClusterNode
$null = Invoke-Command -ComputerName $computerName -ScriptBlock {
    Install-WindowsFeature `
        -Name ADRMS-Server, Web-Mgmt-Console `
        -IncludeManagementTools `
        -Restart 
}

#endregion Task 4: Install Active Directory Rights Managment Server Role

#region Task 5: Request a web server certificate

Write-Host '        Task 5: Request a web server certificate'

$computerName = $rmsClusterNode[0]
$dnsName = @(
    "$rmsClusterName.$domain"
    $rmsClusterName
    "$($computerName).$domain"
    $($computerName)
)


$certificate = Get-ComputerCertificate `
    -SubjectName "cn=$rmsClusterName.$domain" `
    -DnsName $dnsName `
    -ComputerName $computerName

#endregion Task 5: Request a web server certificate

#region Task 6: Create the RMS cluster

Write-Host '        Task 6: Create the RMS cluster'

<# 
    RMS cluster cannot be created using PowerShell remoting.
    Therefore, we must check, if we are on the local computer.
#>

# If $computerName is an FQDN, extract the first segment

# If not called locally, display error message box

$computerName = $rmsClusterNode[0]

Write-Verbose 'Trying to find AD RMS cluster'
    
Import-Module ADRMSAdmin
$adrmsCluster = New-PSDrive `
    -Name RMS `
    -PSProvider AdRmsAdmin `
    -Root "https://$computerName" `
    -ErrorAction SilentlyContinue `
    -Force

if (Get-ChildItem $adrmsCluster.Root) {
    Write-Verbose 'Cluster found'
}

if (-not (Get-ChildItem $adrmsCluster.Root)) {
    Write-Verbose 'Cluster not found, creating new cluster'

    if ($computerName -ne $env:COMPUTERNAME) {
        Write-Warning @"
RMS cluster cannot be created!
Please run $PSCommandPath on $($computerName[0]).
"@
    }


    if ($computerName -eq $env:COMPUTERNAME) {
        Import-Module ADRMS
        $null = New-PSDrive -PSProvider ADRMSInstall -Name RC -Root RootCluster

        Write-Verbose 'Configuring database'
        Set-ItemProperty `
            �Path RC:\ClusterDatabase `
            -Name ServerName `
            -Value $clusterDatabase.Servername

        Write-Verbose 'Configuring service account'
        [PSCredential] $serviceAccount = New-Object `
            -Typename System.Management.Automation.PSCredential `
            -ArgumentList $serviceAccountName, $serviceAccountPassword
        Set-ItemProperty �Path RC:\ -Name ServiceAccount -Value $serviceAccount

        Write-Verbose 'Configuring the cryptographic mode'
        Set-ItemProperty `
            -Path RC:\CryptoSupport `
            -Name SupportCryptoMode2 `
            -Value $true

        Write-Verbose 'Configuring cluster key storage'
        Set-ItemProperty `
            -Path RC:\ClusterKey `
            -Name UseCentrallyManaged `
            -Value $true

        Write-Verbose 'Configuring cluster key password'
        Set-ItemProperty `
            -Path RC:\ClusterKey `
            -Name CentrallyManagedPassword `
            -Value $clusterKey.CentrallyManagedPassword

        Write-Verbose 'Configuring cluster web site'
        Set-ItemProperty `
            -Path RC:\ClusterWebSite `
            -Name WebSiteName `
            -Value 'Default Web Site'

        Write-Verbose 'Configuring the cluster address'
        Set-ItemProperty `
            -Path RC:\ `
            -Name ClusterURL `
            -Value $clusterUrl

        Write-Verbose 'Configuring the server certificate'
        Set-ItemProperty `
            -Path RC:\SSLCertificateSupport `
            -Name SSLCertificateOption `
            -Value Existing
        Set-ItemProperty `
            -Path RC:\SSLCertificateSupport `
            -Name Thumbprint `
            -Value $certificate.Thumbprint

        Write-Verbose 'Configuring the Server Licensor Certificate display name'
        Set-ItemProperty -Path RC:\ -Name SLCName -Value $sLCName

        Write-Verbose 'Configuring SCP registration'
        Set-ItemProperty -Path RC:\ -Name RegisterSCP -Value $true

        Write-Verbose 'Installing the root cluster'
        Install-ADRMS -Path RC:\ -Force
        Write-Host @"
To continue with the configuration, you must sign out and sign in again.
After signing in, please run $($MyInvocation.MyCommand) again.
"@
        Read-Host 'Press Enter to sign out now'
        logoff
        exit
    }
}

Remove-PSDrive $adrmsCluster -Force

#endregion Task 6: Create the RMS cluster

#region Task 7: Request a web server certificate

Write-Host '        Task 7: Request a web server certificate'

$computerName = $env:COMPUTERNAME
$dnsName = @(
    "$rmsClusterName.$domain"
    $rmsclusterName
    "$($computerName).$domain"
    $computerName
)


$certificate = Get-ComputerCertificate `
    -SubjectName "cn=$rmsClusterName.$domain" `
    -DnsName $dnsName `
    -ComputerName $computerName

#endregion Task 7: Request a web server certificate

#region Task 8: Expand the RMS cluster

Write-Host '        Task 8: Expand the RMS cluster'

Write-Verbose 'Trying to find AD RMS cluster'
    
Import-Module ADRMSAdmin

$computerName = $rmsClusterNode[0]
$adrmsCluster = New-PSDrive `
    -Name RMS `
    -PSProvider AdRmsAdmin `
    -Root "https://$computerName" `
    -ErrorAction SilentlyContinue `
    -Force

if (Get-ChildItem $adrmsCluster.Root) {
    Write-Verbose 'Cluster found, getting database information'

    $clusterDatabase = @{
        ServerName = (
            Get-ItemProperty `
                -Path $adrmsCluster.Root `
                -Name ConfigurationDatabaseServer
        ).Value

        DatabaseName = (
            Get-ItemProperty `
                -Path $adrmsCluster.Root `
                -Name ConfigurationDatabaseName
        ).Value
    }

    for ($i = 1; $i -lt $rmsClusterNode.Count; $i++) {
        $computerName = $rmsClusterNode[$i]
        if ($computerName -ne $env:COMPUTERNAME) {
            Write-Warning @"
RMS cluster cannot be expanded!
Please run $PSCommandPath on $($computerName).
"@
        }
        if ($computerName -eq $env:COMPUTERNAME) {

            Import-Module ADRMS
            $adrmsInstall = New-PSDrive -PSProvider ADRMSInstall -Name JC -Root JoinCluster

            Write-Verbose 'Configuring database server'
            Set-ItemProperty `
                �Path "$($adrmsInstall.Name):\ClusterDatabase" `
                -Name ServerName `
                -Value $clusterDatabase.ServerName
            Set-ItemProperty `
                �Path "$($adrmsInstall.Name):\ClusterDatabase" `
                -Name DatabaseName `
                -Value $clusterDatabase.DatabaseName

            Write-Verbose 'Configuring cluster key password'
            Set-ItemProperty `
                -Path "$($adrmsInstall.Name):\ClusterKey" `
                -Name CentrallyManagedPassword `
                -Value $clusterKey.CentrallyManagedPassword

            [PSCredential] $serviceAccount = New-Object `
                -Typename System.Management.Automation.PSCredential `
                -ArgumentList `
                    $serviceAccountName, $serviceAccountPassword

            Write-Verbose 'Configuring service account'
            Set-ItemProperty `
                -Path "$($adrmsInstall.Name):\" `
                -Name ServiceAccount -Value $serviceAccount

            Write-Verbose 'Configuring the server certificate'
            Set-ItemProperty `
                -Path "$($adrmsInstall.Name):\SSLCertificateSupport" `
                -Name SSLCertificateOption `
                -Value Existing
            Set-ItemProperty `
                -Path "$($adrmsInstall.Name):\SSLCertificateSupport" `
                -Name Thumbprint `
                -Value $certificate.Thumbprint

            Write-Verbose "Joining $computerName to the cluster"
            Install-ADRMS -Path "$($adrmsInstall.Name):\" -Force
            Remove-PSDrive $adrmsInstall -Force

            Write-Host @"
To continue with the configuration, you must sign out and sign in again.
After signing in, please run $($MyInvocation.MyCommand) again.
"@
            Read-Host 'Press Enter to sign out now'
            logoff
            exit

        }
    }
}
Remove-PSDrive $adrmsCluster -Force

#endregion Task 8: Expand the RMS cluster

#endregion Exercise 1: Create an Active Directory Rights Management Cluster

#region Exercise 2: Configure Active Directory Rights Management

Write-Host '    Exercise 2: Configure Active Directory Rights Management'

$computerName = $rmsClusterNode[0]
$session = New-PSSession -ComputerName $computername

#region Task 1: Configure the extranet URLs

$extranet = 'https://rms.adatum.com'

Write-Host '        Task 1: Configure the extranet URLs'

Write-Verbose `
    'Set the extranet certification URL and the extranet licensing URL'
Invoke-Command -Session $session -ScriptBlock {
    Import-Module AdRmsAdmin
    $adrmsCluster = New-PSDrive `
        -PSProvider AdRmsAdmin `
        -Name RMS `
        -Root "https://$($using:rmsClusterNode[0])" `
        -ErrorAction SilentlyContinue `
        -Force

    if (-not (Get-ChildItem $adrmsCluster.Root)) {
        Write-Warning @'
    The RMS cluster was not found. Extranet URLs cannot be configured.
'@
    }

    if (Get-ChildItem $adrmsCluster.Root) {
        $path = $adrmsCluster.Root
        try {
            Set-ItemProperty `
                -Path $path `
                -Name ExtranetCertificationUrl `
                -Value "$extranet/_wmcs/certification/certification.asmx" `
                -ErrorAction Stop
            Set-ItemProperty `
                -Path $path `
                -Name ExtranetLicensingUrl `
                -Value "$extranet/_wmcs/licensing" `
                -ErrorAction Stop
        }
        catch {
            Write-Warning @'
The extranet certification URL could not be set.
Probably the URLs cannot be validated.
Outside of a lab environment, you should configure them using the GUI.
'@
        }
    }
    Remove-PSDrive -Name RMS -Force
}


#endregion Task 1: Configure the extranet URLs

#region Task 2: Backup the Server Licensor Certificate

Write-Host '        Task 2: Backup the Server Licensor Certificate'


$path = Invoke-Command -Session $session -ScriptBlock {
    Import-Module AdRmsAdmin
    $adrmsCluster = New-PSDrive `
        -PSProvider AdRmsAdmin `
        -Name RMS `
        -Root "https://$($using:rmsClusterNode[0])" `
        -ErrorAction SilentlyContinue `
        -Force
    
    if (-not (Get-ChildItem $adrmsCluster.Root)) {
        # emit $null to indicate that no certificate was exported
        $null
    }

    if (Get-ChildItem $adrmsCluster.Root) {
        $savedFile = "c:\$using:sLCName.xml"
        Write-Verbose "Getting certificate $($using:sLCName)"
        $tpd = Get-ChildItem RMS:\TrustPolicy\TrustedPublishingDomain\ |
            Where-Object { $PSItem.DisplayName -eq $using:sLCName }
        
        $password = ConvertTo-SecureString `
            -String 'Pa$$w0rd' `
            -AsPlainText `
            -Force

        Write-Verbose "Exporting certificate $($tps.Id) to $savedFile"
        Export-RmsTPD `
            -Path "$($adrmsCluster.Root)\TrustPolicy\TrustedPublishingDomain\$($tpd.Id)" `
            -SavedFile $savedFile `
            -Password $password `
            -Force
        
        # Emit the export path
        $savedFile
    }
    Remove-PSDrive $adrmsCluster -Force
}

if (-not $path) {
    Write-Warning 'The server licensor certificate could not be exported.'
}

if ($path) {
    $destination = '\\VN1-SRV10\IT\'

    Write-Verbose "Copying $path to $destination"

    Copy-Item -Path $path -Destination $destination -FromSession $session

    Write-Verbose "Removing $path"

    Invoke-Command -Session $session -ScriptBlock {
        Remove-Item -Path $using:path
    }
}

#endregion Task 2: Backup the Server Licensor Certificate

#region Task 3: Create a rights policy template

Write-Host '        Task 3: Create a rights policy template'

$rightsPolicyTemplate = Invoke-Command -Session $session -ScriptBlock {
    Import-Module AdRmsAdmin
    $adrmsCluster = New-PSDrive `
        -PSProvider AdRmsAdmin `
        -Name RMS `
        -Root "https://$($using:rmsClusterNode[0])" `
        -ErrorAction SilentlyContinue `
        -Force

    if (Get-ChildItem $adrmsCluster.Root) {
        $path = "$($adrmsCluster.Root)\RightsPolicyTemplate"
        $displayName = 'Research'
        Write-Verbose "Getting righs policy template $displayName"
        $rightsPolicyTemplate = Get-ChildItem -Path $path | 
            Where-Object { $PSItem.DefaultDisplayName -eq $displayName }
        if (-not $rightsPolicyTemplate) {
            New-Item `
                -Path RMS:\RightsPolicyTemplate\ `
                -LocaleName 'en-us' `
                -DisplayName $displayName `
                -Description 'Grants access to members of Research' `
                -UserGroup 'research@adatum.com' `
                -Right ('Edit', 'Reply', 'ReplyAll') `
                -UseLicenseExpiredInDays 7
            $rightsPolicyTemplate = Get-ChildItem -Path $path | 
                Where-Object { $PSItem.DefaultDisplayName -eq $displayName }
        }
    }
    Remove-PSDrive -Name RMS -Force
    # emit template
    $rightsPolicyTemplate
}

if (-not $rightsPolicyTemplate) {
            Write-Warning @'
The rights policy template was not found and could not be created.
Probably the RMS cluster was not created yet.
'@
}

#endregion Task 3: Create a rights policy template

Remove-PSSession $session

#endregion Exercise 2: Configure Active Directory Rights Management