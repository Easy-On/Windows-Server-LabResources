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

function Wait-WSMan {
    [CmdletBinding(PositionalBinding = $false)]
    param (
        [Parameter(Position = 0)]
        [string]
        $ComputerName,
        [ValidateSet(
            'Basic', 
            'ClientCertificate', 
            'Credssp',
            'Default',
            'Digest',
            'Kerberos',
            'Negotiate',
            'None'
        )]
        [string]
        $Authentication,
        [int32]
        $Port,
        [switch]
        $UseSSL,
        [string]
        $ApplicationName,
        [pscredential]
        $Credential,
        [String]
        $CertificateThumbprint,
        [Int32]
        $Timeout,
        [Int16]
        $Delay = 5
    )
    $parameters = $PSBoundParameters
    $null = $parameters.Remove('Timeout')
    $null = $parameters.Remove('Delay')
    $start = (Get-Date)
    while (
        -not (Test-WSMan @parameters -ErrorAction SilentlyContinue)
    ) {
        if ($Timeout -and $start.AddSeconds($Timeout) -lt (Get-Date)) {
            break
        }
        Start-Sleep $Delay
    }
    # Repeat test, in case we got an error

    $null = Test-WSMan @parameters
}

function Import-WACConfigModule {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]
        $Session
    )
    Write-Verbose 'Importing the Windows Admin Center Configuration module'
    Invoke-Command -Session $Session -ScriptBlock {
        Import-Module 'C:\Program Files\WindowsAdminCenter\PowerShellModules\Microsoft.WindowsAdminCenter.Configuration\Microsoft.WindowsAdminCenter.Configuration.psd1'
    }
}

Write-Host 'Practice: Install Windows Admin Center using a Script'

#region Parameters
$computerName = 'VN1-SRV4'

# Zone and host name for the admin center web site

$zoneName = 'ad.adatum.com'
$hostName = 'admincenter'

# Certificate template for admin center
$template = 'WebServer'

#endregion Parameters

# Download Windows Admin Center

$destination = 'C:\LabResources\WindowsAdminCenter.exe'

Write-Verbose "Downloading Windows Admin Center to $destination"

$session = New-PSSession -ComputerName $computerName

$bitsTransfer = Invoke-Command -Session $session -ScriptBlock {
    if (-not (Test-Path($using:destination))) {
        Start-BitsTransfer `
            -Source 'https://aka.ms/WACDownload' `
            -Destination $using:destination `
            -Asynchronous `
            -RetryTimeout (10 * 60)
    }

}

#region Install PowerShell module for Active Directory

$productType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType

# Check for Workstation
if ($productType -eq 1) {
    $names = 'Rsat.ActiveDirectory.DS-LDS.Tools*', 'Rsat.Dns.Tools*'
    $restartNeeded = $false
    $names | ForEach-Object {
        $windowsCapability = Get-WindowsCapability -Online -Name $PSItem
        if ($windowsCapability.State -ne 'Installed') {
            $restartNeeded = $restartNeeded -or (
                $windowsCapability | Add-WindowsCapability -Online
            ).RestartNeeded
        } 
    }
}

# Check for Server
if ($productType -ne 1) {
    $name = 'RSAT-AD-PowerShell', 'RSAT-DNS-Server'
    $featureOperationResult = `
        Get-WindowsFeature -Name $name |
        Where-Object { $PSItem.InstallState -ne 'Installed' } |
        Install-WindowsFeature

    $restartNeeded = $featureOperationResult.Success -and `
        $featureOperationResult.RestartNeeded -eq 'Yes'
    
    if (-not $featureOperationResult.Success) {
        Write-Warning "Feature $name could not be installed. Aborting."
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

#endregion Install PowerShell module for Active Directory

# Get the AD computer object and install required features if required

Write-Verbose "Getting the computer object of $computerName"
$aDComputer = Get-ADComputer $computerName

#region Get certificate

#region Try to find the certificate

$subjectName = "CN=$hostname.$zoneName"

Write-Verbose "Getting the certificate for $subjectName"

$certificate = Invoke-Command -Session $session -ScriptBlock {
    $now = Get-Date
    Get-ChildItem 'Cert:\LocalMachine\My' | 
    Where-Object { 
        $PSItem.Subject -eq $using:subjectName `
        -and $now -gt $PSItem.NotBefore `
        -and $now -lt $PSItem.NotAfter `
    } | 
    Sort-Object NotAfter -Descending | Select-Object -First 1
}

#endregion Try to find the certificate

# Request certificate if required

if ($null -eq $certificate) {

    Write-Verbose "Certificate not found."

    #region Grant the admin center computer Enroll permissions to the template

    Write-Verbose `
        "Granting permissions for certificate template Web Server to $computerName"

    # GUID for the extended AD right to enroll certificates
    $extendedRightCertificateEnrollment = `
        [GUID]'0e10c968-78fb-11d2-90d4-00c04f79dc55'

    $configurationNamingContext = `
        (Get-Item -Path 'AD:\').configurationNamingContext

    # Path to the certificate template
    $path = `
        "AD:\CN=$template,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configurationNamingContext"

    $acl = Get-Acl -Path $path
    $accessRule = New-Object `
        -TypeName System.DirectoryServices.ActiveDirectoryAccessRule `
        -ArgumentList `
            $aDComputer.SID, `
            'GenericRead,ExtendedRight', `
            'Allow', `
            $extendedRightCertificateEnrollment
    $acl.AddAccessRule($accessRule)
    Set-Acl -Path $path -AclObject $acl

    #endregion Grant the admin center computer Enroll permissions to the template

    <# 
        Certificates cannot be requested using PowerShell remoting.
        Therefore, we must check, if we are on the local computer.
    #>

    # If $computerName is an FQDN, extract the first segment

    $computerHostName = ($computerName -split '\.')[0]

    # If not called locally on WAC gateway, display error message box

    if ($computerHostName -ne $env:COMPUTERNAME) {

        Write-Warning @"
Certificate cannot be requested!
Please run $($MyInvocation.MyCommand) on $computerName.
Windows Admin Center was not installed.
"@
    }

    # Request certificate, if everything is okay

    if ($computerHostName -eq $env:COMPUTERNAME) {
        $dnsName = $hostName, "$hostname.$zoneName"

        # Refresh group policies to ensure, the root CA certificate is installed

        Write-Verbose 'Refreshing group policies.'

        gpupdate.exe /force | Out-Null

        Write-Verbose @"
Requesting certificate using the template $template 
with the subject name $subjectName and the DNS name $dnsName
"@

        $certificate = (
            Get-Certificate `
                -Template $template `
                -SubjectName $subjectName `
                -DnsName $dnsName `
                -CertStoreLocation 'Cert:\LocalMachine\My'
            ).Certificate
    }
}


#endregion Get certificate

# Configure SSO

Write-Verbose `
    "Allowing $($adComputer.Name) to delegate to all computers in the domain"

Get-ADComputer -Filter * | 
Set-ADComputer -PrincipalsAllowedToDelegateToAccount $aDComputer    

#region Add DNS record
$cimSession = New-CimSession -ComputerName $computerName

Write-Verbose "Getting the IP address of $computerName."

$ipAddress = (
    Get-DnsClient -CimSession $cimSession | 
    Where-Object { $PSItem.RegisterThisConnectionsAddress } | 
    Get-NetIPAddress -CimSession $cimSession -AddressFamily IPv4 | Where-Object { 
        $PSItem.PrefixOrigin -ne 'WellKnown' `
        -and $PSItem.IPAddress -notlike '169.254.*' `
        -and -not $PSItem.SkipAsSource
    }
).IPAddress

Remove-CimSession $cimSession

Write-Verbose "Got $ipAddress."

# Find authoritative DNS server for zone
$dnsServer = (Resolve-DnsName -Name ad.adatum.com -Type SOA).PrimaryServer

if (
    $null -eq (
        Get-DnsServerResourceRecord `
            -Name $hostname `
            -ZoneName $zoneName `
            -RRType A `
            -ErrorAction SilentlyContinue `
            -ComputerName $dnsServer
    )
) {
    Write-Verbose "Creating an A record for $hostname pointing to $ipAddress"
    Add-DnsServerResourceRecordA `
        -ZoneName $zoneName `
        -Name $hostname `
        -IPv4Address $ipAddress `
        -ComputerName $dnsServer
}

#endregion Add DNS record

# Complete the download

if ($null -ne $bitsTransfer) {
    $jobId = $bitsTransfer.JobId
    $seconds = 60
    
    while (
        $bitsTransfer.JobState `
        -notin @('Transferred', 'Cancelled', 'Error')
    ) {
        Write-Verbose @"
BITS transfer current state is $($bitsTransfer.JobState). Waiting $seconds seconds for completion.
"@
        $bitsTransfer = Invoke-Command -Session $session -ScriptBlock {
            Get-BitsTransfer -JobId $using:jobId
        }
        Start-Sleep -Seconds $seconds
    }
    Invoke-Command -Session $session -ScriptBlock {
        Get-BitsTransfer -JobId $using:jobId | Complete-BitsTransfer
    }
}

# Check for installed Windows Admin Center

$package = Invoke-Command -Session $session {
    Get-Package -Name 'Windows Admin Center (v2)' -ErrorAction SilentlyContinue
}

if ($null -eq $package) {
    # Install Windows Admin Center binaries

    $downloadSucceeded = Invoke-Command -Session $session {
        Test-Path($using:destination)
    }
    if (-not $downloadSucceeded) {
        Write-Warning `
            'Windows Admin Center could not be downloaded and will not be installed.'
    }

    if ($downloadSucceeded) {

        <#
            Because installation of Windows Admin Center apparently restarts
            WinRM, the command ends with an error message, despite the
            installation succeeded.

            To work around this issue, we invoke the command as background job
            using the -AsJob parameter. The job still has State Failed, but
            it does not post an error message to the console. As a side effect,
            the script finishes a bit faster.
        #>

        Write-Verbose "Starting setup of Windows Admin Center from $destination"
        $job = Invoke-Command -Session $session -AsJob -ScriptBlock {
            if (Test-Path($using:destination)) {
                Start-Process `
                    -FilePath $using:destination `
                    -ArgumentList `
                        '/VERYSILENT', `
                        '/LOG=C:\WAC-install.log' `
                    -Wait
            }
        }

        $null = $job | Wait-Job
    }
}

Wait-WSMan -ComputerName $computerName -Authentication Default -Timeout 300

$session = New-PSSession -ComputerName $computerName
Import-WACConfigModule -Session $session

# Write-Verbose 'Setting the WAC login mode to Windows Authentication'
# Invoke-Command -Session $session -ScriptBlock {
#     Set-WACLoginMode -Mode WindowsAuthentication
# }

Write-Verbose 'Retrieving the WAC certificate subject name'
$wacCertificateSubjectName = Invoke-Command -Session $session -ScriptBlock {
    Get-WACCertificateSubjectName
}

if ($wacCertificateSubjectName -ne $subjectName -and $null -ne $certificate) {
    Write-Verbose 'Configuring the Windows Admin Center certificate.'

    $thumbprint = $certificate.Thumbprint
    Invoke-Command -Session $session -ScriptBlock {
        Remove-WACSelfSignedCertificate
        Set-WACCertificateSubjectName `
            -SubjectName $using:subjectName `
            -Thumbprint $using:thumbprint `
            -Target All
        Set-WACCertificateAcl -SubjectName $using:subjectName
    }
}

Write-Verbose 'Setting the WAC endpoint FQDN'
Invoke-Command -Session $session -ScriptBlock {
    $fqdn = "$($using:hostName).$($using:zoneName)"
    Set-WACEndpointFqdn -EndpointFqdn $fqdn
}

Write-Verbose 'Checking the local CredSSP'
$wacLocalCredSSP = Invoke-Command -Session $session -ScriptBlock {
    Get-WacLocalCredSSP -ErrorAction SilentlyContinue
}

if ($null -eq $wacLocalCredSSP) {
    Write-Verbose 'Register the local CredSSP'
    Invoke-Command -Session $session -ScriptBlock {
        Register-WACLocalCredSSP
    }
}

Wait-WSMan -ComputerName $computerName -Authentication Default -Timeout 300

$session = New-PSSession -ComputerName $computerName
Import-WACConfigModule -Session $session

Write-Verbose 'Initializing the the WAC database'
Invoke-Command -Session $session -ScriptBlock {
    Initialize-WACDatabase
}

Write-Verbose 'Setting the WAC service security descriptor'
Invoke-Command -Session $session -ScriptBlock {
    Set-WACServiceSecurityDescriptor
}

Write-Verbose 'Starting the Windows Admin Center service.'

Invoke-Command -Session $session -ScriptBlock {
    Start-WACService
}


Remove-PSSession $session
