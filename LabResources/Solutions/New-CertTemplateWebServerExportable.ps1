$name = 'WebServerExportable'

$configContext = ([ADSI]'LDAP://RootDSE').ConfigurationNamingContext
$certificateTemplatesDN = `
    "CN=Certificate Templates, CN=Public Key Services, CN=Services, $(
        $configContext
    )"
$rDN = "CN=$name"
$pKiCertificateTemplateDN = "$rdn, $certificateTemplatesDN"

$certificateTemplates = [ADSI]"LDAP://$certificateTemplatesDN"
$pKiCertificateTemplate = [ADSI]"LDAP://$pKiCertificateTemplateDN"

if ($null -eq $pKiCertificateTemplate.distinguishedName) {
    $pKiCertificateTemplate = $certificateTemplates.Create(
        'pKICertificateTemplate', $rDN
    ) 

    $pKiCertificateTemplate.put('distinguishedName', $pKiCertificateTemplateDN) 
    $pKiCertificateTemplate.put('displayName', 'Web Server exportable')
    
    $pKiCertificateTemplate.put('flags', 0x20241)

    $pKiCertificateTemplate.put(
        'msPKI-Certificate-Application-Policy', '1.3.6.1.5.5.7.3.1'
    )
    $pKiCertificateTemplate.put('msPKI-Certificate-Name-Flag', 1)
    $pKiCertificateTemplate.put(
        'msPKI-Cert-Template-OID',
        "1.3.6.1.4.1.311.21.8.2646454.14582145.4540859.6623380.1619955.118.$(
            Get-Random
        ).$(
            Get-Random
        )"
    )
    $pKiCertificateTemplate.put('msPKI-Enrollment-Flag', 0)
    $pKiCertificateTemplate.put('msPKI-Minimal-Key-Size', 2048)
    $pKiCertificateTemplate.put('msPKI-Private-Key-Flag', 0x1010010)
    $pKiCertificateTemplate.put('msPKI-RA-Signature', 0)
    $pKiCertificateTemplate.put('msPKI-Template-Minor-Revision', 2)
    $pKiCertificateTemplate.put('msPKI-Template-Schema-Version', 2)

    $pKiCertificateTemplate.put('pKICriticalExtensions', '2.5.29.15')
    $pKiCertificateTemplate.put(
        'pKIDefaultCSPs', 
        @(
            '1,Microsoft RSA SChannel Cryptographic Provider'
            '2,Microsoft DH SChannel Cryptographic Provider'
        )
    )
    $pKiCertificateTemplate.put('pKIDefaultKeySpec', 1)
    
    [Byte[]] $pkiExpirationPeriod = `
        @(0x00, 0x80, 0x72, 0x0E, 0x5D, 0xC2, 0xFD, 0xFF)
    $pKiCertificateTemplate.put('pKIExpirationPeriod', $pkiExpirationPeriod)
    
    $pKiCertificateTemplate.put('pKIExtendedKeyUsage', '1.3.6.1.5.5.7.3.1')
    
    [byte[]] $pkiKeyusage = @(0xA0, 0x00)
    $pKiCertificateTemplate.put('pKIKeyUsage', $pkiKeyusage)
    
    $pKiCertificateTemplate.put('pKIMaxIssuingDepth', 0)
    
    [Byte[]] $pKIOverlapPeriod = `
        @(0x00, 0x80, 0xA6, 0x0A, 0xFF, 0xDE, 0xFF, 0xFF)
    $pKiCertificateTemplate.put('pKIOverlapPeriod', $pKIOverlapPeriod)
    
    $pKiCertificateTemplate.put('revision', 100)
    
    $pKiCertificateTemplate.SetInfo()
}

$module = Get-Module -Name ADCSAdministration -ListAvailable

if ($null -eq $module) {
    Write-Warning `
        "Please rerun the script on a certification authority. The template $(
            $name
        ) was not added to the CA."
}

if ($null -ne $module) {
    if ($null -eq (Get-CATemplate | Where-Object { $PSItem.Name -eq $name })) {
        Add-CATemplate -Name $name -Force
    }
}