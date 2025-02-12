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

#region Practice: Configure Access-Denied-Assistance

Write-Host 'Practice: Configure Access-Denied-Assistance'



$displayMessage = @'
This can occur if you don't have permission to access the file or folder, or if your computer doesn't meet security policy requirements.

Message from the administrator of the file server:
- Ask your manager if you're in the right security groups
- For troubleshooting information, go to <a href="http://support.microsoft.com">Microsoft Support</a>

If you need more help, click Request assistance.
'@

$emailMessage = @'
For general support, contact: [Provide email address]

For share permissions support, contact: [Provide email address]    
'@

Invoke-Command -ComputerName VN1-SRV10 -ScriptBlock {
    Set-FsrmAdrSetting `
        -Event AccessDenied `
        -Enabled `
        -DisplayMessage $using:displayMessage `
        -AllowRequests `
        -IncludeUserClaims `
        -IncludeDeviceClaims `
        -MailToOwner `
        -MailCcAdmin `
        -EmailMessage $using:emailMessage `
        -EventLog
}

#endregion Practice: Configure Access-Denied-Assistance
