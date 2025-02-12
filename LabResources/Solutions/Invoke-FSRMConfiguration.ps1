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

. (Join-Path -Path $PSScriptRoot -ChildPath 'New-UsersShare.ps1')


#endregion Prerequisites

$session = New-PSSession -ComputerName 'VN1-SRV10'

Write-Host 'Lab: File server resource management'

# Remove all file screens to avoid errors during copy operations

Invoke-Command -Session $session -ScriptBlock {
    Get-FsrmFileScreen | Remove-FsrmFileScreen -Confirm:$false
} 

#region Exercise 1: Manage quotas

Write-Host '    Exercise 1: Manage quotas'

#region Task 1: Create quota templates

Write-Host '        Task 1: Create quota templates'

$subject = '[Quota Threshold]% quota threshold exceeded'

$body = @"
User [Source Io Owner] has exceed the [Quota Threshold]% quota threshold for quota on [Quota Path] on server [Server].
The quota limit is [Quota Limit MB] MB and the current usage is [Quota Used MB] MB ([Quota Used Percent]% of limit).'
"@

$actionNearLimit = @(
    (
        Invoke-Command -Session $session -ScriptBlock {
            New-FsrmAction `
                -Type Email `
                -MailTo '[Source Io Owner Email]' `
                -Subject $using:subject -Body $using:body
        }
    )
    (
        Invoke-Command -Session $session -ScriptBlock {
            New-FsrmAction -Type Event -EventType Warning -Body $using:body
        }
    )        
)

$actionExceededLimit = @(
    (
        Invoke-Command -Session $session -ScriptBlock {
            New-FsrmAction `
                -Type Email `
                -MailTo '[Admin Email], [Source Io Owner Email]' `
                -Subject $subject -Body $using:body
        }
    )
    (
        Invoke-Command -Session $session -ScriptBlock {
            New-FsrmAction -Type Event -EventType Warning -Body $using:body
        }
    )
)

$threshold = @(
    (
        Invoke-Command -Session $session -ScriptBlock {
            New-FsrmQuotaThreshold -Percentage 85 -Action $using:actionNearLimit
        }
    )
    (
        Invoke-Command -Session $session -ScriptBlock {
            New-FsrmQuotaThreshold -Percentage 95 -Action $using:actionNearLimit
        }
    )
    (
        Invoke-Command -Session $session -ScriptBlock {
            New-FsrmQuotaThreshold `
                -Percentage 100 `
                -Action $using:actionExceededLimit
        }
    )
)

$quotaTemplateName75MB = '75 MB Limit'

$quotaTemplate75MB = Invoke-Command -Session $session -ScriptBlock {
    Get-FsrmQuotaTemplate `
        -Name $using:quotaTemplateName75MB `
        -ErrorAction SilentlyContinue
}
 
if ($null -eq $quotaTemplate75MB) {
    $quotaTemplate75MB = Invoke-Command -Session $session -ScriptBlock {
        New-FsrmQuotaTemplate `
            -Name $using:quotaTemplateName75MB `
            -Size 75MB `
            -Threshold $using:threshold
    } 
}

if ($null -ne $quotaTemplate75MB) {
    Invoke-Command -Session $session -ScriptBlock {
        Set-FsrmQuotaTemplate `
            -Name $using:quotaTemplateName75MB `
            -Size 75MB `
            -Threshold $using:threshold
    }
}

$quotaTemplate = Invoke-Command -Session $session -ScriptBlock {
    Get-FsrmQuotaTemplate -Name '200 MB Limit with 50 MB Extension'
} 


$threshold = $quotaTemplate.Threshold

$action = ($threshold | Where-Object { $PSItem.Percentage -eq 100 }).Action

(
    $action | 
    Where-Object { 
        $PSItem.Command -eq '%windir%\system32\dirquota.exe' 
    }
).CommandParameters = `
    "quota modify /path:[Quota Path] /sourcetemplate:`"$quotaTemplateName75MB`""

$quotaTemplateName50MB = '50 MB Limit with 25 MB Extension'

$quotaTemplate50MB = Invoke-Command -Session $session -ScriptBlock {
    Get-FsrmQuotaTemplate `
        -Name $using:quotaTemplateName50MB `
        -ErrorAction SilentlyContinue
}
 
if ($null -eq $quotaTemplate50MB) {
    $null = Invoke-Command -Session $session -ScriptBlock {
        New-FsrmQuotaTemplate `
            -Name $using:quotaTemplateName50MB `
            -Size 50MB `
            -Threshold $using:threshold
    }
}

if ($null -ne $quotaTemplate50MB) {
    Invoke-Command -Session $session -ScriptBlock {
        Set-FsrmQuotaTemplate `
            -Name $using:quotaTemplateName50MB `
            -Size 50MB `
            -Threshold $using:threshold
    }
}

#endregion Task 1: Create quota templates

#region Task 2: Apply quotas

Write-Host '        Task 2: Apply quotas'

$quotaPath = 'D:\Shares\IT'
$autoQuotaPath = 'D:\Shares\Users'

$quota = Invoke-Command -Session $session -ScriptBlock {
    Get-FsrmQuota -Path $using:quotaPath -ErrorAction SilentlyContinue
}

if ($null -eq $quota) {
    $null = Invoke-Command -Session $session -ScriptBlock {
        New-FSRMQuota `
            -Path $using:quotaPath `
            -Template $using:quotaTemplateName75MB
    }
}

$autoQuota = Invoke-Command -Session $session -ScriptBlock {
    Get-FsrmAutoQuota -Path $using:autoQuotaPath -ErrorAction SilentlyContinue
}

if ($null -eq $autoQuota) {
    $null = Invoke-Command -Session $session -ScriptBlock {
        New-FsrmAutoQuota `
            -Path $using:autoQuotaPath `
            -Template $using:quotaTemplateName50MB
    }
}

#endregion Task 2: Apply quotas


#region Task 3: Verify the effects of quotas

Write-Host '        Task 3: Verify the effects of quotas'

$path = '\\VN1-SRV10\Users\User11'
    
if (-not (Test-Path -Path $path)) {
    $null = New-Item -ItemType Directory -Path $path
}

Copy-Item `
    -Path \\VN1-SRV10\IT\* `
    -Destination \\VN1-SRV10\Users\User1 `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue
Copy-Item `
    -Path \\VN1-SRV10\IT\* `
    -Destination \\VN1-SRV10\Users\User1 `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

Copy-Item `
    -Path '\\VN1-SRV10\c$\LabResources\Sample Documents\Travel Packages\' `
    -Destination \\VN1-SRV10\Users\User1 `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

Invoke-Command -Session $session -ScriptBlock {
    Set-FSRMQuota -Path D:\Shares\Users\User1\ -Size 100MB
}

Copy-Item `
    -Path '\\VN1-SRV10\c$\LabResources\Sample Documents\Travel Packages\' `
    -Destination \\VN1-SRV10\Users\User1 `
    -Recurse `
    -Force `
    -ErrorAction SilentlyContinue

#endregion Task 3: Verify the effects of quotas

#endregion Exercise 1: Manage quotas

#region Exercise 2: Manage file screening

Write-Host '    Exercise 2: Manage file screening'

#region Task 1: Create a file screen

Write-Host '        Task 1: Create a file screen'

$path =  'd:\'
if (
    $null -eq (
        Invoke-Command -Session $session -ScriptBlock {
            Get-FsrmFileScreen -Path $using:path -ErrorAction SilentlyContinue
        }
    )
) {
    $null = Invoke-Command -Session $session -ScriptBlock {
        New-FsrmFileScreen `
            -Path $using:path `
            -Template 'Block Executable Files'
    } 
}

$path = 'D:\Shares\IT'
if (
    $null -eq (
        Invoke-Command -Session $session -ScriptBlock {
            Get-FsrmFileScreenException `
                -Path $using:path `
                -ErrorAction SilentlyContinue
        }        
    )
) {
    $null = Invoke-Command -Session $session -ScriptBlock {
        New-FsrmFileScreenException `
            -Path $using:path `
            -IncludeGroup 'Executable Files'
    }
}
#endregion Task 1: Create a file screen

#endregion Exercise 2: Manage file screening

#region Exercise 3: Use folder management properties

Write-Host '    Exercise 3: Use folder management properties'

#region Task 1: Add a value to the Folder Usage property

Write-Host '        Task 1: Add a value to the Folder Usage property'

$name = 'Setup Files'
$propertyDefinition = Invoke-Command -Session $session -ScriptBlock {
    Get-FsrmClassificationPropertyDefinition -Name 'FolderUsage_MS'

}

if ($propertyDefinition.PossibleValue.Name -notcontains $name) {
    $propertyDefinition.PossibleValue += `
        Invoke-Command -Session $session -ScriptBlock {
            New-FsrmClassificationPropertyValue -Name $using:name
    }

    $propertyDefinition | Invoke-Command -Session $session -ScriptBlock {
        Set-FsrmClassificationPropertyDefinition `
            -PossibleValue $using:propertyDefinition.PossibleValue
    }
}

#endregion Task 1: Add a value to the Folder Usage property

#region Task 2: Set the Folder Usage property

Write-Host '        Task 2: Set the Folder Usage property'

Invoke-Command -Session $session -ScriptBlock {
    Set-FsrmMgmtProperty `
        -Namespace 'D:\Shares\Users' `
        -Name 'FolderUsage_MS' `
        -Value 'User Files'
}


'D:\Shares\Finance\', 'D:\Shares\IT\', 'D:\Shares\Marketing\' | 
ForEach-Object { 
    $namespace = $PSItem
    Invoke-Command -Session $session -ScriptBlock {
        Set-FsrmMgmtProperty `
            -Namespace $using:namespace `
            -Name 'FolderUsage_MS' `
            -Value 'Group Files'
    }
}

#endregion Task 2: Set the Folder Usage property

#region Task 3: Create an Access Denied Assistance Message for a folder

Write-Host '        Task 3: Create an Access Denied Assistance Message for a folder'

Invoke-Command -Session $session -ScriptBlock {
    Set-FsrmMgmtProperty `
        -Namespace 'D:\Shares\Finance' `
        -Name 'AccessDeniedMessage_MS' `
        -Value @'
Access to finance data is restricted.
Please contact the finance manager to gain access.
'@
}

#endregion Task 3: Create an Access Denied Assistance Message for a folder

#endregion Exercise 3: Use folder management properties

#region Exercise 4: Manage classification

Write-Host '    Exercise 4: Manage classification'

#region Task 1: Add a local property

Write-Host '        Task 1: Add a local property'

$possibleValue = `
    'Confidential', 'PII', 'Secret' | 
    ForEach-Object {
        $name = $PSItem    
        Invoke-Command -Session $session -ScriptBlock {
            New-FsrmClassificationPropertyValue -Name $using:name
        }
    }

$name = 'Confidentiality'

$classificationPropertyDefinition = `
    Invoke-Command -Session $session -ScriptBlock {
        Get-FsrmClassificationPropertyDefinition `
            -Name $using:name `
            -ErrorAction SilentlyContinue
    }

if ($null -eq $classificationPropertyDefinition) {
    $null = Invoke-Command -Session $session -ScriptBlock {
        New-FsrmClassificationPropertyDefinition `
            -Name $using:name `
            -Type SingleChoice `
            -PossibleValue $using:possibleValue
    }
}

if ($null -ne $classificationPropertyDefinition) {
    Invoke-Command -Session $session -ScriptBlock {
        Set-FsrmClassificationPropertyDefinition `
            -Name $using:name `
            -PossibleValue $possibleValue
    }
}

#endregion Task 1: Add a local property

#region Task 2: Create classification rules

Write-Host '        Task 2: Create classification rules'

$classificationRules = @(
    @{
        Name = 'On payroll set confidentiality to PII'
        PropertyValue = 'PII'
        ContentString = 'payroll'
    }
    @{
        Name = 'On vertraulich set conficentiality to confidential'
        PropertyValue = 'Confidential'
        ContentString = 'vertraulich'
    }
    @{
        Name = 'On tax set confidentiality to secret'
        PropertyValue = 'Secret'
        ContentString = 'tax'
    }
)

$classificationRules | ForEach-Object {
    $item = $PSItem
    $classificationRule = Invoke-Command -Session $session -ScriptBlock {
        Get-FsrmClassificationRule `
            -Name $using:item.Name `
            -ErrorAction SilentlyContinue

    }

    if ($null -eq $classificationRule) {
        $null = Invoke-Command -Session $session -ScriptBlock {
            New-FsrmClassificationRule `
                -Name $using:item.Name `
                -Namespace @(
                    '[FolderUsage_MS=User Files]'
                    '[FolderUsage_MS=Group Files]'
                ) `
                -ClassificationMechanism 'Content Classifier' `
                -Property 'Confidentiality' `
                -PropertyValue $using:item.PropertyValue `
                -ContentString $using:item.ContentString
        }
    }
    if ($null -ne $classificationRule) {
        Invoke-Command -Session $session -ScriptBlock {
            Set-FsrmClassificationRule `
                -Name $using:item.Name `
                -Namespace @(
                    '[FolderUsage_MS=User Files]'
                    '[FolderUsage_MS=Group Files]'
                ) `
                -ClassificationMechanism 'Content Classifier' `
                -Property 'Confidentiality' `
                -PropertyValue $using:item.PropertyValue `
                -ContentString $using:item.ContentString
        }
    }
}

#endregion Task 2: Create classification rules

#region Task 3: Run the classification

Write-Host '        Task 3: Run the classification'

if (
    (
        Invoke-Command -Session $session -ScriptBlock { Get-FsrmClassification }
    ).Status -eq 'NotRunning'
) {
    $null = Invoke-Command -Session $session -ScriptBlock {
        Start-FsrmClassification -Confirm:$false
    }
}

#endregion Task 3: Run the classification

#endregion Exercise 4: Manage classification

#region Exercise 5: Create storage reports

Write-Host '    Exercise 5: Create storage reports'

#region Task 1: Schedule a report task

Write-Host '        Task 1: Schedule a report task'

$name = 'All reports'
$schedule = Invoke-Command -Session $session -ScriptBlock {
    New-FsrmScheduledTask -Weekly Monday -Time 07:00:00
}
 

$storageReport = Invoke-Command -Session $session -ScriptBlock {
    Get-FsrmStorageReport -Name $using:name -ErrorAction SilentlyContinue
}

if ($null -eq $storageReport) {
    $null = Invoke-Command -Session $session -ScriptBlock {
        New-FsrmStorageReport `
            -Name $using:name `
            -Namespace @(
                '[FolderUsage_MS=User Files]'
                '[FolderUsage_MS=Group Files]'
            ) `
            -Schedule $using:schedule `
            -ReportFormat DHtml `
            -ReportType `
                DuplicateFiles, `
                FilesByFileGroup, `
                FilesByOwner, `
                FilesByProperty, `
                FileScreenAuditFiles, `
                LargeFiles, `
                LeastRecentlyAccessed, `
                MostRecentlyAccessed, `
                QuotaUsage `
            -PropertyName 'Confidentiality'
    }
}

if ($null -ne $storageReport) {
    Invoke-Command -Session $session -ScriptBlock {
        Set-FsrmStorageReport `
            -Name $using:name `
            -Namespace @(
                '[FolderUsage_MS=User Files]'
                '[FolderUsage_MS=Group Files]'
            ) `
            -Schedule $using:schedule `
            -ReportFormat DHtml `
            -ReportType `
                DuplicateFiles, `
                FilesByFileGroup, `
                FilesByOwner, `
                FilesByProperty, `
                FileScreenAuditFiles, `
                LargeFiles, `
                LeastRecentlyAccessed, `
                MostRecentlyAccessed, `
                QuotaUsage `
            -PropertyName 'Confidentiality' `
    }
}

$null = Invoke-Command -Session $session -ScriptBlock {
    Start-FsrmStorageReport -Name $using:name -Confirm:$false
} 

#endregion Task 1: Schedule a report task

#endregion Exercise 5: Create storage reports

#region Exercise 6: Create a file management task

Write-Host '    Exercise 6: Create a file management task'

#region Task 1: Create a file management task

Write-Host '        Task 1: Create a file management task'

$name = 'Expire files with confidentiality level after 365 days'
$expirationFolder = "\\$computerName\D$\Archive"

if (-not (Test-Path $expirationFolder)) {
    $null = New-Item -Type Directory -Path $expirationFolder
}    

$schedule = Invoke-Command -Session $session -ScriptBlock {
    New-FsrmScheduledTask -Weekly Saturday -Time 07:00:00
}

$action = Invoke-Command -Session $session -ScriptBlock {
    New-FsrmFmjAction -Type Expiration -ExpirationFolder $using:expirationFolder
}

$condition =@(
    (
        Invoke-Command -Session $session -ScriptBlock {
            New-FsrmFmjCondition -Property 'Confidentiality' -Condition Exist
        }
    )
    (
        Invoke-Command -Session $session -ScriptBlock {
            New-FsrmFmjCondition `
                -Property File.DateLastModified `
                -Condition LessThan `
                -Value 'Date.Now'

        }
    )
)

$namespace = @(
    '[FolderUsage_MS=User Files]'
    '[FolderUsage_MS=Group Files]'
)

$fileManagementJob = Invoke-Command -Session $session -ScriptBlock {
    Get-FsrmFileManagementJob -Name $using:name -ErrorAction SilentlyContinue
}

if ($null -eq $fileManagementJob) {
    $null = Invoke-Command -Session $session -ScriptBlock {
        New-FsrmFileManagementJob `
            -Name $using:name `
            -Namespace $using:namespace `
            -Condition $using:condition `
            -Action $using:action `
            -ReportFormat DHtml `
            -ReportLog Information, Error `
            -Schedule $using:schedule
    }
}

if ($null -ne $fileManagementJob) {
    Invoke-Command -Session $session -ScriptBlock {
        Set-FsrmFileManagementJob `
            -Name $using:name `
            -Namespace $using:namespace `
            -Condition $using:condition `
            -Action $using:action `
            -ReportFormat DHtml `
            -ReportLog Information, Error `
            -Schedule $using:schedule
    }
}    

#endregion Task 1: Create a file management task

#region Task 2: Run the file management task

Write-Host '        Task 2: Run the file management task'

$null = Invoke-Command -Session $session -ScriptBlock {
    Start-FsrmFileManagementJob -Name $using:name -Confirm:$false
}

#endregion Task 2: Run the file management task

#endregion Exercise 6: Create a file management task

Remove-PSSession $session