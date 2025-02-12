$path = 'c:\Logs'
$filePath = Join-Path -Path $path -ChildPath 'Policies.log'

if (-not (Test-Path $path)) {
    New-Item -Path $path -ItemType Directory | Out-Null
}

do {
    $policies = Get-ChildItem -Path '\\ad.adatum.com\SYSVOL\ad.adatum.com\Policies'
    
    Write-Output "[$(Get-Date -Format o)] GPOs: $($policies -join ', ')" |
    Out-File -FilePath $filePath -Append
    
    Start-Sleep -Seconds 30
} while (
    $true
)