[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [Int64]
    $StartupBytes
)

$vmName = 'WIN-VN1-SRV10'

Write-Host "Changing memory on $vmName to $StartupBytes..."



# Shut down VM if necessary

if ((Get-VM -Name $vmName).State -eq 'Running') {
    Stop-VM -Name $vmName
}

# Configure memory

Set-VMMemory `
    -VMName $vmName `
    -DynamicMemoryEnabled $false `
    -StartupBytes $StartupBytes

# Start VM

Start-VM $vmName