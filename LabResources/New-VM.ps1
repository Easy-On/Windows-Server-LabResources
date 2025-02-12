[CmdletBinding()]
param (
    # The name of the new VM
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Name,
    # Name of switch the VM should connect to
    [Parameter()]
    [string]
    $SwitchName = 'VNet1'
)
Write-Host "Creating $Name..."

$namePrefix = 'WIN-'
$memoryStartupBytes = 1GB
$newVHDSizeBytes = 127GB
$processorCount = 4
$labPath = 'C:\Labs'
$courseLabPath = Join-Path -Path $labPath -ChildPath 'WS2025'
$vMName = $namePrefix + $Name
# $isoFilename = '2022_x64_EN_Eval.iso'
$switchName = $SwitchName

$virtualHardDisksPath = Join-Path `
    -Path $courseLabPath `
    -ChildPath 'VMVirtualHardDisks'
# $iSOPath = Join-Path -Path $labPath -ChildPath 'ISOs'
# $oSISOPath = Join-Path -Path $iSOPath -ChildPath $isoFilename

$newVHDPath = Join-Path -Path $virtualHardDisksPath -ChildPath "$vMName.vhdx"



$vM = New-VM `
    -Name $vMName `
    -Generation 2 `
    -NewVHDPath $newVHDPath `
    -NewVHDSizeBytes $newVHDSizeBytes `
    -SwitchName $switchName `
    -MemoryStartupBytes $memoryStartupBytes

Set-VM `
    -VM $vm `
    -ProcessorCount $processorCount `
    -AutomaticCheckpointsEnabled $false `
    -DynamicMemory
$vMDvdDrive = Add-VMDvdDrive -VMName $vMName -Passthru
Set-VMFirmware -VMName $vMName -FirstBootDevice $vMDvdDrive
