#Requires -Version 5.1
<#
.SYNOPSIS
    Offline BCD repair for a non-booting VM/disk: attach its boot + OS disks to a
    helper machine, rebuild the BCD with bcdboot, and offline the disks again.

.DESCRIPTION
    Disaster-recovery move when a Windows guest won't boot (BCD corruption after a
    failed update, a P2V/V2V, or a disk shuffle). Detach the dead guest's boot disk
    and OS disk in the hypervisor and attach BOTH to a healthy helper VM, then run this
    ON the helper. It:

      1. Identifies the two attached disks (default: auto-picks the two Offline disks,
         smallest = boot, largest = OS; or pass explicit -BootDiskNumber/-OsDiskNumber
         with size guards so the helper's own disks can never be touched).
      2. Onlines them, assigns temporary drive letters, confirms <OS>:\Windows exists.
      3. Dumps the BCD before, runs `bcdboot <OS>:\Windows /s <BOOT>: /f <Firmware>`
         to rewrite the boot files/store, dumps the BCD after.
      4. Removes the temp letters and offlines both disks so they can be reattached to
         the original guest.

    HARD GUARDS: with -BootDiskNumber/-OsDiskNumber, the boot disk must be under
    -MaxBootGB and the OS disk within -OsMinGB..-OsMaxGB, or it aborts, so you cannot
    accidentally bcdboot the helper's own volume.

.PARAMETER BootDiskNumber
    Disk number of the attached boot/system partition disk (small). Optional; if
    omitted, the smaller of the two Offline disks is used.

.PARAMETER OsDiskNumber
    Disk number of the attached OS disk (large). Optional; defaults to the larger
    Offline disk.

.PARAMETER Firmware
    'BIOS' (MBR/legacy) or 'UEFI' (GPT). Default BIOS.

.PARAMETER MaxBootGB
    Upper size bound for the boot disk guard. Default 1.

.PARAMETER OsMinGB / OsMaxGB
    Size window for the OS disk guard. Set these to bracket the known OS disk size.

.EXAMPLE
    .\Repair-OfflineBcd.ps1                                   # auto-detect the 2 offline disks, BIOS
    .\Repair-OfflineBcd.ps1 -BootDiskNumber 2 -OsDiskNumber 3 -OsMinGB 110 -OsMaxGB 125 -Firmware UEFI
#>
[CmdletBinding()]
param(
    [int]$BootDiskNumber = -1,
    [int]$OsDiskNumber = -1,
    [ValidateSet('BIOS','UEFI')][string]$Firmware = 'BIOS',
    [double]$MaxBootGB = 1,
    [double]$OsMinGB = 0,
    [double]$OsMaxGB = 100000
)
$ErrorActionPreference = 'Continue'

Write-Host "== disks ==" -ForegroundColor Cyan
Get-Disk | Format-Table Number,FriendlyName,@{N='GB';E={[math]::Round($_.Size/1GB,1)}},PartitionStyle,OperationalStatus -AutoSize | Out-String | Write-Host

if ($BootDiskNumber -ge 0 -and $OsDiskNumber -ge 0) {
    $bootDisk = Get-Disk -Number $BootDiskNumber
    $osDisk   = Get-Disk -Number $OsDiskNumber
    if ([math]::Round($bootDisk.Size/1GB,1) -gt $MaxBootGB) { Write-Host "GUARD: disk $BootDiskNumber is larger than $MaxBootGB GB - not a boot disk. STOP." -ForegroundColor Red; return }
    $osGB = [math]::Round($osDisk.Size/1GB)
    if ($osGB -lt $OsMinGB -or $osGB -gt $OsMaxGB) { Write-Host "GUARD: disk $OsDiskNumber is ${osGB}GB, outside $OsMinGB..$OsMaxGB. STOP." -ForegroundColor Red; return }
} else {
    $offline = Get-Disk | Where-Object { $_.OperationalStatus -eq 'Offline' } | Sort-Object Size
    if (($offline | Measure-Object).Count -lt 2) { Write-Host "Expected 2 offline disks to auto-detect; found $(($offline|Measure-Object).Count). Pass -BootDiskNumber/-OsDiskNumber. STOP." -ForegroundColor Red; return }
    $bootDisk = $offline[0]; $osDisk = $offline[-1]
    Write-Host ("Auto-detected: bootDisk=#{0} ({1:N1}GB)  osDisk=#{2} ({3:N1}GB)" -f $bootDisk.Number,($bootDisk.Size/1GB),$osDisk.Number,($osDisk.Size/1GB)) -ForegroundColor Yellow
}

foreach ($d in $bootDisk,$osDisk) { Set-Disk -Number $d.Number -IsOffline $false; Set-Disk -Number $d.Number -IsReadOnly $false -ErrorAction SilentlyContinue }
Start-Sleep 4

# assign temp letters
$bp = Get-Partition -DiskNumber $bootDisk.Number | Where-Object { $_.Size -gt 50MB } | Select-Object -First 1
$op = Get-Partition -DiskNumber $osDisk.Number | Sort-Object Size -Descending | Select-Object -First 1
foreach ($pair in @(@($bp,'X'),@($op,'Y'))) {
    $part = $pair[0]; $L = $pair[1]
    if (-not $part.DriveLetter) { $part | Add-PartitionAccessPath -AccessPath "${L}:" -ErrorAction SilentlyContinue }
}
$bp = Get-Partition -DiskNumber $bootDisk.Number | Where-Object { $_.Size -gt 50MB } | Select-Object -First 1
$op = Get-Partition -DiskNumber $osDisk.Number | Sort-Object Size -Descending | Select-Object -First 1
$BL = $bp.DriveLetter; $OL = $op.DriveLetter
Write-Host ("boot partition={0}:  os partition={1}:" -f $BL,$OL)
Write-Host ("  {1}:\Windows exists: {0}" -f (Test-Path "${OL}:\Windows"),$OL)
Write-Host ("  boot partition active(MBR): {0}" -f $bp.IsActive)
if (-not (Test-Path "${OL}:\Windows")) { Write-Host "  ${OL}:\Windows not found - wrong OS disk/partition. Offlining and stopping." -ForegroundColor Red }
else {
    Write-Host "`n== BCD BEFORE (diagnosis) ==" -ForegroundColor Cyan
    $bcd = "${BL}:\Boot\BCD"; if ($Firmware -eq 'UEFI') { $bcd = "${BL}:\EFI\Microsoft\Boot\BCD" }
    if (-not (Test-Path $bcd)) { Write-Host "  no BCD store at $bcd - listing ${BL}: root:"; Get-ChildItem "${BL}:\" -Force | Select-Object Name | Out-String | Write-Host }
    else { bcdedit /store $bcd /enum 2>&1 | Select-String 'identifier|device|osdevice|description' | ForEach-Object { Write-Host "  $_" } }

    Write-Host "`n== bcdboot repair ==" -ForegroundColor Cyan
    $r = bcdboot "${OL}:\Windows" /s "${BL}:" /f $Firmware 2>&1
    Write-Host "  $r"

    Write-Host "`n== BCD AFTER ==" -ForegroundColor Cyan
    bcdedit /store $bcd /enum 2>&1 | Select-String 'identifier|device|osdevice|description' | ForEach-Object { Write-Host "  $_" }
}

Write-Host "`n== remove temp letters + offline both disks ==" -ForegroundColor Cyan
foreach ($part in @($bp,$op)) { if ($part.DriveLetter) { $part | Remove-PartitionAccessPath -AccessPath ("{0}:" -f $part.DriveLetter) -ErrorAction SilentlyContinue } }
Set-Disk -Number $bootDisk.Number -IsOffline $true
Set-Disk -Number $osDisk.Number -IsOffline $true
Write-Host "DONE - disks offlined, safe to detach and reattach to the original guest." -ForegroundColor Green
