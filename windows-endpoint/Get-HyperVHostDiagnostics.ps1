<#
.SYNOPSIS
    Read-only Hyper-V host inventory: VMs, checkpoints, disk chains, and big VHD files.
.DESCRIPTION
    Run on a Hyper-V host (admin). The quick "what's on this host and what's eating the disk"
    snapshot - especially useful when a host's C: is filling from runaway checkpoints or fat
    differencing (.avhdx) chains. Reports host free space, each VM's state / AutomaticStopAction /
    checkpoint count, every attached virtual disk with its on-disk size, and the largest VHD/AVHDX/
    ISO files under the common VM storage paths. Optionally lists Hyper-V-Worker/VMMS admin events.
    Changes nothing.
.PARAMETER SearchPaths
    Folders to scan for large VM disk files. Defaults to common Hyper-V storage locations.
.NOTES
    A high checkpoint count or an active disk still on an .avhdx usually means a backup left
    checkpoints behind - investigate before merging.
#>
[CmdletBinding()]
param(
    [string[]]$SearchPaths = @('C:\Virtual Server','C:\VMs','C:\ProgramData\Microsoft\Windows\Hyper-V','C:\Users\Public\Documents\Hyper-V')
)

$ErrorActionPreference = 'SilentlyContinue'
"### HOST: $env:COMPUTERNAME  $(Get-Date -f s)"
Get-PSDrive C | ForEach-Object { "C: {0:N0} GB free / {1:N0} GB total ({2:P0} used)" -f ($_.Free/1GB), (($_.Used+$_.Free)/1GB), ($_.Used/($_.Used+$_.Free)) }

"### VMs (state | AutomaticStopAction | checkpoints)"
Get-VM | ForEach-Object {
    $cp = (Get-VMCheckpoint -VMName $_.Name | Measure-Object).Count
    "{0} | {1} | AutoStop={2} | Checkpoints={3}" -f $_.Name, $_.State, $_.AutomaticStopAction, $cp
}

"### Attached virtual disks (on-disk size)"
Get-VM | Get-VMHardDiskDrive | ForEach-Object {
    $f = Get-Item $_.Path -ErrorAction SilentlyContinue
    if ($f) { "{0,8:N1} GB  {1}  ({2})" -f ($f.Length/1GB), $_.Path, $_.VMName }
}

"### Largest VHD/AVHDX/ISO files under VM storage paths"
$paths = $SearchPaths | Where-Object { Test-Path $_ }
if ($paths) {
    Get-ChildItem $paths -Recurse -Include *.vhdx,*.vhd,*.avhdx,*.avhd,*.vmrs,*.iso -ErrorAction SilentlyContinue |
        Sort-Object Length -Descending | Select-Object -First 40 | ForEach-Object {
            "{0,8:N1} GB  {1}  {2:d}" -f ($_.Length/1GB), $_.FullName, $_.LastWriteTime }
}

"### Active differencing-disk chains (VM still riding an .avhdx = checkpoints or a stuck merge)"
Get-VM | Get-VMHardDiskDrive | Where-Object { $_.Path -like '*.avhdx' } | ForEach-Object {
    $v = Get-VHD -Path $_.Path
    "  $($_.VMName): $($_.Path)  parent=[$($v.ParentPath)]"
}
