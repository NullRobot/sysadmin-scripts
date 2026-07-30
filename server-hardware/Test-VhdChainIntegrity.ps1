<#
.SYNOPSIS
    Traces a Hyper-V VM's VHD/AVHDX differencing chain from the active disk
    back to the base, flagging broken parents and orphaned snapshot files.

.DESCRIPTION
    When a Hyper-V host's disk fills with .avhdx files, or a VM won't boot
    after failed checkpoint merges, the first question is always: what does
    the chain actually look like? This script:
      1. Reads the disk the VM is ACTUALLY attached to right now
      2. Walks parent-by-parent to the base VHDX, reporting type and size at
         each hop, and stops loudly if a parent file is missing (broken chain)
      3. Compares the AVHDX file count in the disk folder against the chain
         depth
      4. Lists any AVHDX files NOT part of the active chain (orphans that are
         safe-to-review candidates for reclaiming space; verify before delete)
    Read-only. Run on the Hyper-V host (as admin/SYSTEM).

.PARAMETER VMName
    The VM whose chain to trace.

.PARAMETER VhdDirectory
    Folder containing the VM's disks. Default: derived from the active disk path.

.EXAMPLE
    .\Test-VhdChainIntegrity.ps1 -VMName APP-SRV1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$VMName,
    [string]$VhdDirectory
)

# Step 1: What disk is the VM actually using right now?
Write-Output "=== ACTIVE DISK(S) (what the VM boots from) ==="
$activeDisks = @((Get-VMHardDiskDrive -VMName $VMName -ErrorAction Stop).Path)
$activeDisks | ForEach-Object { Write-Output "Active: $_" }
$activeDisk = $activeDisks[0]
if (-not $VhdDirectory) { $VhdDirectory = Split-Path $activeDisk -Parent }
Write-Output ""

# Step 2: Trace the chain from active disk back to base
Write-Output "=== TRACING VHD CHAIN (active -> base) ==="
$current = $activeDisk
$depth = 0
$chainOK = $true
while ($current) {
    $depth++
    try {
        $vhd = Get-VHD -Path $current -ErrorAction Stop
        $parent = $vhd.ParentPath
        $sizeGB = [math]::Round($vhd.FileSize/1GB,1)
        Write-Output "[$depth] $($vhd.VhdType) | ${sizeGB} GB | $current"
        if ($parent) {
            if (Test-Path $parent) {
                Write-Output "     Parent exists: $parent"
            } else {
                Write-Output "     BROKEN PARENT (file missing): $parent"
                $chainOK = $false
                break
            }
            $current = $parent
        } else {
            Write-Output "     (base disk, no parent)"
            $current = $null
        }
    } catch {
        Write-Output "[$depth] ERROR reading VHD: $($_.Exception.Message)"
        Write-Output "     Path: $current"
        $chainOK = $false
        break
    }
}

Write-Output ""
Write-Output "Chain depth: $depth"
Write-Output "Chain intact: $chainOK"
Write-Output ""

# Step 3: Count all AVHDX files in the directory vs chain depth
Write-Output "=== FILE COUNT CHECK ==="
$allAvhdx = Get-ChildItem $VhdDirectory -Filter "*.avhdx" -ErrorAction SilentlyContinue
Write-Output "AVHDX files in directory: $($allAvhdx.Count)"
Write-Output "Expected from chain depth: $($depth - 1) (depth minus the base VHDX)"
Write-Output ""

# Step 4: List any AVHDX files NOT in the chain (orphans)
Write-Output "=== CHECKING FOR ORPHANS ==="
$chainPaths = @()
$current = $activeDisk
while ($current) {
    $chainPaths += $current
    try {
        $vhd = Get-VHD -Path $current -ErrorAction Stop
        $current = $vhd.ParentPath
    } catch {
        $current = $null
    }
}
$orphans = $allAvhdx | Where-Object { $_.FullName -notin $chainPaths }
if ($orphans) {
    Write-Output "Found $($orphans.Count) orphaned AVHDX files (not in active chain):"
    $orphans | Select-Object Name, @{N='SizeGB';E={[math]::Round($_.Length/1GB,1)}}, LastWriteTime | Format-Table -AutoSize
    Write-Output "Verify no checkpoint/replica still references these before deleting."
} else {
    Write-Output "No orphans found. All AVHDX files are part of the active chain."
}
