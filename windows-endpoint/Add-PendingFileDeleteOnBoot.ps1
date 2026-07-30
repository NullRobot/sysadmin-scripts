<#
.SYNOPSIS
    Schedules stubborn files/directories for deletion at next boot via the
    PendingFileRenameOperations registry mechanism.

.DESCRIPTION
    For files that cannot be deleted while Windows is running (locked by a driver,
    filter-driver protected, orphaned installer leftovers, EDR remnants). The kernel
    processes PendingFileRenameOperations very early in boot, before the locking
    software loads, so the deletes almost always succeed.

    For each target root it enumerates files first, then directories deepest-first,
    then the root itself, so children are removed before parents. Existing pending
    operations already queued in the registry (e.g. by Windows Update) are preserved,
    never clobbered.

    Run elevated (SYSTEM via RMM is fine). Nothing is deleted until the machine
    reboots. To verify what is queued afterwards:
      (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').PendingFileRenameOperations

.PARAMETER Path
    One or more files or directory roots to schedule for boot-time deletion.

.PARAMETER WhatIf
    Show what would be queued without writing the registry.

.EXAMPLE
    .\Add-PendingFileDeleteOnBoot.ps1 -Path 'C:\Program Files\StuckApp','C:\Program Files (x86)\StuckApp'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string[]]$Path
)

$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
$valueName = 'PendingFileRenameOperations'

# Read existing pending ops so we don't clobber other queued operations
$existing = @()
try {
    $val = Get-ItemProperty -Path $key -Name $valueName -ErrorAction SilentlyContinue
    if ($val.$valueName) { $existing = @($val.$valueName) }
} catch {}
Write-Output "Existing pending rename ops: $($existing.Count / 2)"

$ops = @($existing)
$totalFiles = 0
$totalDirs = 0

foreach ($root in $Path) {
    if (-not (Test-Path -LiteralPath $root)) {
        Write-Output "  $root - not found, skipping"
        continue
    }
    Write-Output ""
    Write-Output "  Processing: $root"

    $item = Get-Item -LiteralPath $root -Force
    if (-not $item.PSIsContainer) {
        # Single file target
        $ops += "\??\$($item.FullName)"; $ops += ""
        $totalFiles++
        continue
    }

    # Files first (any order)
    Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $ops += "\??\$($_.FullName)"; $ops += ""
        $totalFiles++
    }

    # Then directories, DEEPEST first (children must be deleted before parents)
    Get-ChildItem -LiteralPath $root -Recurse -Directory -Force -ErrorAction SilentlyContinue |
        Sort-Object { ($_.FullName -split '\\').Count } -Descending |
        ForEach-Object {
            $ops += "\??\$($_.FullName)"; $ops += ""
            $totalDirs++
        }

    # Root directory last
    $ops += "\??\$root"; $ops += ""
    $totalDirs++
}

Write-Output ""
Write-Output "Files scheduled: $totalFiles"
Write-Output "Directories scheduled: $totalDirs"
Write-Output "Total ops after merge: $($ops.Count / 2)"

if ($PSCmdlet.ShouldProcess("$key\$valueName", "queue $($totalFiles + $totalDirs) boot-time deletes")) {
    try {
        Set-ItemProperty -Path $key -Name $valueName -Value $ops -Type MultiString -ErrorAction Stop
        Write-Output ""
        Write-Output "PendingFileRenameOperations registered. The deletes run automatically during early boot."
        Write-Output ">>> Reboot the machine to execute."
    } catch {
        Write-Output "FAILED to write registry: $($_.Exception.Message)"
    }
}
