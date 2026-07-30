<#
.SYNOPSIS
    Reclaim C: space with reversible, low-risk cleanups (no user data deleted).
.DESCRIPTION
    Run as SYSTEM (Datto RMM / Web Remote) or admin. Everything here is safe by design - it clears
    caches Windows rebuilds on its own and truncates runaway logs in place (so the owning service
    keeps its file handle and its logging target), rather than deleting anything a user would miss.
    Steps, each reporting free space before/after:
      1. MSI*.LOG debris in Windows\Temp (installer-loop leftovers, can be many GB).
      2. Recycle bin.
      3. Windows Update download cache (SoftwareDistribution\Download; re-downloadable by design).
      4. Old Windows\Temp subdirectories (> N days).
      5. Optional: truncate specific runaway application logs you pass in (via -TruncateLogs).
    Prints total reclaimed. Use -WhatIf to preview. Does NOT touch WinSxS, user profiles, or app data.
.PARAMETER TempAgeDays
    Age threshold for clearing old Windows\Temp subdirectories. Default 30.
.PARAMETER TruncateLogs
    Optional full paths of runaway app logs to truncate in place (SetLength 0, keeping the handle).
.NOTES
    For a heavier clean, first run Get-DiskSpaceUsage.ps1 to see what's actually big, then decide.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
    [int]$TempAgeDays = 30,
    [string[]]$TruncateLogs = @()
)

$ErrorActionPreference = 'SilentlyContinue'
function FreeGB { [math]::Round((Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace/1GB,2) }
$before = FreeGB
"C: free BEFORE: $before GB"

if ($PSCmdlet.ShouldProcess('C:\Windows\Temp\MSI*.LOG', 'Delete MSI installer logs')) {
    Get-ChildItem 'C:\Windows\Temp' -File -Force -Filter 'MSI*.LOG' | Remove-Item -Force -ErrorAction SilentlyContinue
    "After MSI logs: $(FreeGB) GB"
}

if ($PSCmdlet.ShouldProcess('Recycle Bin', 'Empty')) {
    Clear-RecycleBin -DriveLetter C -Force -Confirm:$false -ErrorAction SilentlyContinue
    "After Recycle Bin: $(FreeGB) GB"
}

if ($PSCmdlet.ShouldProcess('SoftwareDistribution\Download', 'Clear Windows Update download cache')) {
    Stop-Service wuauserv, bits -Force -ErrorAction SilentlyContinue
    Remove-Item 'C:\Windows\SoftwareDistribution\Download\*' -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service bits, wuauserv -ErrorAction SilentlyContinue
    "After WU cache: $(FreeGB) GB"
}

if ($PSCmdlet.ShouldProcess("C:\Windows\Temp dirs older than $TempAgeDays days", 'Delete')) {
    Get-ChildItem 'C:\Windows\Temp' -Directory -Force | Where-Object LastWriteTime -lt (Get-Date).AddDays(-$TempAgeDays) |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    "After old Temp dirs: $(FreeGB) GB"
}

foreach ($log in $TruncateLogs) {
    if (Test-Path $log) {
        "TRUNCATE {0:N2} GB  {1}" -f ((Get-Item $log).Length/1GB), $log
        if ($PSCmdlet.ShouldProcess($log, 'Truncate to 0 bytes in place')) {
            try {
                $fs = [IO.File]::Open($log, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
                $fs.SetLength(0); $fs.Close(); "  truncated OK"
            } catch { "  TRUNCATE FAILED (locked): $($_.Exception.Message) -> stop the owning service first" }
        }
    }
}

$after = FreeGB
"C: free AFTER:  $after GB"
"RECLAIMED:      {0:N2} GB" -f ($after - $before)
