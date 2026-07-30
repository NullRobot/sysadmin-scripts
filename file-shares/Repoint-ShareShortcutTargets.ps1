#Requires -Version 5.1
<#
.SYNOPSIS
    After a file-server migration, finds .lnk shortcuts saved INSIDE folders on a share
    and repoints any that still target the old server at the new one.

.DESCRIPTION
    Users routinely save shortcuts to shared files inside the share itself, so after a
    server migration those shortcuts still point at \\OLDSERVER\... . Because they live
    on the share, ONE run fixes them for every user at once. Only the server token in
    the target path is swapped; the share name and rest of the path are untouched.

    DRY RUN by default; -Apply rewrites. A shortcut is only saved when its new target
    actually exists, so a renamed/moved path is flagged MANUAL instead of guessed at.
    Drive-letter shortcuts (S:\...) are deliberately left alone (they follow the user's
    mapped drive). Shortcut paths at/over 260 chars cannot be opened by the COM
    WScript.Shell interface and are flagged MANUAL-LONGPATH.

    Enumeration uses robocopy /L so long paths do not break the walk. Best run on the
    file server itself against the local volume paths (fastest, long-path safe), but a
    UNC root works too.

.PARAMETER Roots
    One or more share roots to walk (e.g. 'D:\Shares\Public' or '\\newserver\Public').

.PARAMETER OldServer
    Old server NetBIOS name (matched with or without any DNS suffix).

.PARAMETER NewServer
    New server name/FQDN to substitute.

.PARAMETER Apply
    Actually rewrite shortcuts. Without it, reports only.

.EXAMPLE
    .\Repoint-ShareShortcutTargets.ps1 -Roots 'D:\Shares\Public','D:\Shares\HR' -OldServer OLDFS -NewServer newfs.corp.example.com
    .\Repoint-ShareShortcutTargets.ps1 -Roots 'D:\Shares\Public' -OldServer OLDFS -NewServer newfs.corp.example.com -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$Roots,
    [Parameter(Mandatory)][string]$OldServer,
    [Parameter(Mandatory)][string]$NewServer,
    [switch]$Apply,
    [string]$LogDir = 'C:\Temp'
)
$ErrorActionPreference = 'Continue'

$oldEsc = [regex]::Escape($OldServer)
$rxFind = "(?i)\\\\$oldEsc(\.[^\\]+)?(\\|`$)"           # does this path reference the old server?
$rxSwap = "(?i)\\\\$oldEsc(\.[^\\]+)?(?=\\|`$)"         # swap just the server token
function Swap($p) { if ($p) { $p -replace $rxSwap, "\\$NewServer" } else { $p } }

New-Item -ItemType Directory -Force -Path $LogDir -ErrorAction SilentlyContinue | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$csv   = Join-Path $LogDir "share-shortcuts-$stamp.csv"

$mode = if ($Apply) { 'APPLY (writing changes)' } else { 'DRY RUN (no changes)' }
Write-Host "`n==================  FIX SHARE SHORTCUTS  -  $mode  ==================" -ForegroundColor Cyan
Write-Host "Roots : $($Roots -join ', ')" -ForegroundColor Gray
Write-Host "Swap  : \\$OldServer -> \\$NewServer" -ForegroundColor Gray
Write-Host "Log   : $csv`n" -ForegroundColor Gray

# ---- enumerate every .lnk under each root using robocopy /L (handles long paths natively) ----
function Get-LnkFiles($root) {
    $tmp = Join-Path $env:TEMP ("lnkscan-{0}.log" -f ([guid]::NewGuid().ToString('N')))
    robocopy $root $env:TEMP '*.lnk' /L /S /FP /NC /NS /NJH /NJS /NDL /R:0 /W:0 /LOG:$tmp 2>$null | Out-Null
    $files = @(Get-Content -LiteralPath $tmp -ErrorAction SilentlyContinue |
                ForEach-Object { $_.Trim() } |
                Where-Object   { $_ -match '(?i)\.lnk$' })
    Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    return $files
}

$wsh  = New-Object -ComObject WScript.Shell
$rows = New-Object System.Collections.Generic.List[object]
$counts = @{}
function Tally($d) { if ($counts.ContainsKey($d)) { $counts[$d]++ } else { $counts[$d] = 1 } }

foreach ($root in $Roots) {
    if (-not (Test-Path -LiteralPath $root)) { Write-Host "ROOT NOT REACHABLE: $root" -ForegroundColor Red; continue }
    Write-Host "Scanning $root ..." -ForegroundColor White
    $lnks = Get-LnkFiles $root
    Write-Host ("  found {0} shortcut file(s)" -f $lnks.Count) -ForegroundColor DarkGray

    foreach ($f in $lnks) {
        $row = [pscustomobject]@{ Disposition = ''; Shortcut = $f; OldTarget = ''; NewTarget = ''; Note = '' }

        # COM CreateShortcut cannot open a path at/over the 260 limit; flag those.
        if ($f.Length -ge 260) {
            $row.Disposition = 'MANUAL-LONGPATH'; $row.Note = 'shortcut path too long for auto-edit; shorten it first'
            $rows.Add($row); Tally $row.Disposition; continue
        }
        try {
            $sc = $wsh.CreateShortcut($f)
            $tp = $sc.TargetPath; $wd = $sc.WorkingDirectory
            $row.OldTarget = $tp
            if ($tp -match $rxFind) {
                $ntp = Swap $tp
                $row.NewTarget = $ntp
                if (Test-Path -LiteralPath $ntp) {
                    if ($Apply) {
                        $sc.TargetPath = $ntp
                        if ($wd -and ($wd -match $rxFind)) { $sc.WorkingDirectory = Swap $wd }
                        $sc.Save()
                        $row.Disposition = 'FIXED'
                    } else {
                        $row.Disposition = 'WOULD-FIX'
                    }
                } else {
                    $row.Disposition = 'MANUAL-TARGET-MISSING'
                    $row.Note = 'new target does not exist (file renamed/moved during migration?)'
                }
            }
            elseif ($tp -match '(?i)' + [regex]::Escape($NewServer)) { $row.Disposition = 'OK-ALREADY' }
            elseif ($tp -match '^[A-Za-z]:\\')                       { $row.Disposition = 'OK-DRIVELETTER' }
            else                                                     { $row.Disposition = 'SKIP-UNRELATED' }
        }
        catch {
            $row.Disposition = 'ERROR'; $row.Note = $_.Exception.Message
        }
        $rows.Add($row); Tally $row.Disposition
    }
}

$rows | Sort-Object Disposition, Shortcut | Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8

Write-Host "`n----- RESULTS -----" -ForegroundColor White
foreach ($k in ($counts.Keys | Sort-Object)) {
    $col = switch -Regex ($k) { 'FIXED|WOULD-FIX' { 'Green' } '^OK' { 'Gray' } 'SKIP' { 'DarkGray' } default { 'Yellow' } }
    Write-Host ("  {0,-22} {1}" -f $k, $counts[$k]) -ForegroundColor $col
}
$toFix = @($rows | Where-Object { $_.Disposition -in 'WOULD-FIX', 'FIXED' }).Count
Write-Host ""
if ($Apply) {
    Write-Host ("Done. Rewrote $toFix shortcut(s). Full per-file log: $csv") -ForegroundColor Cyan
} else {
    Write-Host ("DRY RUN. $toFix shortcut(s) would be fixed. Review $csv, then re-run with -Apply.") -ForegroundColor Yellow
}
Write-Host "Anything MANUAL-* needs a human: the link is too deep to auto-edit or its file was moved/renamed." -ForegroundColor Gray
