#Requires -Version 5.1
<#
.SYNOPSIS
    Finds and flattens "doubled folder" structures (...\NAME\NAME\...) on a file share
    that push file paths past the Windows 260-character limit.

.DESCRIPTION
    Some folders end up nested inside an identically named copy of themselves (usually
    a copy/migration artifact). That extra level pushes file paths past MAX_PATH so apps
    (Explorer, Edge, Adobe) cannot open the files. Two remediation cases:

      COLLAPSE - the outer NAME folder contains ONLY the inner same-named copy (a pure
                 redundant wrapper). Collapse ...\NAME\NAME\ to ...\NAME\ . Always safe.
                 (Default behavior.)
      MERGE    - the outer NAME folder holds the inner same-named copy PLUS other real
                 content. With -Merge, lift the inner copy's contents up next to the
                 others, then remove the empty inner, ONLY when nothing inside the inner
                 collides with something already in the outer. Never overwrites.

    Enumeration uses robocopy /L (handles long paths natively). Every move is a
    same-volume rename (metadata only), so it is fast and no file data is recopied.

    SAFETY: dry run by default (-Apply required); optional -AllowRoots allowlist so a
    typo'd -Root cannot walk the wrong tree; each operation is wrapped so a failure
    leaves data in place (collapse even rolls back); transcript logged.

.PARAMETER Root
    The folder tree to scan (local path on the file server is fastest).

.PARAMETER AllowRoots
    Optional allowlist. When supplied, -Root must equal or sit under one of these.

.PARAMETER Apply
    Actually perform the renames. Without it, reports only.

.PARAMETER Merge
    Also perform the collision-free MERGE case (changes folder layout; use deliberately).

.PARAMETER LogDir
    Where the transcript and scan log go.

.EXAMPLE
    .\Repair-NestedDuplicateFolders.ps1 -Root 'F:\Shares\Public'                # dry run
    .\Repair-NestedDuplicateFolders.ps1 -Root 'F:\Shares\Public' -Apply
    .\Repair-NestedDuplicateFolders.ps1 -Root 'F:\Shares\Public' -Merge -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Root,
    [string[]]$AllowRoots = @(),
    [switch]$Apply,
    [switch]$Merge,
    [string]$LogDir = "$env:TEMP\flatten-dupes"
)
$ErrorActionPreference = 'Continue'

function Say { param([string]$m,[string]$c='Gray') Write-Host $m -ForegroundColor $c }

if ($AllowRoots.Count) {
    $rootOk = $false
    foreach ($a in $AllowRoots) { if ($Root -ieq $a -or $Root -like "$a\*") { $rootOk = $true; break } }
    if (-not $rootOk) { Say "[FAIL] -Root '$Root' is not under an allowed root. Aborting." 'Red'; return }
}
if (-not (Test-Path -LiteralPath $Root)) { Say "[FAIL] Root not found: $Root" 'Red'; return }

# Drive prefix of the root (robocopy output lines are matched against this)
$rootPrefix = ($Root -replace '\\+$','')

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
try { Start-Transcript -Path "$LogDir\flatten-dupes-$stamp.transcript.txt" -Append -ErrorAction SilentlyContinue | Out-Null } catch { }

Say "`n=========  FLATTEN DUPLICATED FOLDERS  ($(if($Apply){'APPLY'}else{'DRY RUN'}); merge $(if($Merge){'ON'}else{'OFF'}))  =========" 'Cyan'
Say "Root: $Root" 'Cyan'

# ---- DISCOVER (robocopy /L lists every file, long paths included) ----
Say "`nScanning $Root for duplicated folders..." 'White'
$scanLog = "$LogDir\flatten-scan-$stamp.log"
$rcArgs = @($Root, 'NULL', '/L', '/E', '/FP', '/NJH', '/NJS', '/NDL', '/NC', '/NS', '/R:0', '/W:0', '/XJ', "/LOG:$scanLog")
$proc = Start-Process -FilePath robocopy.exe -ArgumentList $rcArgs -PassThru -WindowStyle Hidden
while (-not $proc.HasExited) {
    Start-Sleep -Seconds 3
    $kb = 0; try { $kb = [math]::Round((Get-Item -LiteralPath $scanLog -ErrorAction Stop).Length / 1KB) } catch { }
    Say ("  scanning... {0} KB listed" -f $kb) 'DarkGray'
}
$paths = @(Get-Content -LiteralPath $scanLog -ErrorAction SilentlyContinue | ForEach-Object { $_.Trim() } | Where-Object { $_ -like "$rootPrefix*" })
Remove-Item -LiteralPath $scanLog -ErrorAction SilentlyContinue
Say ("  listed {0} file path(s)." -f $paths.Count) 'Gray'

$dupes = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
foreach ($p in $paths) {
    $segs = $p -split '\\'
    for ($i = 2; $i -lt ($segs.Count - 1); $i++) {
        if ($segs[$i] -and $segs[$i-1] -and ($segs[$i] -ieq $segs[$i-1])) { [void]$dupes.Add( ($segs[0..$i] -join '\') ); break }
    }
}
$dupeList = @($dupes) | Sort-Object { $_.Length } -Descending
Say ("`nFound {0} duplicated folder(s)." -f $dupeList.Count) $(if ($dupeList.Count) { 'Yellow' } else { 'Green' })
if ($dupeList.Count -eq 0) { Say "Nothing to do." 'Green'; try { Stop-Transcript | Out-Null } catch { }; return }

# ---- PROCESS ----
$collapsed = 0; $merged = 0; $skipped = 0; $failed = 0; $n = 0
foreach ($inner in $dupeList) {
    $n++
    $outer  = $inner.Substring(0, $inner.LastIndexOf('\'))
    $name   = $inner.Substring($inner.LastIndexOf('\') + 1)
    $parent = $outer.Substring(0, $outer.LastIndexOf('\'))

    try {
        if (-not (Test-Path -LiteralPath $outer)) { Say ("  SKIP  [{0}/{1}] already gone: {2}" -f $n,$dupeList.Count,$outer) 'DarkGray'; $skipped++; continue }
        if (-not (Test-Path -LiteralPath $inner)) { Say ("  SKIP  [{0}/{1}] inner already gone: {2}" -f $n,$dupeList.Count,$inner) 'DarkGray'; $skipped++; continue }
        $outerKids = @(Get-ChildItem -LiteralPath $outer -Force -ErrorAction Stop)
    }
    catch { Say ("  SKIP  [{0}/{1}] could not read (path too long / access): {2}" -f $n,$dupeList.Count,$outer) 'Yellow'; $skipped++; continue }

    $pure = ($outerKids.Count -eq 1 -and $outerKids[0].PSIsContainer -and $outerKids[0].Name -ieq $name)

    if ($pure) {
        # ---- COLLAPSE ----
        if (-not $Apply) { Say ("  WOULD COLLAPSE  [{0}/{1}]  {2}\{3}\{3}  ->  {2}\{3}" -f $n,$dupeList.Count,$parent,$name) 'Cyan'; continue }
        $temp = "$parent\~flat-$stamp-$n"
        try {
            [System.IO.Directory]::Move($outer, $temp)
            try {
                [System.IO.Directory]::Move("$temp\$name", $outer)
                try { [System.IO.Directory]::Delete($temp, $false) } catch { Say ("    note: empty temp not removed: $temp") 'DarkYellow' }
                Say ("  COLLAPSED  [{0}/{1}]  {2}\{3}" -f $n,$dupeList.Count,$parent,$name) 'Green'; $collapsed++
            }
            catch {
                if ((Test-Path -LiteralPath $temp) -and -not (Test-Path -LiteralPath $outer)) { try { [System.IO.Directory]::Move($temp, $outer) } catch { } }
                Say ("  FAIL  [{0}/{1}]  {2}\{3}: {4} (rolled back)" -f $n,$dupeList.Count,$parent,$name,$_.Exception.Message) 'Red'; $failed++
            }
        }
        catch { Say ("  FAIL  [{0}/{1}]  {2}\{3}: {4} (no change)" -f $n,$dupeList.Count,$parent,$name,$_.Exception.Message) 'Red'; $failed++ }
        continue
    }

    # ---- NON-PURE: needs -Merge, and only if collision-free ----
    if (-not $Merge) { Say ("  SKIP  [{0}/{1}] outer has other contents; re-run with -Merge to merge it: {2}" -f $n,$dupeList.Count,$outer) 'Yellow'; $skipped++; continue }

    try { $innerKids = @(Get-ChildItem -LiteralPath $inner -Force -ErrorAction Stop) }
    catch { Say ("  SKIP  [{0}/{1}] could not read inner (path too long): {2}" -f $n,$dupeList.Count,$inner) 'Yellow'; $skipped++; continue }

    $outerOther = @($outerKids | Where-Object { -not ($_.PSIsContainer -and $_.Name -ieq $name) } | ForEach-Object { $_.Name })
    $collide = @($innerKids | Where-Object { $outerOther -contains $_.Name } | ForEach-Object { $_.Name })
    if ($collide.Count -gt 0) {
        Say ("  SKIP  [{0}/{1}] merge would collide on [{2}], needs manual review: {3}" -f $n,$dupeList.Count,($collide -join ', '),$outer) 'Yellow'; $skipped++; continue
    }

    if (-not $Apply) {
        Say ("  WOULD MERGE  [{0}/{1}]  lift {2} item(s) out of {3}\{4}\{4}  up into  {3}\{4}" -f $n,$dupeList.Count,$innerKids.Count,$parent,$name) 'Cyan'
        continue
    }

    # MERGE apply: move each inner child up next to the outer's other contents, then drop the empty inner.
    $mv = 0; $mfail = 0
    foreach ($ic in $innerKids) {
        $dest = "$outer\$($ic.Name)"
        try {
            if ($ic.PSIsContainer) { [System.IO.Directory]::Move($ic.FullName, $dest) } else { [System.IO.File]::Move($ic.FullName, $dest) }
            $mv++
        }
        catch { $mfail++; Say ("    could not move '{0}': {1}" -f $ic.Name, $_.Exception.Message) 'Red' }
    }
    if ($mfail -eq 0) {
        try { [System.IO.Directory]::Delete($inner, $false) } catch { Say ("    note: inner not removed after merge: $inner") 'DarkYellow' }
        Say ("  MERGED  [{0}/{1}]  {2} item(s) lifted, duplicate level removed:  {3}\{4}" -f $n,$dupeList.Count,$mv,$parent,$name) 'Green'; $merged++
    }
    else {
        Say ("  PARTIAL [{0}/{1}]  moved {2}, failed {3} (no data lost; re-run to finish): {4}" -f $n,$dupeList.Count,$mv,$mfail,$outer) 'Red'; $failed++
    }
}

Say "`n=========  SUMMARY  =========" 'White'
Say ("  collapsed: {0}   merged: {1}   skipped: {2}   failed: {3}   (of {4})" -f $collapsed,$merged,$skipped,$failed,$dupeList.Count) $(if ($failed) { 'Red' } elseif ($Apply) { 'Green' } else { 'Cyan' })
if (-not $Apply) { Say "`nDRY RUN, nothing changed. Add -Apply to do it (and -Merge to include the merges)." 'Yellow' }
else { Say "`nDone. Re-run (no -Apply) to confirm. Remaining skips are collisions or too-deep paths to handle by hand." 'Yellow' }
try { Stop-Transcript | Out-Null } catch { }
