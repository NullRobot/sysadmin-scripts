#Requires -Version 5.1
<#
.SYNOPSIS
    Safely retires a GPO: always backs it up and records its settings first, then
    unlinks and/or deletes only when explicitly asked.

.DESCRIPTION
    Run on a DC (or an RSAT box), elevated. Behavior by switch:

        .\Retire-Gpo.ps1 -GpoName 'Old Policy'              # SAFE: backup + HTML report + show links. Changes NOTHING.
        .\Retire-Gpo.ps1 -GpoName 'Old Policy' -UnlinkOnly  # backup, then UNLINK from every OU (keeps the GPO, neuters it). Reversible.
        .\Retire-Gpo.ps1 -GpoName 'Old Policy' -Delete      # backup, unlink, then DELETE the GPO object.

    The backup means a full restore is one command away (printed at the end), so either
    action is reversible. If the backup fails, nothing else runs.

.PARAMETER GpoName
    Display name of the GPO to retire.

.PARAMETER BackupDir
    Where the timestamped backup + HTML settings record go.

.EXAMPLE
    .\Retire-Gpo.ps1 -GpoName 'Legacy Drive Maps' -UnlinkOnly
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$GpoName,
    [string]$BackupDir = 'C:\GPO-Backups',
    [switch]$UnlinkOnly,
    [switch]$Delete
)
$ErrorActionPreference = 'Continue'
Import-Module GroupPolicy -ErrorAction SilentlyContinue
function Say { param([string]$m,[string]$c='Gray') Write-Host $m -ForegroundColor $c }

$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) { Say "GPO '$GpoName' not found. Nothing to do." 'Yellow'; return }
$mode = if ($Delete) { 'DELETE' } elseif ($UnlinkOnly) { 'UNLINK ONLY' } else { 'DRY RUN (backup + report only)' }
Say "`n========  RETIRE $($gpo.DisplayName)  -  $mode  ========" 'Cyan'
Say ("Id: {0}   Modified: {1}" -f $gpo.Id, $gpo.ModificationTime)

# ---- 1. ALWAYS back up first + write a human-readable record ----
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$dest  = Join-Path (Join-Path $BackupDir ($GpoName -replace '[^\w\- ]','_')) $stamp
New-Item -ItemType Directory -Force -Path $dest | Out-Null
try {
    $bk = Backup-GPO -Guid $gpo.Id -Path $dest -Comment "Pre-retire backup of $GpoName ($stamp)" -ErrorAction Stop
    Say ("[ OK ] Backed up. BackupId: {0}" -f $bk.Id) 'Green'
} catch { Say "[FAIL] Backup failed: $($_.Exception.Message). STOPPING (no backup = no changes)." 'Red'; return }
$htmlPath = Join-Path $dest "$($GpoName -replace '[^\w\- ]','_')-report.html"
try { Get-GPOReport -Guid $gpo.Id -ReportType Html -Path $htmlPath -ErrorAction Stop; Say ("[ OK ] Full settings record: {0}" -f $htmlPath) 'Green' } catch {}
Say ("Backup folder: {0}" -f $dest) 'Cyan'

# ---- 2. show what it configures + where it is linked ----
[xml]$rpt = Get-GPOReport -Guid $gpo.Id -ReportType Xml
Say "`n----- what this GPO configures -----" 'White'
$exts = @($rpt.SelectNodes("//*[local-name()='ExtensionData']/*[local-name()='Name']") | ForEach-Object { $_.InnerText } | Sort-Object -Unique)
if ($exts.Count) { $exts | ForEach-Object { Say ("  - $_") 'Gray' } } else { Say "  (no client-side settings reported)" 'Gray' }

function SomToDN { param([string]$som)
    $parts = $som -split '/'
    $dc  = (($parts[0] -split '\.') | ForEach-Object { "DC=$_" }) -join ','
    $ous = @(); for ($i = $parts.Count - 1; $i -ge 1; $i--) { $ous += "OU=$($parts[$i])" }
    if ($ous.Count) { ($ous -join ',') + ',' + $dc } else { $dc }
}
Say "`n----- links -----" 'White'
$linkDNs = @()
foreach ($l in $rpt.SelectNodes("//*[local-name()='LinksTo']")) {
    $som = ($l.SelectSingleNode("*[local-name()='SOMPath']")).InnerText
    $dn  = SomToDN $som
    $linkDNs += $dn
    Say ("  {0}   ->   {1}" -f $som, $dn) 'Gray'
}
if ($linkDNs.Count -eq 0) { Say "  (not linked anywhere)" 'Gray' }

# ---- 3. act only if asked ----
if (-not ($UnlinkOnly -or $Delete)) {
    Say "`nDRY RUN complete. Nothing changed. Re-run with -UnlinkOnly (reversible) or -Delete once you're happy." 'Yellow'
    return
}

foreach ($dn in $linkDNs) {
    try { Remove-GPLink -Guid $gpo.Id -Target $dn -ErrorAction Stop | Out-Null; Say ("[ OK ] Unlinked from {0}" -f $dn) 'Green' }
    catch { Say ("[WARN] Could not unlink from {0}: {1}" -f $dn, $_.Exception.Message) 'Yellow' }
}

if ($Delete) {
    try { Remove-GPO -Guid $gpo.Id -ErrorAction Stop; Say "[ OK ] GPO '$GpoName' deleted." 'Green' }
    catch { Say "[FAIL] Delete failed: $($_.Exception.Message)" 'Red'; return }
}

# ---- restore instructions ----
Say "`n----- if you ever need it back -----" 'White'
Say ("  Restore-GPO -BackupId {0} -Path '{1}' -TargetName '{2}' -CreateIfNeeded" -f $bk.Id, $dest, $GpoName) 'Cyan'
Say "  (then re-link it to the OU if needed). The HTML record above shows exactly what it contained." 'Gray'
Say "`nDone." 'Green'
