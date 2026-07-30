#Requires -Version 5.1
<#
.SYNOPSIS
    Dumps how a Group Policy Preferences drive-map GPO maps drives today: letter,
    action, target path, remove-policy, and item-level targeting.

.DESCRIPTION
    Read-only. Run on a DC (or any RSAT box that reaches SYSVOL), elevated. Reads the
    GPO's Drives.xml straight out of SYSVOL and prints one row per drive item:
      - letter and action (Create/Replace/Update/Delete)
      - the UNC target path
      - whether "Remove this item when it is no longer applied" is set
      - the item-level targeting filters (a row with NO targeting maps for EVERYONE
        the GPO reaches, whether or not they can open the share)

    With -All (no -GpoName) it instead walks every Drives.xml in the domain's SYSVOL,
    which answers "which GPO maps drive X?" in one pass.

    Useful for planning "only map drives the user actually has access to" and for
    file-server migrations (find every GPP item still pointing at the old server).

.PARAMETER GpoName
    Display name of the drive-map GPO. If not found, lists GPOs whose name contains
    'drive' or 'map' as a hint.

.PARAMETER All
    Ignore -GpoName and dump every Drives.xml found under the domain's Policies tree.

.EXAMPLE
    .\Get-GppDriveMappings.ps1 -GpoName 'Mapped Drives'
    .\Get-GppDriveMappings.ps1 -All
#>
[CmdletBinding()]
param(
    [string]$GpoName,
    [switch]$All
)
$ErrorActionPreference = 'Continue'
Import-Module GroupPolicy -ErrorAction SilentlyContinue
function Say { param([string]$m,[string]$c='Gray') Write-Host $m -ForegroundColor $c }

$dom = $env:USERDNSDOMAIN
$actMap = @{ 'C'='Create'; 'R'='Replace'; 'U'='Update'; 'D'='Delete' }

function Show-DrivesXml([string]$xmlPath) {
    [xml]$x = Get-Content -LiteralPath $xmlPath -Raw
    Say ""
    Say ("{0,-7} {1,-8} {2,-42} {3,-12} {4}" -f 'Letter','Action','Target path','Remove?','Targeted to (item-level targeting)') 'White'
    Say ("-" * 118) 'DarkGray'
    foreach ($d in $x.SelectNodes('//Drive')) {
        $p      = $d.Properties
        $act    = if ($actMap["$($p.action)"]) { $actMap["$($p.action)"] } else { "$($p.action)" }
        $letter = if ($p.letter) { "$($p.letter):" } else { "$($d.name)" }
        $remove = if ("$($d.removePolicy)" -eq '1') { 'YES' } else { 'no' }
        $filters = @()
        if ($d.Filters) { foreach ($f in $d.Filters.ChildNodes) { $filters += $(if ($f.name) { "$($f.LocalName)=$($f.name)" } else { $f.LocalName }) } }
        $tgt = if ($filters.Count) { $filters -join '; ' } else { '(none - maps for EVERYONE the GPO reaches)' }
        Say ("{0,-7} {1,-8} {2,-42} {3,-12} {4}" -f $letter, $act, $p.path, $remove, $tgt) $(if ($filters.Count) { 'Gray' } else { 'Yellow' })
    }
}

if ($All -or -not $GpoName) {
    $base = "\\$dom\SYSVOL\$dom\Policies"
    Say "Walking every Drives.xml under $base ..." 'Cyan'
    Get-ChildItem -Path $base -Recurse -Filter 'Drives.xml' -ErrorAction SilentlyContinue | ForEach-Object {
        $gpoGuid = (($_.FullName -split '\\Policies\\')[1] -split '\\')[0]
        $name = ''
        try { $name = (Get-GPO -Guid ($gpoGuid.Trim('{}')) -ErrorAction Stop).DisplayName } catch {}
        Say "`n===== $($_.FullName)" 'Cyan'
        if ($name) { Say "GPO: $name" 'Cyan' }
        Show-DrivesXml $_.FullName
    }
    return
}

$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) {
    Say "GPO '$GpoName' not found. GPOs with 'drive' or 'map' in the name:" 'Yellow'
    Get-GPO -All | Where-Object { $_.DisplayName -match '(?i)drive|map' } | ForEach-Object { Say "  $($_.DisplayName)" }
    return
}
$xml = "\\$dom\SYSVOL\$dom\Policies\{$($gpo.Id)}\User\Preferences\Drives\Drives.xml"
Say "`nGPO: $($gpo.DisplayName)   Id=$($gpo.Id)" 'Cyan'
if (-not (Test-Path -LiteralPath $xml)) {
    $xml = "\\$dom\SYSVOL\$dom\Policies\{$($gpo.Id)}\Machine\Preferences\Drives\Drives.xml"
    if (-not (Test-Path -LiteralPath $xml)) { Say "No Drives.xml under this GPO (it may use a logon script for drives instead, not GPP)." 'Red'; return }
}
Say "Drives.xml: $xml" 'DarkGray'
Show-DrivesXml $xml

Say "`nYellow rows have NO targeting, so every user the GPO reaches gets that drive whether they can open it or not." 'Yellow'
Say "Plan: add a Security-Group filter per drive (its access group) and tick 'Remove this item when it is no longer applied'." 'Cyan'
Say "Action 'Update' is gentler than 'Replace' (Replace deletes+recreates each refresh, which can blip an open file)." 'Cyan'
