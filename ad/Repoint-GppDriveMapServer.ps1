#Requires -Version 5.1
<#
.SYNOPSIS
    File-server migration cutover for a GPP drive-map GPO: rewrites every drive item
    still pointing at the old server to the new server, safely, with backup and a
    correct version bump.

.DESCRIPTION
    Editing Drives.xml in SYSVOL by hand does NOT make clients pick up the change; the
    GPO's versionNumber must also be bumped in BOTH the AD object and gpt.ini, in sync,
    or clients skip the GPO or replication fights you. This script does the whole
    sequence correctly, pinned to a single DC so AD and SYSVOL writes cannot land on
    different DCs mid-flight:

      1. Verifies domain, GPO GUID, and expected display name (aborts on any mismatch).
      2. Rewrites each Drive item's path via regex (old server -> new), sets its action
         to 'R' (Replace) so clients re-create the mapping at next refresh.
      3. Aborts with zero writes if nothing matched, if any old-server reference
         survives the replace, or if gpt.ini is malformed.
      4. DRY RUN by default. With -Apply: GPMC backup first (BackupId recorded for a
         restore script), then writes the XML (UTF-8 no BOM), bumps versionNumber by
         65536 (user-side increment) in AD, mirrors it into gpt.ini, and verifies both
         read back in sync.

    Restore path: Restore-GPO with the recorded BackupId, or copy back the saved
    pre-change Drives xml and re-bump.

.PARAMETER Domain
    DNS name of the domain holding the GPO.

.PARAMETER Guid
    The GPO's GUID (no braces).

.PARAMETER ExpectedName
    The GPO display name; write is refused if the GUID resolves to anything else.

.PARAMETER OldHostPattern
    Regex matching the old server token in a UNC path. Example for server OLDFS with
    optional FQDN: '(?i)\\\\oldfs(\.corp\.example\.com)?(?=\\|$)'

.PARAMETER NewHost
    Replacement UNC server prefix, e.g. '\\newfs.corp.example.com'

.EXAMPLE
    .\Repoint-GppDriveMapServer.ps1 -Domain corp.example.com -Guid 11111111-2222-3333-4444-555555555555 `
        -ExpectedName 'Mapped Drives' -OldHostPattern '(?i)\\\\oldfs(\.corp\.example\.com)?(?=\\|$)' `
        -NewHost '\\newfs.corp.example.com'            # dry run
    ... -Apply                                          # commit
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Domain,
    [Parameter(Mandatory)][string]$Guid,
    [Parameter(Mandatory)][string]$ExpectedName,
    [Parameter(Mandatory)][string]$OldHostPattern,
    [Parameter(Mandatory)][string]$NewHost,
    [string]$BackupDir = 'C:\GPO-Backups\gpp-repoint',
    [string]$Dc = '',
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop

$dom = Get-ADDomain -Server $Domain
if ($dom.DNSRoot -ne $Domain) { throw "Resolved $($dom.DNSRoot), expected $Domain" }
if ($Dc) { $dc = $Dc } else { $dc = ((Get-ADDomainController -DomainName $Domain -Discover -Service ADWS -ErrorAction Stop).HostName | Select-Object -First 1) }
Write-Host "Using DC: $dc"
$dn  = "CN={$($Guid.ToUpper())},CN=Policies,CN=System,$($dom.DistinguishedName)"
$gpo = Get-ADObject -Identity $dn -Server $dc -Properties versionNumber, displayName
if ($gpo.displayName -ne $ExpectedName) { throw "GPO is '$($gpo.displayName)', expected '$ExpectedName' - wrong GUID/domain. ABORTING." }

# Pin SYSVOL to the SAME DC as the AD write (a \\domain\ DFS path could land on a different DC)
$sysvol    = "\\$dc\SYSVOL\$Domain\Policies\{$($Guid.ToUpper())}"
$drivesXml = Join-Path $sysvol 'User\Preferences\Drives\Drives.xml'
$gptIni    = Join-Path $sysvol 'gpt.ini'

[xml]$xml = Get-Content -LiteralPath $drivesXml -Raw
$changed = 0; $before = @()
foreach ($d in $xml.Drives.Drive) {
    $old = $d.Properties.path
    $new = $old -replace $OldHostPattern, $NewHost
    if ($old -and ($new -ne $old)) {
        $before += $old
        $d.Properties.path   = $new
        $d.Properties.action = 'R'
        $changed++
    }
}

Write-Host "Domain          : $Domain ($dc)"
Write-Host "GPO             : $ExpectedName"
Write-Host "Repointed items : $changed"
$before | ForEach-Object { "  BEFORE: $_" }
$newEsc = [regex]::Escape(($NewHost -replace '^\\\\',''))
$xml.Drives.Drive | Where-Object { $_.Properties.path -match "(?i)$newEsc" } | ForEach-Object { "  AFTER : $($_.Properties.path)  [action=$($_.Properties.action)]" }

if ($changed -eq 0) { throw "No old-server drive items found/changed in $drivesXml - nothing to repoint. ABORTING (no write, no version bump)." }
$survivors = @($xml.Drives.Drive | Where-Object { $_.Properties.path -match $OldHostPattern })
if ($survivors.Count) { throw "After replace, $($survivors.Count) drive path(s) still reference the old server - ABORTING before any write: $(($survivors | ForEach-Object { $_.Properties.path }) -join '; ')" }

if (-not $Apply) { Write-Host "`n[DRY-RUN] nothing written. Re-run with -Apply to commit."; return }

# Validate gpt.ini is well-formed BEFORE touching AD, so a malformed one aborts with zero writes
$ini  = Get-Content -LiteralPath $gptIni
$hits = @([regex]::Matches(($ini -join "`n"), '(?im)^\s*Version=\d+')).Count
if ($hits -ne 1) { throw "gpt.ini has $hits 'Version=' lines (expected exactly 1). ABORTING with zero writes - fix gpt.ini first." }

New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
$bk   = Backup-GPO -Guid $Guid -Domain $Domain -Server $dc -Path $BackupDir
$bkId = $bk.Id.ToString()
Set-Content -LiteralPath (Join-Path $BackupDir "BackupId-$Domain.txt") -Value $bkId
Write-Host "GPMC backup taken: BackupId $bkId  (saved to BackupId-$Domain.txt)"
Copy-Item -LiteralPath $drivesXml -Destination (Join-Path $BackupDir "Drives-$Domain-pre.xml") -Force

$settings = New-Object System.Xml.XmlWriterSettings
$settings.Encoding = New-Object System.Text.UTF8Encoding($false)
$settings.Indent = $false
$wtr = [System.Xml.XmlWriter]::Create($drivesXml, $settings)
$xml.Save($wtr); $wtr.Dispose()

# User-side version lives in the HIGH word of versionNumber, so +65536 per user-side change.
$cur    = [int64]$gpo.versionNumber
$newVer = $cur + 65536
Set-ADObject -Identity $dn -Server $dc -Replace @{versionNumber = $newVer}
($ini -replace '(?im)^(\s*Version=)\d+', "`${1}$newVer") | Set-Content -LiteralPath $gptIni -Encoding ASCII

$adBack  = [int64](Get-ADObject -Identity $dn -Server $dc -Properties versionNumber).versionNumber
$iniBack = [int64]([regex]::Match((Get-Content -LiteralPath $gptIni -Raw), '(?im)^\s*Version=(\d+)').Groups[1].Value)
if ($adBack -ne $newVer -or $iniBack -ne $newVer) { throw "VERSION DESYNC: AD=$adBack gpt.ini=$iniBack expected=$newVer. Investigate before rollout." }

Write-Host "`nDONE. Version $cur -> $newVer (AD + gpt.ini in sync on $dc)."
Write-Host "Test one user: gpupdate /force, then log off / log on, confirm drives now point at the new server."
