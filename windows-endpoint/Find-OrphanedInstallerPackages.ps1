#Requires -Version 5.1
<#
.SYNOPSIS
    Reports orphaned .msi/.msp packages bloating C:\Windows\Installer (read-only), and
    can optionally delete them.

.DESCRIPTION
    C:\Windows\Installer holds Windows Installer's cached packages. A failed-install /
    self-repair loop (AV agents are notorious) can dump thousands of copies of the same
    MSI there and eat the disk. NEVER blind-delete this folder: real apps need their
    referenced packages for repair/uninstall.

    An "orphan" = a cached .msi/.msp that NO installed product or patch references in
    the registry (Installer\UserData\*\Products\*\InstallProperties and
    Installer\UserData\*\Patches\* LocalPackage values). This script:

      1. Rebuilds the referenced-package set from the registry (sanity: this count
         should be in the hundreds on a typical box, not single digits).
      2. Splits the cached packages into KEEP (referenced) vs ORPHANED, with sizes.
      3. Shows orphan size buckets (a repair loop shows up as N copies of one size)
         and the oldest/newest orphan (the loop's lifespan).
      4. Writes the exact orphan list to a file for review.
      5. With -Delete (run elevated / as SYSTEM): deletes ONLY the orphans, optionally
         narrowed by -SizeKB (+/-2%) to just the loop's copies.

.PARAMETER Delete
    Actually delete the orphans. Default is report-only.

.PARAMETER SizeKB
    With -Delete: only delete orphans within 2% of this size in KB (targets one
    repair-loop family and leaves every other orphan alone).

.PARAMETER ListPath
    Where the orphan list is written. Default C:\Temp\installer-orphans.txt

.EXAMPLE
    .\Find-OrphanedInstallerPackages.ps1                       # report only
    .\Find-OrphanedInstallerPackages.ps1 -Delete -SizeKB 6696  # delete just that family
#>
[CmdletBinding()]
param(
    [switch]$Delete,
    [int]$SizeKB = 0,
    [string]$ListPath = 'C:\Temp\installer-orphans.txt'
)
$ErrorActionPreference = 'SilentlyContinue'
$dir = 'C:\Windows\Installer'

# 1) Build the set of packages the registry still references (products + patches)
$ref = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$keys = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Products\*\InstallProperties',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Patches\*'
)
foreach ($k in $keys) {
  Get-ItemProperty $k -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.LocalPackage) { [void]$ref.Add([string]$_.LocalPackage) }
  }
}
Write-Output ("Referenced packages in registry: {0}" -f $ref.Count)
if ($ref.Count -lt 10) { Write-Output "WARNING: referenced set is suspiciously small - do NOT trust a -Delete run from this state." }

# 2) Enumerate every cached .msi/.msp and split referenced vs orphan
$all = Get-ChildItem $dir -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.msi','.msp' }
$orphans = @(); $kept = @()
foreach ($f in $all) { if ($ref.Contains($f.FullName)) { $kept += $f } else { $orphans += $f } }

$toMB = { param($x) [math]::Round((($x | Measure-Object Length -Sum).Sum)/1MB,1) }
Write-Output ("`nCached .msi/.msp total : {0} files, {1} MB" -f $all.Count, (& $toMB $all))
Write-Output ("  KEEP (referenced)    : {0} files, {1} MB" -f $kept.Count, (& $toMB $kept))
Write-Output ("  ORPHANED             : {0} files, {1} MB" -f $orphans.Count, (& $toMB $orphans))

Write-Output "`n-- Orphan size buckets (a repair loop = many copies of one size) --"
$orphans | Group-Object { [int]([math]::Round($_.Length/1KB)) } | Sort-Object Count -Descending |
  Select-Object -First 8 | ForEach-Object { Write-Output ("  {0,8:N0} KB x {1}" -f [int]$_.Name, $_.Count) }

Write-Output "`n-- Oldest / newest orphan (shows a loop's lifespan) --"
$orphans | Sort-Object LastWriteTime | Select-Object -First 1 | ForEach-Object { Write-Output ("  oldest: {0:yyyy-MM-dd HH:mm}  {1}" -f $_.LastWriteTime,$_.Name) }
$orphans | Sort-Object LastWriteTime | Select-Object -Last 1  | ForEach-Object { Write-Output ("  newest: {0:yyyy-MM-dd HH:mm}  {1}" -f $_.LastWriteTime,$_.Name) }

# 3) Save the exact orphan list
$out = Split-Path $ListPath -Parent
if (-not (Test-Path $out)) { New-Item -ItemType Directory -Path $out | Out-Null }
$orphans.FullName | Set-Content -Path $ListPath -Encoding ASCII
Write-Output "`nOrphan list written to $ListPath"

# 4) Optional deletion (orphans only, optionally one size family)
if ($Delete) {
  $targets = $orphans
  if ($SizeKB -gt 0) {
    $lo = $SizeKB * 1KB * 0.98; $hi = $SizeKB * 1KB * 1.02
    $targets = @($orphans | Where-Object { $_.Length -ge $lo -and $_.Length -le $hi })
    Write-Output ("`nDeleting only the ~{0} KB family: {1} file(s)" -f $SizeKB, $targets.Count)
  } else {
    Write-Output ("`nDeleting ALL {0} orphan(s)" -f $targets.Count)
  }
  $freed = (& $toMB $targets)
  $done = 0; $fail = 0
  foreach ($f in $targets) { try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop; $done++ } catch { $fail++ } }
  Write-Output ("Deleted {0}, failed {1}, freed ~{2} MB" -f $done, $fail, $freed)
} else {
  Write-Output "===== DONE (read-only; use -Delete to clean, ideally with -SizeKB) ====="
}
