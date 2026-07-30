<#
.SYNOPSIS
    Junction-aware disk-usage triage for a Windows volume (find what's eating the drive).
.DESCRIPTION
    Read-only. Run as SYSTEM (Datto RMM) or admin. The "C: is full, what's using it" answer.
    Uses a manual stack-based directory walk that SKIPS reparse points (junctions), so junction
    loops never double-count. Reports: all fixed volumes, top-level folder sizes on the target drive,
    the "usual suspects" (WU download cache, Temp, CCMCache, Package Cache, Windows\Installer, IIS
    logs), a loose-file census of Windows\Temp root, WinSxS size, recycle bin, per-user profile sizes,
    VSS shadow-storage usage, pagefile/hiberfil, and the 20 largest files over 500 MB. Changes nothing.
.PARAMETER Drive
    Drive letter to scan (no colon). Default C.
.NOTES
    On big drives the full walk can take a minute or two.
#>
[CmdletBinding()]
param(
    [string]$Drive = 'C'
)

$ErrorActionPreference = 'SilentlyContinue'
$root = "${Drive}:\"

function Get-DirSize([string]$path) {
    $stack = New-Object System.Collections.Stack; $stack.Push($path); $total = [long]0
    while ($stack.Count -gt 0) {
        $d = $stack.Pop()
        try {
            foreach ($e in [IO.Directory]::EnumerateFileSystemEntries($d)) {
                $a = [IO.File]::GetAttributes($e)
                if ($a -band [IO.FileAttributes]::ReparsePoint) { continue }
                if ($a -band [IO.FileAttributes]::Directory) { $stack.Push($e) }
                else { $total += ([IO.FileInfo]$e).Length }
            }
        } catch {}
    }
    $total
}

Write-Output "=== Volumes ==="
Get-Volume | Where-Object DriveLetter | ForEach-Object {
    "{0}:  {1,8:N1} GB free of {2,8:N1} GB  ({3})" -f $_.DriveLetter, ($_.SizeRemaining/1GB), ($_.Size/1GB), $_.FileSystemLabel }

Write-Output "`n=== Top-level $root folder sizes (junction-aware) ==="
Get-ChildItem $root -Directory -Force | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | ForEach-Object {
    [pscustomobject]@{ GB = [math]::Round((Get-DirSize $_.FullName)/1GB,2); Name = $_.FullName }
} | Sort-Object GB -Descending | Select-Object -First 15 | ForEach-Object { "{0,8:N2} GB  {1}" -f $_.GB, $_.Name }

Write-Output "`n=== Usual suspects ==="
foreach ($p in "$root`Windows\SoftwareDistribution\Download","$root`Windows\Temp","$root`Temp","$root`Windows\CCMCache","$root`ProgramData\Package Cache","$root`Windows\Installer","$root`inetpub\logs","$root`Windows\System32\LogFiles") {
    if (Test-Path $p) { "{0,8:N2} GB  {1}" -f ((Get-DirSize $p)/1GB), $p }
}
Write-Output ("{0,8:N2} GB  WinSxS" -f ((Get-DirSize "$root`Windows\WinSxS")/1GB))
Write-Output ("{0,8:N2} GB  Recycle Bin" -f ((Get-DirSize "$root`$Recycle.Bin")/1GB))

Write-Output "`n=== User profiles > 500 MB ==="
Get-ChildItem "$root`Users" -Directory -Force | ForEach-Object {
    $s = Get-DirSize $_.FullName
    if ($s -gt 500MB) { "{0,8:N2} GB  {1}" -f ($s/1GB), $_.FullName }
}

Write-Output "`n=== VSS shadow storage ==="
vssadmin list shadowstorage 2>$null | Select-String 'Used|Allocated|Maximum'

Write-Output "`n=== Pagefile / hiberfil ==="
foreach ($f in "$root`pagefile.sys","$root`hiberfil.sys","$root`swapfile.sys") {
    if (Test-Path $f) { "{0,8:N2} GB  {1}" -f (([IO.FileInfo]$f).Length/1GB), $f }
}

Write-Output "`n=== 20 largest files > 500 MB (junction-aware) ==="
$big = New-Object System.Collections.Generic.List[object]
$stack = New-Object System.Collections.Stack; $stack.Push($root)
while ($stack.Count -gt 0) {
    $d = $stack.Pop()
    try {
        foreach ($e in [IO.Directory]::EnumerateFileSystemEntries($d)) {
            $a = [IO.File]::GetAttributes($e)
            if ($a -band [IO.FileAttributes]::ReparsePoint) { continue }
            if ($a -band [IO.FileAttributes]::Directory) { $stack.Push($e) }
            else { $fi = [IO.FileInfo]$e; if ($fi.Length -gt 500MB) { $big.Add($fi) } }
        }
    } catch {}
}
$big | Sort-Object Length -Descending | Select-Object -First 20 | ForEach-Object { "{0,8:N2} GB  {1}  (mod {2:yyyy-MM-dd})" -f ($_.Length/1GB), $_.FullName, $_.LastWriteTime }
Write-Output "DONE"
