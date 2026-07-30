<#
.SYNOPSIS
    Emergency C: drive space reclaim - cleans only known-safe caches and
    reports exactly how much was freed.

.DESCRIPTION
    For "server/VDI host at 99% disk, users are down" moments. Cleans, in
    order of typical yield:
      1. Windows Update download cache (stops/starts wuauserv around it)
      2. C:\Windows\Temp
      3. Every user profile's AppData\Local\Temp over 100 MB
      4. $WINDOWS.~BT upgrade leftovers
      5. C:\adobeTemp (Acrobat's update droppings)
      6. DISM component store cleanup with /ResetBase (several GB on old
         machines; NOTE /ResetBase makes installed updates permanent -
         they can no longer be uninstalled)
    Reports the Windows Installer cache size as info only (never deletes it -
    orphan cleanup there needs dedicated tooling). Prints free-space before/
    after. Run as SYSTEM or admin. Deletions are safe-by-location, but files
    in Temp that are open will simply be skipped.

.PARAMETER SkipComponentCleanup
    Skip the DISM step (it takes several minutes and pins update rollback).

.EXAMPLE
    .\Invoke-SafeDiskCleanup.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$SkipComponentCleanup
)

$before = (Get-PSDrive C).Free

# 1. Windows Update cache
$wuPath = "C:\Windows\SoftwareDistribution\Download"
if ((Test-Path $wuPath) -and $PSCmdlet.ShouldProcess($wuPath, "Clear")) {
    $size = (Get-ChildItem $wuPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    Write-Host "Windows Update cache: $([math]::Round($size/1GB,2)) GB - cleaning..."
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    Remove-Item "$wuPath\*" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Service wuauserv -ErrorAction SilentlyContinue
}

# 2. Windows Temp
$tempPath = "C:\Windows\Temp"
if ((Test-Path $tempPath) -and $PSCmdlet.ShouldProcess($tempPath, "Clear")) {
    $size = (Get-ChildItem $tempPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    Write-Host "Windows Temp: $([math]::Round($size/1GB,2)) GB - cleaning..."
    Remove-Item "$tempPath\*" -Recurse -Force -ErrorAction SilentlyContinue
}

# 3. User temp folders (all profiles), only when over 100 MB
Get-ChildItem "C:\Users" -Directory | ForEach-Object {
    $uTemp = "$($_.FullName)\AppData\Local\Temp"
    if (Test-Path $uTemp) {
        $size = (Get-ChildItem $uTemp -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
        if ($size -gt 100MB -and $PSCmdlet.ShouldProcess($uTemp, "Clear")) {
            Write-Host "User temp $($_.Name): $([math]::Round($size/1MB,0)) MB - cleaning..."
            Remove-Item "$uTemp\*" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# 4. Old Windows upgrade leftovers
if ((Test-Path "C:\`$WINDOWS.~BT") -and $PSCmdlet.ShouldProcess('C:\$WINDOWS.~BT', "Remove")) {
    $size = (Get-ChildItem "C:\`$WINDOWS.~BT" -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    Write-Host "Windows upgrade leftovers: $([math]::Round($size/1GB,2)) GB - cleaning..."
    Remove-Item "C:\`$WINDOWS.~BT" -Recurse -Force -ErrorAction SilentlyContinue
}

# 5. Adobe temp
if ((Test-Path "C:\adobeTemp") -and $PSCmdlet.ShouldProcess("C:\adobeTemp", "Clear")) {
    $size = (Get-ChildItem "C:\adobeTemp" -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    Write-Host "Adobe temp: $([math]::Round($size/1GB,2)) GB - cleaning..."
    Remove-Item "C:\adobeTemp\*" -Recurse -Force -ErrorAction SilentlyContinue
}

# 6. Windows component store cleanup
if (-not $SkipComponentCleanup -and $PSCmdlet.ShouldProcess("Component store", "DISM /StartComponentCleanup /ResetBase")) {
    Write-Host "Running DISM component cleanup (takes a few minutes; makes installed updates permanent)..."
    dism /online /Cleanup-Image /StartComponentCleanup /ResetBase 2>&1
}

# 7. Windows Installer cache - info only, never delete blindly
$msiPath = "C:\Windows\Installer"
if (Test-Path $msiPath) {
    $size = (Get-ChildItem $msiPath -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    Write-Host "Windows Installer cache: $([math]::Round($size/1GB,2)) GB (info only - not touched)"
}

# Results
$after = (Get-PSDrive C).Free
Write-Host "`n=== RESULTS ===" -ForegroundColor Cyan
Write-Host "Free before: $([math]::Round($before/1GB,2)) GB"
Write-Host "Free after:  $([math]::Round($after/1GB,2)) GB"
Write-Host "Freed: $([math]::Round(($after - $before)/1GB, 2)) GB" -ForegroundColor Green
