<#
.SYNOPSIS
    Downloads Dell's PERCCLI utility and reports PERC RAID controller / physical drive / virtual drive health.

.DESCRIPTION
    Fetches the official Dell PERCCLI (ZPE self-extracting) package, extracts it to a working
    directory, and runs a set of read-only PERCCLI queries against a RAID controller:
      - controller summary (/c<N> show)
      - all physical drives, detailed (/c<N>/eall/sall show all)
      - all virtual drives (/c<N>/vall show all)
    All operations are read-only against the controller. The working directory and downloaded
    files are removed at the end of the run.

.PARAMETER WorkDir
    Local directory used to stage the download and extracted PERCCLI binary. Defaults to a
    subfolder under the system temp directory and is deleted when the script finishes.

.PARAMETER DownloadUrl
    URL to the Dell PERCCLI ZPE package. Defaults to the current Dell download link at the time
    this script was written; check Dell's support site for the latest PERCCLI build for your
    controller generation before relying on this default.

.PARAMETER ControllerIndex
    Controller number to query, as recognized by PERCCLI (e.g. 0 for the first controller).
    Defaults to 0.

.EXAMPLE
    .\Get-PercRaidHealth.ps1
    Downloads PERCCLI, queries controller 0, prints results, and cleans up.

.EXAMPLE
    .\Get-PercRaidHealth.ps1 -ControllerIndex 1 -WorkDir 'C:\Temp\perccli'
    Queries controller 1 and stages files in a custom working directory.

.NOTES
    Requires local admin rights to run perccli64.exe against the RAID controller.
    Tested against a Dell PERC H330 controller; PERCCLI works the same way across most
    PERC/MegaRAID-based controllers, but command output fields can vary by firmware.
#>

[CmdletBinding()]
param(
    [string]$WorkDir = (Join-Path $env:TEMP 'perccli-run'),
    [string]$DownloadUrl = 'https://dl.dell.com/FOLDER04476242M/43/perccli_7.1-007.0127_win_ZPE.exe',
    [int]$ControllerIndex = 0
)

$ErrorActionPreference = 'Stop'
$exe = Join-Path $WorkDir 'perccli_zpe.exe'

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Output "=== DOWNLOAD ==="
Invoke-WebRequest -Uri $DownloadUrl -OutFile $exe -UseBasicParsing
Write-Output ("downloaded: {0} bytes" -f (Get-Item $exe).Length)

Write-Output "=== EXTRACT ==="
# Dell ZPE self-extractor: /auto <dir> extracts silently
Start-Process -FilePath $exe -ArgumentList '/auto', (Join-Path $WorkDir 'x') -Wait
$cli = Get-ChildItem $WorkDir -Recurse -Filter perccli64.exe | Select-Object -First 1
if (-not $cli) {
    # fallback: some ZPE builds are plain zips with an exe stub; try Expand-Archive on a .zip copy
    Copy-Item $exe (Join-Path $WorkDir 'p.zip') -Force
    try { Expand-Archive (Join-Path $WorkDir 'p.zip') (Join-Path $WorkDir 'x2') -Force } catch {}
    $cli = Get-ChildItem $WorkDir -Recurse -Filter perccli64.exe | Select-Object -First 1
}
if (-not $cli) {
    Write-Output "FATAL: perccli64.exe not found after extraction"
    Get-ChildItem $WorkDir -Recurse | Select-Object FullName
    exit 1
}
Write-Output ("cli: " + $cli.FullName)

$ErrorActionPreference = 'SilentlyContinue'
Write-Output "`n=== CONTROLLER SUMMARY (/c$ControllerIndex show) ==="
& $cli.FullName "/c$ControllerIndex" show

Write-Output "`n=== PHYSICAL DRIVES DETAIL (/c$ControllerIndex/eall/sall show all) ==="
& $cli.FullName "/c$ControllerIndex/eall/sall" show all

Write-Output "`n=== VIRTUAL DRIVES (/c$ControllerIndex/vall show all) ==="
& $cli.FullName "/c$ControllerIndex/vall" show all

Write-Output "`n=== CLEANUP ==="
Remove-Item $WorkDir -Recurse -Force
Write-Output ("workdir removed: " + (-not (Test-Path $WorkDir)))
