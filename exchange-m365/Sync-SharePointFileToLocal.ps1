<#
.SYNOPSIS
    Unattended one-way sync of the newest matching file from a SharePoint document
    library folder down to a fixed local path, via Microsoft Graph app-only auth.
    No modules required - pure REST, works on Windows PowerShell 5.1.

.DESCRIPTION
    The pattern behind "user uploads X to SharePoint, a server needs the latest copy
    locally" (digital signage videos, price lists, config bundles) with no human in
    the loop. Designed to run as a scheduled task.

    Flow:
      1. Client-credentials token from Entra (app registration needs application
         permissions Files.Read.All and/or Sites.Read.All, admin-consented)
      2. Lists the target folder, picks the newest file matching -FilePattern
      3. Skips the download entirely if the local copy is already current
         (same size, not older than the SharePoint modified time)
      4. Downloads to a .downloading temp file, verifies size, rotates the previous
         copy to .old, then renames into place (atomic on the same volume)

    SETUP: put the app registration's client secret in the environment variable
    named by -SecretEnvVar (default GRAPH_CLIENT_SECRET). The secret is never
    stored in this script. To find your DriveId:
      GET https://graph.microsoft.com/v1.0/sites/{hostname}:/sites/{site}?$expand=drives

.PARAMETER TenantId
    Entra tenant GUID.

.PARAMETER ClientId
    App registration (client) ID.

.PARAMETER DriveId
    Graph drive ID of the document library.

.PARAMETER FolderPath
    Folder path within the drive, with leading slash (e.g. '/TV-Content').

.PARAMETER FilePattern
    Regex the filename must match. Default '\.mp4$'.

.PARAMETER TargetPath
    Full local path the newest file lands at (fixed name, e.g. C:\Content\current.mp4).

.PARAMETER SecretEnvVar
    Name of the environment variable holding the client secret. Default GRAPH_CLIENT_SECRET.

.PARAMETER LogFile
    Append-log path. Default: <target dir>\sync_log.txt.

.EXAMPLE
    $env:GRAPH_CLIENT_SECRET = '<secret>'
    .\Sync-SharePointFileToLocal.ps1 -TenantId $tid -ClientId $cid -DriveId $did `
        -FolderPath '/TV-Content' -TargetPath 'C:\Content\current.mp4'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$ClientId,
    [Parameter(Mandatory)][string]$DriveId,
    [Parameter(Mandatory)][string]$FolderPath,
    [string]$FilePattern = '\.mp4$',
    [Parameter(Mandatory)][string]$TargetPath,
    [string]$SecretEnvVar = 'GRAPH_CLIENT_SECRET',
    [string]$LogFile
)

$ErrorActionPreference = 'Stop'

# Windows PowerShell 5.1 defaults to TLS 1.0/1.1; Microsoft endpoints require TLS 1.2+
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$clientSecret = [Environment]::GetEnvironmentVariable($SecretEnvVar)
if (-not $clientSecret) { throw "Client secret not found in env var '$SecretEnvVar'. Set it before running." }

$localDir   = Split-Path $TargetPath -Parent
$targetName = Split-Path $TargetPath -Leaf
$oldPath    = "$TargetPath.old"
$tempPath   = "$TargetPath.downloading"
if (-not $LogFile) { $LogFile = Join-Path $localDir 'sync_log.txt' }
if (-not (Test-Path $localDir)) { New-Item -ItemType Directory -Path $localDir | Out-Null }

function Write-Log($msg) {
    $line = "[{0:yyyy-MM-dd HH:mm:ss}] {1}" -f (Get-Date), $msg
    Write-Output $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

# 1. Auth (client credentials)
Write-Log "Authenticating to Microsoft Graph..."
$tokenBody = @{
    grant_type    = 'client_credentials'
    client_id     = $ClientId
    client_secret = $clientSecret
    scope         = 'https://graph.microsoft.com/.default'
}
$tokenResp = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -Method POST -Body $tokenBody -ContentType 'application/x-www-form-urlencoded'
$headers = @{ Authorization = "Bearer $($tokenResp.access_token)" }

# 2. List the folder, pick the newest matching file
Write-Log "Listing SharePoint folder '$FolderPath'..."
$listUri = "https://graph.microsoft.com/v1.0/drives/$DriveId/root:${FolderPath}:/children"
$listing = Invoke-RestMethod -Uri $listUri -Headers $headers -Method GET

$matches0 = $listing.value | Where-Object { $_.name -match $FilePattern -and $_.file }
if (-not $matches0) {
    Write-Log "No files matching '$FilePattern' found. Nothing to do."
    exit 0
}

$latest = $matches0 | Sort-Object lastModifiedDateTime -Descending | Select-Object -First 1
$spSize     = $latest.size
$spModified = [datetime]$latest.lastModifiedDateTime  # UTC
Write-Log ("Latest match: '{0}' ({1:N2} MB, modified {2:yyyy-MM-dd HH:mm} UTC)" -f $latest.name, ($spSize/1MB), $spModified)

# 3. Skip if local copy is already current
if (Test-Path $TargetPath) {
    $local = Get-Item -LiteralPath $TargetPath
    if ($spModified -le $local.LastWriteTimeUtc -and $local.Length -eq $spSize) {
        Write-Log "Local target already current. Nothing to do."
        exit 0
    }
    Write-Log "SharePoint version is newer or different size. Updating."
} else {
    Write-Log "Local target missing. Will create."
}

# 4. Download to temp file and verify size
$downloadUri = "https://graph.microsoft.com/v1.0/drives/$DriveId/items/$($latest.id)/content"
Write-Log "Downloading..."
if (Test-Path $tempPath) { Remove-Item -LiteralPath $tempPath -Force }
try {
    Invoke-RestMethod -Uri $downloadUri -Headers $headers -Method GET -OutFile $tempPath -ErrorAction Stop
} catch {
    Write-Log "ERROR downloading: $($_.Exception.Message)"
    if (Test-Path $tempPath) { Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue }
    exit 1
}
$dl = Get-Item -LiteralPath $tempPath
Write-Log ("Downloaded {0:N2} MB" -f ($dl.Length/1MB))

if ([math]::Abs($dl.Length - $spSize) -gt 1024) {
    Write-Log ("Size mismatch (downloaded {0} bytes, expected {1}). Aborting." -f $dl.Length, $spSize)
    Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
    exit 1
}

# 5. Rotate previous copy and rename into place
if (Test-Path $TargetPath) {
    if (Test-Path $oldPath) { Remove-Item -LiteralPath $oldPath -Force }
    Rename-Item -LiteralPath $TargetPath -NewName "$targetName.old"
    Write-Log "Rotated previous copy -> .old"
}
Rename-Item -LiteralPath $tempPath -NewName $targetName
$final = Get-Item -LiteralPath $TargetPath
Write-Log ("Replaced target: {0:N2} MB, LastWriteTime {1}" -f ($final.Length/1MB), $final.LastWriteTime)
Write-Log "Sync complete."
