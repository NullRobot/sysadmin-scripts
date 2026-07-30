<#
.SYNOPSIS
    Find Group Policy Preference drive maps (and other GPP/SYSVOL content) that reference a string.
.DESCRIPTION
    Read-only. When a decommissioned server, renamed share, or dead UNC path is still being
    pushed to clients, the culprit is usually a GPP Drives.xml or a logon script left in SYSVOL.
    This walks every GPP Drives.xml under the domain's SYSVOL, prints the mapped paths, flags any
    that contain the search string, and also greps the broader SYSVOL/NETLOGON policy tree
    (xml/bat/cmd/vbs/ps1/ini/kix) for the same string. Run on a DC as an account that can read SYSVOL.
.PARAMETER Domain
    FQDN of the domain to sweep. Defaults to the current machine's domain.
.PARAMETER Pattern
    The string to hunt for (a dead server name, old share, UNC fragment). Case-insensitive.
.NOTES
    Requires the GroupPolicy module for the drive-map detail. The SYSVOL grep works regardless.
#>
[CmdletBinding()]
param(
    [string]$Domain = $env:USERDNSDOMAIN,
    [Parameter(Mandatory)][string]$Pattern
)

$ErrorActionPreference = 'SilentlyContinue'
Import-Module GroupPolicy -ErrorAction SilentlyContinue

$polRoot = "\\$Domain\SYSVOL\$Domain\Policies"
Write-Output "==== GPP Drives.xml under $Domain (flagging '$Pattern') ===="
$dx = Get-ChildItem $polRoot -Recurse -Filter 'Drives.xml' -ErrorAction SilentlyContinue
Write-Output "Found $($dx.Count) Drives.xml"
foreach ($f in $dx) {
    $txt   = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
    $guid  = ($f.FullName -split '\\Policies\\')[1].Split('\')[0]
    $paths = ([regex]::Matches($txt, 'path="([^"]*)"') | ForEach-Object { $_.Groups[1].Value }) -join ' ; '
    $flag  = if ($txt -match [regex]::Escape($Pattern)) { "   <<< $Pattern PRESENT" } else { '' }
    Write-Output "GPO $guid$flag"
    Write-Output "   paths: $paths"
}

Write-Output "`n==== SYSVOL policy-file grep for '$Pattern' ===="
Get-ChildItem $polRoot -Recurse -Include *.xml,*.bat,*.cmd,*.kix,*.vbs,*.ps1,*.ini -ErrorAction SilentlyContinue |
    Select-String -Pattern $Pattern -SimpleMatch -ErrorAction SilentlyContinue |
    Select-Object -First 40 Path, LineNumber, @{n='Line';e={ $_.Line.Trim() }} | Format-List | Out-String

Write-Output "==== NETLOGON grep for '$Pattern' ===="
Get-ChildItem "\\$Domain\NETLOGON" -Recurse -ErrorAction SilentlyContinue |
    Select-String -Pattern $Pattern -SimpleMatch -ErrorAction SilentlyContinue |
    Select-Object -First 20 Path, LineNumber, @{n='Line';e={ $_.Line.Trim() }} | Format-List | Out-String
Write-Output "(done)"
