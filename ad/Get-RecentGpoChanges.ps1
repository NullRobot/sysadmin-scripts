<#
.SYNOPSIS
    List GPOs modified in the last N days with their links, security filtering, and CSEs.
.DESCRIPTION
    Read-only. The fast "what GPO changed recently" audit - the first thing to check when logon,
    drive-map, or policy behavior shifts across a site, or when investigating a suspicious GPO edit.
    For every GPO modified within the window it prints the AD/SYSVOL version numbers, where it's
    linked (SOMPath), the trustees that have Apply Group Policy (security filtering), and the
    computer/user client-side extensions it carries. Run on a DC or a box with the GroupPolicy module.
.PARAMETER Days
    Look-back window in days. Default 45.
.NOTES
    Requires the GroupPolicy module (RSAT).
#>
[CmdletBinding()]
param(
    [int]$Days = 45
)

$ErrorActionPreference = 'Stop'
Write-Output "HOST: $env:COMPUTERNAME  DOMAIN: $env:USERDNSDOMAIN  NOW: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

$cut  = (Get-Date).AddDays(-$Days)
$gpos = Get-GPO -All | Where-Object { $_.ModificationTime -ge $cut } | Sort-Object ModificationTime -Descending

Write-Output "`n=== GPOs modified in the last $Days days ==="
if (-not $gpos) { Write-Output "(none)"; return }
foreach ($g in $gpos) {
    Write-Output ("{0} | {1} | modified {2} | ver AD/SYS user {3}/{4} computer {5}/{6}" -f `
        $g.DisplayName, $g.Id, $g.ModificationTime.ToString('yyyy-MM-dd HH:mm:ss'), `
        $g.User.DSVersion, $g.User.SysvolVersion, $g.Computer.DSVersion, $g.Computer.SysvolVersion)
}

Write-Output "`n=== Detail ==="
foreach ($g in $gpos) {
    Write-Output "--- $($g.DisplayName) [$($g.Id)] ---"
    [xml]$rpt = Get-GPOReport -Guid $g.Id -ReportType Xml
    $links = @($rpt.GPO.LinksTo | ForEach-Object { $_.SOMPath })
    Write-Output ("Links: " + $(if ($links) { $links -join '; ' } else { '(unlinked)' }))
    $filters = @($rpt.GPO.SecurityDescriptor.Permissions.TrusteePermissions |
        Where-Object { $_.Type.PermissionType -eq 'Apply Group Policy' } |
        ForEach-Object { $_.Trustee.Name.'#text' })
    Write-Output ("ApplyGroupPolicy: " + $(if ($filters) { $filters -join '; ' } else { '(none)' }))
    Write-Output ("ComputerExtensions: " + (@($rpt.GPO.Computer.ExtensionData.Name) -join '; '))
    Write-Output ("UserExtensions: " + (@($rpt.GPO.User.ExtensionData.Name) -join '; '))
    Write-Output ""
}
