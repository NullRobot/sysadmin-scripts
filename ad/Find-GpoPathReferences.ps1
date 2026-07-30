<#
.SYNOPSIS
    Scans every GPO in the domain for references to a given server, share, or
    path string (e.g. before decommissioning a file server).

.DESCRIPTION
    Generates the XML report for each GPO and searches it for the target
    string. For each hit it lists the GPO name, GUID, status, where it is
    linked, and the exact path strings found. This is the discovery step
    before a file server migration or decommission: anything that shows up
    here (login scripts, drive maps, wallpaper paths, GPP shortcuts,
    software installs) will break when the old server goes away.
    Read-only. Pair with Update-GpoUncPaths.ps1 to do the actual rewrite.

.PARAMETER SearchString
    The server name or path fragment to look for (e.g. "OLDFS01").

.EXAMPLE
    .\Find-GpoPathReferences.ps1 -SearchString OLDFS01
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SearchString
)

Import-Module GroupPolicy -ErrorAction Stop

$allGPOs = Get-GPO -All
$results = @()

foreach ($gpo in $allGPOs) {
    try {
        $xml = Get-GPOReport -Guid $gpo.Id -ReportType XML -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to read GPO '$($gpo.DisplayName)': $_"
        continue
    }

    if ($xml -imatch [regex]::Escape($SearchString)) {
        $paths = [regex]::Matches($xml, '[^<>"'']*' + [regex]::Escape($SearchString) + '[^<>"'']*') |
            ForEach-Object { $_.Value.Trim() } |
            Sort-Object -Unique

        $links = @()
        try {
            [xml]$xmlDoc = $xml
            $xmlDoc.GPO.LinksTo | ForEach-Object {
                $links += "$($_.SOMPath) (Enabled: $($_.Enabled))"
            }
        }
        catch {}

        $results += [PSCustomObject]@{
            GPOName = $gpo.DisplayName
            GPOId   = $gpo.Id.ToString()
            Status  = $gpo.GpoStatus
            LinksTo = ($links -join "; ")
            Paths   = ($paths -join "`n    ")
        }
    }
}

Write-Output "========================================="
Write-Output " GPOs referencing '$SearchString'"
Write-Output " Scanned: $($allGPOs.Count) GPOs"
Write-Output " Found:   $($results.Count) with references"
Write-Output "========================================="
Write-Output ""

if ($results.Count -eq 0) {
    Write-Output "No GPOs reference '$SearchString'."
}
else {
    foreach ($r in $results) {
        Write-Output "GPO:    $($r.GPOName)"
        Write-Output "GUID:   {$($r.GPOId)}"
        Write-Output "Status: $($r.Status)"
        Write-Output "Links:  $($r.LinksTo)"
        Write-Output "Paths:"
        Write-Output "    $($r.Paths)"
        Write-Output ""
    }
}
