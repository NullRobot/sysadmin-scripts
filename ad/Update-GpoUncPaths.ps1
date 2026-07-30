<#
.SYNOPSIS
    Rewrites UNC path references inside GPOs (Preferences XML + Registry.pol
    values) from an old server/share to a new location, with correct version
    bumps so clients actually re-apply the policy.

.DESCRIPTION
    The second half of a file-server migration/decommission (use
    Find-GpoPathReferences.ps1 first to discover which GPOs are affected).
    For each specified GPO it:
      1. Edits every Preferences *.xml under the GPO's SYSVOL folder,
         replacing each Old->New path pair (case-insensitive), preserving the
         file encoding and leaving a .bak backup beside each changed file.
      2. Optionally rewrites Admin Template registry VALUES (e.g. Wallpaper,
         SCRNSAVE.EXE) via Get/Set-GPRegistryValue for the keys you name.
      3. Bumps the GPO version in BOTH gpt.ini and the AD object for GPOs
         that only had XML edits (direct SYSVOL edits do NOT auto-bump, and
         without the bump clients never re-download the policy). Registry
         edits via Set-GPRegistryValue auto-bump on their own.
      4. Re-scans each GPO report and prints any remaining old references.

    IMPORTANT: copy the referenced files to the new location BEFORE running
    this (a good destination is inside SYSVOL itself, e.g.
    \\domain\SYSVOL\domain\GPOFiles\..., which replicates to every DC).
    Run on a DC as a domain admin. Test with gpupdate /force on one client.

.PARAMETER GpoGuid
    GUIDs of the GPOs to rewrite (with or without braces).

.PARAMETER PathMap
    Array of hashtables @{Old="\\OLDFS\Share\"; New="\\domain\SYSVOL\domain\GPOFiles\"}.
    Include trailing backslashes so replacements stay path-safe.

.PARAMETER RegistryValueCheck
    Optional array of hashtables @{Key="HKCU\Control Panel\Desktop"; Value="Wallpaper"}
    to also rewrite inside Admin Templates (Registry.pol) for each GPO.

.PARAMETER OldServerPattern
    The string that marks a value as needing rewrite (e.g. "OLDFS01").
    Defaults to the Old value of the first PathMap entry.

.EXAMPLE
    .\Update-GpoUncPaths.ps1 -GpoGuid '{804a27a6-...}' `
        -PathMap @(@{Old='\\OLDFS01\GPOFiles\'; New='\\corp.local\SYSVOL\corp.local\GPOFiles\'}) `
        -RegistryValueCheck @(@{Key='HKCU\Control Panel\Desktop'; Value='Wallpaper'})
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string[]]$GpoGuid,
    [Parameter(Mandatory)]
    [hashtable[]]$PathMap,
    [hashtable[]]$RegistryValueCheck,
    [string]$OldServerPattern
)

Import-Module GroupPolicy -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

$domain = (Get-ADDomain).DNSRoot
$domainDN = (Get-ADDomain).DistinguishedName
$policiesBase = "\\$domain\SYSVOL\$domain\Policies"
if (-not $OldServerPattern) { $OldServerPattern = $PathMap[0].Old }

# ---------- PHASE 1: Update GPO Preferences XML files ----------
Write-Output "`n===== PHASE 1: Update GPO Preferences XML ====="
$xmlUpdated = @()

foreach ($guid in $GpoGuid) {
    $braced = if ($guid -match '^\{') { $guid } else { "{$guid}" }
    $clean = $braced.Trim('{}')
    $gpoPath = "$policiesBase\$braced"
    $gpoName = (Get-GPO -Guid $clean).DisplayName

    if (-not (Test-Path $gpoPath)) {
        Write-Warning "  GPO folder not found: $gpoPath [$gpoName]"
        continue
    }

    $xmlFiles = Get-ChildItem -Path $gpoPath -Recurse -Include "*.xml" -ErrorAction SilentlyContinue
    $gpoChanged = $false

    foreach ($xmlFile in $xmlFiles) {
        # Read with encoding detection so we can write it back identically
        $reader = [System.IO.StreamReader]::new($xmlFile.FullName, $true)
        $content = $reader.ReadToEnd()
        $encoding = $reader.CurrentEncoding
        $reader.Close()

        $original = $content
        foreach ($r in $PathMap) {
            $content = $content -ireplace [regex]::Escape($r.Old), $r.New
        }

        if ($content -ne $original -and $PSCmdlet.ShouldProcess($xmlFile.FullName, "Rewrite UNC paths")) {
            Copy-Item $xmlFile.FullName "$($xmlFile.FullName).bak" -Force
            [System.IO.File]::WriteAllText($xmlFile.FullName, $content, $encoding)
            Write-Output "  Updated: $($xmlFile.FullName) [$gpoName]"
            $gpoChanged = $true
        }
    }
    if ($gpoChanged) { $xmlUpdated += $braced }
}

# ---------- PHASE 2: Update Admin Template registry values ----------
if ($RegistryValueCheck) {
    Write-Output "`n===== PHASE 2: Update Admin Templates (Registry.pol) ====="
    foreach ($guid in $GpoGuid) {
        $clean = $guid.Trim('{}')
        $gpoName = (Get-GPO -Guid $clean).DisplayName
        foreach ($rk in $RegistryValueCheck) {
            try {
                $val = Get-GPRegistryValue -Guid $clean -Key $rk.Key -ValueName $rk.Value -ErrorAction Stop
                if ($val.Value -imatch [regex]::Escape($OldServerPattern)) {
                    $newVal = $val.Value
                    foreach ($r in $PathMap) {
                        $newVal = $newVal -ireplace [regex]::Escape($r.Old), $r.New
                    }
                    if ($PSCmdlet.ShouldProcess("$gpoName $($rk.Key)\$($rk.Value)", "Set to $newVal")) {
                        Set-GPRegistryValue -Guid $clean -Key $rk.Key -ValueName $rk.Value -Value $newVal -Type String -ErrorAction Stop
                        Write-Output "  Updated registry: $gpoName -> $($rk.Key)\$($rk.Value)"
                        Write-Output "    Old: $($val.Value)"
                        Write-Output "    New: $newVal"
                    }
                }
            }
            catch [System.Runtime.InteropServices.COMException] {
                # Key/value doesn't exist in this GPO, skip
            }
            catch {
                if ($_.Exception.Message -notmatch "does not exist|cannot find") {
                    Write-Warning "  Error reading $gpoName $($rk.Key): $_"
                }
            }
        }
    }
}

# ---------- PHASE 3: Version bump for XML-only edits ----------
Write-Output "`n===== PHASE 3: Version bump for XML-edited GPOs ====="
# Set-GPRegistryValue auto-bumps versions. GPOs that ONLY had XML edits must
# be bumped manually or clients will never re-apply. +65536 bumps the USER
# config version; use +1 for machine-side-only preference edits.
foreach ($braced in $xmlUpdated) {
    $clean = $braced.Trim('{}')
    $gpoName = (Get-GPO -Guid $clean).DisplayName

    $gptIni = "$policiesBase\$braced\gpt.ini"
    if ((Test-Path $gptIni) -and $PSCmdlet.ShouldProcess($gpoName, "Bump gpt.ini + AD versionNumber")) {
        $iniContent = Get-Content $gptIni
        $newIni = $iniContent | ForEach-Object {
            if ($_ -match '^Version=(\d+)') {
                "Version=$([int]$Matches[1] + 65536)"
            } else { $_ }
        }
        Set-Content $gptIni -Value $newIni

        try {
            $dn = "CN=$braced,CN=Policies,CN=System,$domainDN"
            $adObj = Get-ADObject $dn -Properties versionNumber
            Set-ADObject $dn -Replace @{versionNumber = ($adObj.versionNumber + 65536)}
            Write-Output "  Version bumped: $gpoName (AD + SYSVOL)"
        }
        catch {
            Write-Warning "  Failed to bump AD version for ${gpoName}: $_"
        }
    }
}

# ---------- PHASE 4: Verify ----------
Write-Output "`n===== PHASE 4: Verification ====="
$remaining = @()
foreach ($guid in $GpoGuid) {
    $clean = $guid.Trim('{}')
    $gpoName = (Get-GPO -Guid $clean).DisplayName
    $xml = Get-GPOReport -Guid $clean -ReportType XML
    if ($xml -imatch [regex]::Escape($OldServerPattern)) {
        $remaining += $gpoName
        $ctx = [regex]::Matches($xml, '(?i).{0,60}' + [regex]::Escape($OldServerPattern) + '.{0,60}')
        foreach ($c in $ctx) {
            $snip = ($c.Value -replace '<[^>]+>', ' ') -replace '\s+', ' '
            Write-Output "  STILL FOUND in ${gpoName}: $($snip.Trim())"
        }
    }
}

if ($remaining.Count -eq 0) {
    Write-Output "  All processed GPOs are clean. No remaining '$OldServerPattern' references."
} else {
    Write-Output "`n  WARNING: $($remaining.Count) GPO(s) still reference '$OldServerPattern'."
}
Write-Output "`nDone. Run 'gpupdate /force' on a test client to verify."
