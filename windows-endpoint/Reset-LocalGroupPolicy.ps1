<#
.SYNOPSIS
    Removes rogue LOCAL Group Policy overrides (Registry.pol) from a machine,
    with backup, so domain/Intune policy can win again.

.DESCRIPTION
    Symptom: a setting keeps coming back or is "managed by your organization"
    on a machine where neither domain GPO nor Intune sets it - some past tech
    or script wrote it into LOCAL Group Policy. This script:
      1. Reports the Machine and User Registry.pol files (size + mtime)
      2. Backs both up to C:\Windows\Temp\GPOBackup_<timestamp>
      3. Deletes them, wiping all local policy (domain/Intune policy is
         untouched and re-applies on the next refresh)
      4. Optionally clears specific HKLM/HKCU Policies registry subtrees you
         name (local policy writes persist in the registry even after the
         .pol file is gone)
      5. Runs gpupdate /force
    Safe to run as SYSTEM via RMM. User should sign out/in afterward.
    DESTRUCTIVE to local policy by design - anything intentionally set in
    gpedit.msc on this machine is removed (the backup allows restore).

.PARAMETER ClearPolicyKey
    Optional registry keys (e.g. "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer")
    to also delete recursively after removing the .pol files.

.EXAMPLE
    .\Reset-LocalGroupPolicy.ps1 -ClearPolicyKey "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$ClearPolicyKey
)

Write-Host "=== LOCAL GROUP POLICY RESET ===" -ForegroundColor Cyan

$localGpoMachine = "$env:SystemRoot\System32\GroupPolicy\Machine\Registry.pol"
$localGpoUser = "$env:SystemRoot\System32\GroupPolicy\User\Registry.pol"

foreach ($p in @($localGpoMachine, $localGpoUser)) {
    if (Test-Path $p) {
        $item = Get-Item $p
        Write-Host "FOUND $($p): $($item.Length) bytes, modified $($item.LastWriteTime)" -ForegroundColor Yellow
    } else {
        Write-Host "Not present: $p"
    }
}

# Back up before removing
$backupDir = "C:\Windows\Temp\GPOBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
if (Test-Path $localGpoMachine) {
    Copy-Item $localGpoMachine "$backupDir\Machine_Registry.pol" -Force
    Write-Host "Backed up Machine Registry.pol to $backupDir"
}
if (Test-Path $localGpoUser) {
    Copy-Item $localGpoUser "$backupDir\User_Registry.pol" -Force
    Write-Host "Backed up User Registry.pol to $backupDir"
}

# Delete the Registry.pol files
Write-Host "`n=== REMOVING LOCAL GPO FILES ===" -ForegroundColor Yellow
foreach ($p in @($localGpoMachine, $localGpoUser)) {
    if ((Test-Path $p) -and $PSCmdlet.ShouldProcess($p, "Delete local policy file")) {
        Remove-Item $p -Force
        Write-Host "Deleted $p"
    }
}

# Clear the specified policy registry keys that local GPO wrote to
if ($ClearPolicyKey) {
    Write-Host "`n=== CLEARING POLICY REGISTRY KEYS ===" -ForegroundColor Yellow
    foreach ($key in $ClearPolicyKey) {
        if (Test-Path $key) {
            if ($PSCmdlet.ShouldProcess($key, "Remove recursively")) {
                try {
                    Remove-Item $key -Recurse -Force
                    Write-Host "Removed: $key"
                } catch {
                    Write-Host "Could not remove: $key - $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "Not present: $key"
        }
    }
}

# Force policy refresh so domain/Intune settings re-apply
Write-Host "`n=== RUNNING GPUPDATE /FORCE ===" -ForegroundColor Cyan
gpupdate /force

Write-Host "`n=== DONE ===" -ForegroundColor Green
Write-Host "Backup saved at: $backupDir"
Write-Host "User must sign out and back in for changes to fully take effect."
