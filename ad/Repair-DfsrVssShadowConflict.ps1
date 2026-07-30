<#
.SYNOPSIS
    Recovers a DFSR service wedged by stuck VSS shadow copies (classic SYSVOL
    replication stall where DFSR holds or trips over a shadow-copy set).

.DESCRIPTION
    Symptom pattern: DFSR event log shows initialization/journal errors, SYSVOL stops
    replicating, and vssadmin cannot delete the shadow copies ("snapshot set is in
    use" or silent failure) because DFSR itself holds a VSS context.

    Fix sequence, escalating only as needed:
      1. Stop DFSR (releases any VSS context it holds)
      2. diskshadow "set context persistent; delete shadows all"
      3. If shadows remain: diskshadow with volatile context
      4. If shadows STILL remain: per-object WMI delete (Win32_ShadowCopy.Delete)
      5. Start DFSR, dfsrdiag pollad, wait, then show the latest DFSR events
         (look for 5004 "connection established" with no matching 5014 error)

    DESTRUCTIVE: deletes ALL VSS shadow copies on the server, which wipes
    Previous Versions history on every volume. Confirm the customer is not
    relying on Previous Versions before running. Backup snapshots held by a
    backup product (not Windows VSS) are unaffected.

    Run elevated directly on the affected server.

.EXAMPLE
    .\Repair-DfsrVssShadowConflict.ps1 -Confirm:$false
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param()

if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Stop DFSR and DELETE ALL VSS shadow copies (wipes Previous Versions)')) { return }

Write-Host "`n=== BEFORE ===" -ForegroundColor Cyan
$before = (Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Host "  Shadow copies: $before"
Get-Service DFSR | Format-Table Status, Name

Write-Host "`n=== Stopping DFSR (releases any VSS context it holds) ===" -ForegroundColor Cyan
Stop-Service DFSR -Force
(Get-Service DFSR).WaitForStatus('Stopped', '00:00:30')
Get-Service DFSR | Format-Table Status, Name

Write-Host "`n=== Attempt 1: diskshadow with persistent context ===" -ForegroundColor Cyan
$ds = @"
set context persistent
delete shadows all
exit
"@
$ds | Out-File -FilePath C:\Windows\Temp\ds-del.txt -Encoding ASCII
& diskshadow.exe /s C:\Windows\Temp\ds-del.txt
Remove-Item C:\Windows\Temp\ds-del.txt -Force -ErrorAction SilentlyContinue
$mid = (Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Host "  After diskshadow persistent: $mid"

if ($mid -gt 0) {
    Write-Host "`n=== Attempt 2: diskshadow with volatile context ===" -ForegroundColor Cyan
    $ds2 = @"
set context volatile
delete shadows all
exit
"@
    $ds2 | Out-File -FilePath C:\Windows\Temp\ds-del2.txt -Encoding ASCII
    & diskshadow.exe /s C:\Windows\Temp\ds-del2.txt
    Remove-Item C:\Windows\Temp\ds-del2.txt -Force -ErrorAction SilentlyContinue
    Write-Host "  After diskshadow volatile: $((Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | Measure-Object).Count)"
}

$still = (Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | Measure-Object).Count
if ($still -gt 0) {
    Write-Host "`n=== Attempt 3: WMI direct delete (per-object) ===" -ForegroundColor Cyan
    Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $id = $_.ID
            $_.Delete()
            Write-Host "  Deleted $id"
        } catch { Write-Host "  FAIL $id -> $_" }
    }
}

Write-Host "`n=== Starting DFSR ===" -ForegroundColor Cyan
Start-Service DFSR
Start-Sleep -Seconds 3
Get-Service DFSR | Format-Table Status, Name

Write-Host "`n=== dfsrdiag pollad (pick up AD config) ==="
& dfsrdiag.exe pollad

Write-Host "`n=== Waiting 30 seconds for replication to initiate ==="
Start-Sleep -Seconds 30

Write-Host "`n=== AFTER ===" -ForegroundColor Cyan
$after = (Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Host "  Shadow copies: $after"

Write-Host "`n=== Latest 12 DFSR events (look for 5004 without 5014) ==="
Get-WinEvent -LogName 'DFS Replication' -MaxEvents 12 -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, LevelDisplayName, @{n='Msg';e={($_.Message -split "`n")[0]}} |
    Format-Table -AutoSize

Write-Host "`n=== SUMMARY ===" -ForegroundColor Green
Write-Host "  Shadows before: $before"
Write-Host "  Shadows after:  $after"
Write-Host "  DFSR: $((Get-Service DFSR).Status)"
