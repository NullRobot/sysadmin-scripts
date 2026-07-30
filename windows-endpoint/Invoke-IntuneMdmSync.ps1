<#
.SYNOPSIS
    Forces an immediate Intune/MDM policy sync on a Windows device, from
    SYSTEM context (RMM-friendly), and reports the last successful sync time.

.DESCRIPTION
    "Wait up to 8 hours for the next check-in" is not an answer mid-ticket.
    This script:
      1. Finds the MDM enrollment (ProviderID "MS DM Server") under
         HKLM\SOFTWARE\Microsoft\Enrollments and starts every scheduled task
         in the matching \Microsoft\Windows\EnterpriseMgmt\<enrollmentID>\
         folder - the same mechanism the "Sync" button in Settings uses
      2. Falls back to DeviceEnroller.exe /c /AutoEnrollMDMUsingAADDeviceCredential
         if no enrollment is found (also repairs a missing enrollment)
      3. Restarts the Intune Management Extension service so Win32 apps and
         PowerShell scripts re-evaluate quickly too
      4. Prints the LastSuccessfulSync timestamp for verification
    Run as SYSTEM. Policy typically applies within a few minutes after.

.EXAMPLE
    .\Invoke-IntuneMdmSync.ps1
#>
[CmdletBinding()]
param()

# Method 1: Trigger MDM sync via the enrollment's scheduled tasks
$enrollmentPath = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments" -ErrorAction SilentlyContinue |
    Where-Object { $_.GetValue("ProviderID") -eq "MS DM Server" }

if ($enrollmentPath) {
    $enrollmentID = $enrollmentPath.PSChildName
    $taskPath = "\Microsoft\Windows\EnterpriseMgmt\$enrollmentID\"

    Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "Starting task: $($_.TaskName)"
        Start-ScheduledTask -TaskPath $taskPath -TaskName $_.TaskName -ErrorAction SilentlyContinue
    }
    Write-Host "MDM sync tasks triggered via enrollment ID: $enrollmentID"
} else {
    Write-Host "No MDM enrollment found, trying DeviceEnroller directly..."
    Start-Process "C:\Windows\System32\DeviceEnroller.exe" -ArgumentList "/c /AutoEnrollMDMUsingAADDeviceCredential" -Wait
}

# Method 2: Restart Intune Management Extension to pick up changes faster
if (Get-Service -Name IntuneManagementExtension -ErrorAction SilentlyContinue) {
    Restart-Service -Name IntuneManagementExtension -Force
    Write-Host "Intune Management Extension restarted"
}

# Verify: check last sync time
$lastSync = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Enrollments\*\DMClient\MS DM Server" -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty LastSuccessfulSync -ErrorAction SilentlyContinue
Write-Host "Last successful sync: $lastSync"

Write-Host "`nDone. Policy should apply within a few minutes. The user can watch status at"
Write-Host "Settings > Accounts > Access work or school > (connection) > Info."
