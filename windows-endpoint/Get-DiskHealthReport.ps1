<#
.SYNOPSIS
    Read-only Windows disk, storage-reliability (SMART), and boot/shutdown health report.

.DESCRIPTION
    Collects a point-in-time health snapshot for a Windows server or workstation that has had
    an unexpected reboot, hang, or suspected disk failure. Pulls physical disk / volume health,
    SMART predictive-failure status, storage reliability counters (wear, uncorrected read/write
    errors, temperature), disk/NTFS/storage-controller event log entries, unexpected boot and
    shutdown events, and the state of any auto-start services and scheduled tasks matching a
    supplied name pattern (useful for checking whether a specific application's services came
    back up cleanly after a reboot).

    The script is entirely read-only. It makes no configuration changes.

.PARAMETER DaysBack
    How many days of event log history to review. Default 35.

.PARAMETER AppServicePattern
    Regex used to find and report on services/scheduled tasks belonging to a specific
    application you want to check after the reboot (for example, a line-of-business app,
    backup agent, or graphics/imaging suite). Default is a generic placeholder pattern;
    replace it with your own application's service/display names.

.EXAMPLE
    .\Get-DiskHealthReport.ps1
    Runs with defaults (35 days of history, generic app-service pattern).

.EXAMPLE
    .\Get-DiskHealthReport.ps1 -DaysBack 14 -AppServicePattern 'SQL|MSSQL'
    Reviews the last 14 days and reports on SQL Server related services/tasks specifically.

.NOTES
    Run locally as Administrator, or push via your RMM/remote-management tool of choice.
    Requires the Storage module (Get-PhysicalDisk/Get-Disk/Get-Volume, built into modern
    Windows Server and Windows 10/11) and the Get-StorageReliabilityCounter cmdlet, which
    needs the underlying storage driver to expose SMART/reliability data.
#>

param(
    [int]$DaysBack = 35,
    [string]$AppServicePattern = 'YourApp|YourService'
)

$ErrorActionPreference = 'SilentlyContinue'
$since = (Get-Date).AddDays(-$DaysBack)

Write-Output "=== SYSTEM ==="
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
Write-Output ("Host: {0} | Model: {1} {2} | PhysOrVM: {3}" -f $cs.Name, $cs.Manufacturer, $cs.Model, $(if ($cs.Model -match 'Virtual|VMware') {'VM'} else {'Physical'}))
Write-Output ("OS: {0} | LastBoot: {1} | Uptime(h): {2:N1}" -f $os.Caption, $os.LastBootUpTime, ((Get-Date) - $os.LastBootUpTime).TotalHours)

Write-Output "`n=== DISK / VOLUME HEALTH ==="
Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus, OperationalStatus, Size | Format-Table -AutoSize | Out-String -Width 200
Get-Disk | Select-Object Number, FriendlyName, HealthStatus, OperationalStatus, IsBoot, Size | Format-Table -AutoSize | Out-String -Width 200
Get-Volume | Where-Object DriveLetter | Select-Object DriveLetter, FileSystemLabel, HealthStatus, @{n='FreeGB';e={[math]::Round($_.SizeRemaining/1GB,1)}}, @{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}} | Format-Table -AutoSize | Out-String -Width 200

Write-Output "=== SMART / RELIABILITY ==="
Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus | Select-Object InstanceName, PredictFailure | Format-Table -AutoSize | Out-String -Width 200
Get-PhysicalDisk | Get-StorageReliabilityCounter | Select-Object DeviceId, Wear, ReadErrorsUncorrected, WriteErrorsUncorrected, Temperature | Format-Table -AutoSize | Out-String -Width 200

Write-Output "=== STORAGE/DISK EVENTS last $DaysBack days (disk, ntfs, storahci, volmgr, WHEA) ==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since; ProviderName='disk','Ntfs','storahci','volmgr','iaStorA','LSI_SAS','WHEA-Logger','Microsoft-Windows-Ntfs'} |
  Group-Object Id, ProviderName | Sort-Object Count -Descending |
  ForEach-Object { $e = $_.Group[0]; "{0}x  {1} / EventID {2}  last={3}  msg={4}" -f $_.Count, $e.ProviderName, $e.Id, ($_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated, ($e.Message -replace "`r`n",' ' | Out-String).Substring(0,[math]::Min(160,$e.Message.Length)) }

Write-Output "`n=== BOOT / SHUTDOWN EVENTS last $DaysBack days (41, 6008, 1074, 1076) ==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$since; Id=41,6008,1074,1076} |
  Sort-Object TimeCreated -Descending | Select-Object -First 15 |
  ForEach-Object { "{0}  {1}  {2}" -f $_.TimeCreated, $_.Id, (($_.Message -replace "`r`n",' ')).Substring(0,[math]::Min(140,$_.Message.Length)) }

Write-Output "`n=== APPLICATION SERVICES matching pattern '$AppServicePattern' (name, state, start mode, account) ==="
Get-CimInstance Win32_Service | Where-Object { $_.DisplayName -match $AppServicePattern -or $_.Name -match $AppServicePattern } |
  Select-Object Name, DisplayName, State, StartMode, StartName | Format-Table -AutoSize | Out-String -Width 220

Write-Output "=== NON-RUNNING AUTO SERVICES (what didn't come back after boot) ==="
Get-CimInstance Win32_Service | Where-Object { $_.StartMode -like 'Auto*' -and $_.State -ne 'Running' } |
  Select-Object Name, DisplayName, State, StartMode | Format-Table -AutoSize | Out-String -Width 220

Write-Output "=== SCHEDULED TASKS matching pattern '$AppServicePattern' or mentioning reboot/restart ==="
Get-ScheduledTask | Where-Object { $_.TaskName -match $AppServicePattern -or $_.TaskName -match 'reboot|restart' -or $_.TaskPath -match $AppServicePattern } |
  Select-Object TaskPath, TaskName, State | Format-Table -AutoSize | Out-String -Width 220
