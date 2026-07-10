<#
.SYNOPSIS
    Read-only diagnostic sweep of Windows Event Logs and current network state around a reboot or maintenance window.

.DESCRIPTION
    Pulls Service Control Manager failures, NIC/link/DHCP-related events, RMM agent service
    state and log entries, top Application-log error sources, and boot-completion timestamps
    for a specified time window. Finishes with a snapshot of current NIC and IPv4 state.
    Intended for troubleshooting "something broke after a reboot" scenarios (failed services,
    NIC driver issues after a driver/firmware update, RMM agent not reconnecting, etc.).
    Does not modify any system state.

.PARAMETER StartTime
    Start of the window to inspect (e.g. a few minutes before the reboot began).

.PARAMETER EndTime
    End of the window to inspect.

.PARAMETER RmmAgentNamePattern
    Regex pattern used to match your RMM agent's service DisplayName/Name and
    Application-log ProviderName (e.g. 'Datto|CentraStage|Cag' for Datto RMM, or the
    equivalent identifiers for your RMM platform). Defaults to a Datto RMM pattern; change
    this if you use a different agent.

.EXAMPLE
    .\Get-PostRebootDiagnostics.ps1 -StartTime '2026-07-05 01:55:00' -EndTime '2026-07-05 08:00:00'

    Runs the sweep for the given window using the default (Datto) RMM agent pattern.

.EXAMPLE
    .\Get-PostRebootDiagnostics.ps1 -StartTime (Get-Date).AddHours(-6) -EndTime (Get-Date) -RmmAgentNamePattern 'ScreenConnect|ConnectWise'

    Runs the sweep for the last 6 hours, matching a different RMM agent.

.NOTES
    Read-only. Requires permission to query the System/Application event logs
    (typically local admin, or run under a SYSTEM-context RMM session).
    Run directly on the affected machine, or against a remote machine via
    Invoke-Command / your RMM's remote PowerShell execution.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [datetime]$StartTime,

    [Parameter(Mandatory = $true)]
    [datetime]$EndTime,

    [string]$RmmAgentNamePattern = 'Datto|CentraStage|Cag'
)

$ErrorActionPreference = 'SilentlyContinue'
$s = $StartTime
$e = $EndTime

Write-Output "=== SCM SERVICE FAILURES $($s) - $($e) (7000/7001/7009/7022/7023/7026/7031/7034) ==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$s; EndTime=$e; Id=7000,7001,7009,7022,7023,7026,7031,7034,7043} |
  Sort-Object TimeCreated | Select-Object -First 40 |
  ForEach-Object { "{0}  {1}  {2}" -f $_.TimeCreated, $_.Id, (($_.Message -replace "`r`n",' ')).Substring(0,[math]::Min(150,[int]($_.Message.Length))) }

Write-Output "`n=== NIC / LINK / DHCP EVENTS $($s) - $($e) ==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$s; EndTime=$e} |
  Where-Object { $_.ProviderName -match 'e1i|e1r|e2f|intel|bxnd|bnistr|l2nd|NDIS|Dhcp|Tcpip|netbt|iANSMiniport|Mslbfo' } |
  Sort-Object TimeCreated | Select-Object -First 30 |
  ForEach-Object { "{0}  {1}/{2}  {3}" -f $_.TimeCreated, $_.ProviderName, $_.Id, (($_.Message -replace "`r`n",' ')).Substring(0,[math]::Min(140,[int]($_.Message.Length))) }

Write-Output "`n=== RMM AGENT SERVICES on the box (name, state, start mode) ==="
Get-CimInstance Win32_Service | Where-Object { $_.DisplayName -match $RmmAgentNamePattern -or $_.Name -match $RmmAgentNamePattern } |
  Select-Object Name, DisplayName, State, StartMode | Format-Table -AutoSize | Out-String -Width 200

Write-Output "=== RMM AGENT EVENTS (Application log, matching agent provider) ==="
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$s; EndTime=$e.AddDays(1)} |
  Where-Object { $_.ProviderName -match $RmmAgentNamePattern } |
  Sort-Object TimeCreated | Select-Object -First 25 |
  ForEach-Object { "{0}  {1}/{2}  {3}" -f $_.TimeCreated, $_.ProviderName, $_.Id, (($_.Message -replace "`r`n",' ')).Substring(0,[math]::Min(140,[int]($_.Message.Length))) }

Write-Output "`n=== APPLICATION LOG ERRORS $($s) - $($e) (top sources) ==="
Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$s; EndTime=$e; Level=1,2} |
  Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 10 |
  ForEach-Object { $ev=$_.Group | Sort-Object TimeCreated | Select-Object -First 1; "{0}x  {1}  first={2}  msg={3}" -f $_.Count, $_.Name, $ev.TimeCreated, (($ev.Message -replace "`r`n",' ')).Substring(0,[math]::Min(140,[int]($ev.Message.Length))) }

Write-Output "`n=== WHEN DID THE BOX FINISH BOOTING? (EventLog start 6005/6009/6013 + kernel-boot) ==="
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$s; EndTime=$e; Id=6005,6009,6013,12,13} |
  Sort-Object TimeCreated | Select-Object -First 10 |
  ForEach-Object { "{0}  {1}/{2}  {3}" -f $_.TimeCreated, $_.ProviderName, $_.Id, (($_.Message -replace "`r`n",' ')).Substring(0,[math]::Min(120,[int]($_.Message.Length))) }

Write-Output "`n=== CURRENT NIC / IP STATE (sanity) ==="
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed | Format-Table -AutoSize | Out-String -Width 200
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.*' -and $_.IPAddress -ne '127.0.0.1' } | Select-Object InterfaceAlias, IPAddress, PrefixOrigin | Format-Table -AutoSize | Out-String -Width 200
