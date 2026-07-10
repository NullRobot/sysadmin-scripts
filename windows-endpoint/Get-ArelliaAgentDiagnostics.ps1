<#
.SYNOPSIS
    Collects and summarizes Arellia (Ivanti Endpoint Manager) agent event log entries
    to help diagnose sync, policy, or certificate/TLS failures.

.DESCRIPTION
    Reads the local 'Arellia' Windows Event Log (read-only), and writes a summary
    report containing:
      - The newest N events (one-line summaries)
      - The newest error/warning/critical events (full message text)
      - Events matching common comms/policy/certificate keywords (cert, TLS/SSL,
        policy, client item registration, handshake, secure channel, etc.), useful
        for tracking down agent-to-server communication failures.

    The script does not modify the event log or any agent configuration. It only
    reads events and writes a plain-text report to the path you specify.

.PARAMETER LogPath
    Path to write the plain-text summary report to. Defaults to a file in the
    current user's temp directory.

.PARAMETER MaxEvents
    Maximum number of most-recent events to pull from the Arellia event log.
    Default is 1200.

.PARAMETER NewestCount
    How many of the newest events to list in the "newest events" section.
    Default is 20.

.PARAMETER ErrorCount
    How many of the newest error/warning/critical events to show in full.
    Default is 15.

.PARAMETER KeywordCount
    How many of the newest keyword-matched (comms/policy/cert) events to show
    in full. Default is 12.

.EXAMPLE
    .\Get-ArelliaAgentDiagnostics.ps1

    Runs with defaults and writes the report to the user's temp folder.

.EXAMPLE
    .\Get-ArelliaAgentDiagnostics.ps1 -LogPath 'C:\Temp\arellia-diag.txt' -MaxEvents 2000

    Pulls up to 2000 events and writes the report to a custom path.

.NOTES
    Requires the 'Arellia' event log source to exist on the machine (installed by
    the Ivanti/Arellia endpoint management agent). Run with sufficient rights to
    read the Windows Event Log (typically local admin or SYSTEM).
#>

[CmdletBinding()]
param(
    [string]$LogPath = (Join-Path $env:TEMP 'arellia-agent-diagnostics.txt'),
    [int]$MaxEvents = 1200,
    [int]$NewestCount = 20,
    [int]$ErrorCount = 15,
    [int]$KeywordCount = 12
)

$ErrorActionPreference = 'SilentlyContinue'

# Start with a clean report file
Remove-Item -LiteralPath $LogPath -Force -EA SilentlyContinue

function Write-Report {
    param([string]$Line)
    $Line = [string]$Line
    Add-Content -LiteralPath $LogPath -Value $Line -EA SilentlyContinue
    $Line
}

$events = Get-WinEvent -LogName 'Arellia' -MaxEvents $MaxEvents -EA SilentlyContinue

Write-Report "===== NEWEST $NewestCount Arellia events ====="
$events | Select-Object -First $NewestCount | ForEach-Object {
    Write-Report ("   {0}  {1,-9} id={2}  {3}" -f $_.TimeCreated, $_.LevelDisplayName, $_.Id, (($_.Message -split "`r?`n")[0]))
}

Write-Report ""
Write-Report "===== ERRORS / WARNINGS (newest $ErrorCount, full text) ====="
$events | Where-Object { $_.LevelDisplayName -match 'Error|Warning|Critical' } | Select-Object -First $ErrorCount | ForEach-Object {
    Write-Report ("   --- {0}  {1}  id={2} ---" -f $_.TimeCreated, $_.LevelDisplayName, $_.Id)
    ($_.Message -split "`r?`n") | Select-Object -First 6 | ForEach-Object { Write-Report ("     " + $_) }
}

Write-Report ""
Write-Report "===== COMMS / POLICY / CERT keyword events (newest $KeywordCount, full text) ====="
$events | Where-Object { $_.Message -match 'certificat|\bssl\b|\btls\b|policy|client item|registr|server|connect|forbidden|unauthor|trust|download|secure channel|handshake' } | Select-Object -First $KeywordCount | ForEach-Object {
    Write-Report ("   --- {0}  {1}  id={2} ---" -f $_.TimeCreated, $_.LevelDisplayName, $_.Id)
    ($_.Message -split "`r?`n") | Select-Object -First 6 | ForEach-Object { Write-Report ("     " + $_) }
}

Write-Report ""
Write-Report ("   newest event time: " + ($events | Select-Object -First 1).TimeCreated)
Write-Report ("   events scanned: " + @($events).Count)
Write-Report "===== DONE ====="
Write-Host "Report written to: $LogPath"
