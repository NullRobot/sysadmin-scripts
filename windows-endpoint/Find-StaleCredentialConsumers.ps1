<#
.SYNOPSIS
    Finds everything on a machine that runs under a real user account and could
    be holding a stale (old) password.

.DESCRIPTION
    The classic follow-up to a password change or an account-lockout hunt:
    something on some server keeps replaying the old credential. This script
    inventories the usual suspects on the local machine:
      1. Services whose logon account is a user account (not LocalSystem /
         LocalService / NetworkService / virtual accounts)
      2. Scheduled tasks whose principal is a user account
      3. Scheduled tasks with a frequent repetition interval (minutes-scale),
         regardless of principal - these line up with lockout cadence
      4. Established outbound TCP connections mapped to owning processes
      5. Recent 4624 logons for the target users (logon type, workstation,
         source IP, process)
    Read-only. Run on each machine implicated by Find-AccountLockoutSource
    (or on the DC itself when the lockout source field is blank).

.PARAMETER UserName
    Account names to correlate 4624 logons against. Optional.

.PARAMETER Hours
    Lookback for the 4624 section. Default 2.

.EXAMPLE
    .\Find-StaleCredentialConsumers.ps1 -UserName jsmith -Hours 4
#>
[CmdletBinding()]
param(
    [string[]]$UserName,
    [int]$Hours = 2
)

$ErrorActionPreference = 'Continue'
Write-Host "`n=== HOST: $env:COMPUTERNAME ===" -ForegroundColor Cyan

# Services running as a non-standard user (not LocalSystem/LocalService/NetworkService)
Write-Host "`n=== Services running under user accounts ===" -ForegroundColor Yellow
Get-CimInstance Win32_Service |
    Where-Object { $_.StartName -and $_.StartName -notmatch '^(LocalSystem|NT AUTHORITY\\|NT Service\\|\.?\\NetworkService|\.?\\LocalService|\.?\\LocalSystem|\s*$)$' -and $_.StartName -notmatch '^(LocalSystem|NT AUTHORITY)' } |
    Select-Object Name, StartName, StartMode, State, PathName |
    Format-Table -AutoSize | Out-String -Width 240 | Write-Host

# Scheduled tasks running under user accounts (not SYSTEM/NT AUTHORITY/builtin groups)
Write-Host "`n=== Scheduled tasks running under user accounts ===" -ForegroundColor Yellow
Get-ScheduledTask | ForEach-Object {
    $t = $_
    $principal = $t.Principal.UserId
    if ($principal -and $principal -notmatch '^(SYSTEM|NT AUTHORITY|LOCAL SERVICE|NETWORK SERVICE|Users|Administrators|Authenticated Users|INTERACTIVE|S-1-)') {
        $info = $t | Get-ScheduledTaskInfo
        [PSCustomObject]@{
            Name    = $t.TaskName
            Path    = $t.TaskPath
            RunAs   = $principal
            State   = $t.State
            LastRun = $info.LastRunTime
            NextRun = $info.NextRunTime
            LastRes = '{0:X8}' -f $info.LastTaskResult
        }
    }
} | Format-Table -AutoSize | Out-String -Width 240 | Write-Host

# Tasks with a frequent recurrence (minutes/hourly) regardless of principal
Write-Host "`n=== Scheduled tasks with frequent recurrence (any principal) ===" -ForegroundColor Yellow
Get-ScheduledTask | ForEach-Object {
    $t = $_
    foreach ($tr in $t.Triggers) {
        if ($tr.Repetition -and $tr.Repetition.Interval) {
            $interval = $tr.Repetition.Interval
            if ($interval -match 'PT\d{1,2}M' -or $interval -eq 'PT1H') {
                [PSCustomObject]@{
                    Name     = $t.TaskName
                    Path     = $t.TaskPath
                    RunAs    = $t.Principal.UserId
                    Interval = $interval
                    State    = $t.State
                }
            }
        }
    }
} | Sort-Object Interval, Name | Format-Table -AutoSize | Out-String -Width 240 | Write-Host

# Established connections mapped to processes (what is talking out from here)
Write-Host "`n=== Current network connections (established, with owning process) ===" -ForegroundColor Yellow
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { $_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1' } |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess,
        @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
    Sort-Object Process | Format-Table -AutoSize | Out-String -Width 240 | Write-Host

# Recent 4624 logons for the target users - names the process and source
if ($UserName) {
    Write-Host "`n=== Recent 4624 logons for target users (last $Hours h) ===" -ForegroundColor Yellow
    $since = (Get-Date).AddHours(-$Hours)
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$since} -ErrorAction SilentlyContinue |
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $tu = ($xml.Event.EventData.Data | Where-Object Name -eq 'TargetUserName').'#text'
            if ($UserName -contains $tu) {
                [PSCustomObject]@{
                    Time        = $_.TimeCreated
                    Target      = $tu
                    LogonType   = ($xml.Event.EventData.Data | Where-Object Name -eq 'LogonType').'#text'
                    Workstation = ($xml.Event.EventData.Data | Where-Object Name -eq 'WorkstationName').'#text'
                    IpAddress   = ($xml.Event.EventData.Data | Where-Object Name -eq 'IpAddress').'#text'
                    Process     = ($xml.Event.EventData.Data | Where-Object Name -eq 'ProcessName').'#text'
                    AuthPackage = ($xml.Event.EventData.Data | Where-Object Name -eq 'AuthenticationPackageName').'#text'
                }
            }
        } | Sort-Object Time | Format-Table -AutoSize | Out-String -Width 240 | Write-Host
}

# System context
Write-Host "`n=== System info ===" -ForegroundColor Yellow
$os = Get-CimInstance Win32_OperatingSystem
Write-Host ("OS: {0}  LastBoot: {1}" -f $os.Caption, $os.LastBootUpTime)

Write-Host "`nDone." -ForegroundColor Cyan
