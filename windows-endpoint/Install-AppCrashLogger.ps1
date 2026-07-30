#Requires -Version 5.1
<#
.SYNOPSIS
    Installs an event-triggered forensic crash logger for one process: on every
    Application Error 1000 it records the fault signature plus the loaded-module
    evidence from the matching WER report.

.DESCRIPTION
    For intermittent app crashes you can't sit and watch (user reports "it just
    closes"). Deploy as SYSTEM (RMM). Installs a scheduled task triggered by
    Application-log Event 1000 (survives reboot, needs no logged-on watcher). Each
    firing the worker:

      1. Filters to the target process (skips other apps' crashes).
      2. Appends a durable line to the log: FaultModule, ExceptionCode, Offset,
         ReportId - parsed from the 1000 event's XML.
      3. Locates the matching WER Report.wer (machine ReportArchive/ReportQueue AND
         every user profile's local WER store) and, if a classify regex is supplied,
         records the matching LoadedModule lines. The loaded-module set is the real
         evidence of WHICH driver/DLL family was in the process at crash time (e.g.
         printer-driver UI DLLs for RDP-redirection crashes: PS5UI, ADUIGP,
         PrintConfig, prntvpt, mxdwdrv, vendor UI DLLs).
      4. Tags the entry [MATCH] / [OTHER] so "did the fix hold" is answered by
         counting [MATCH] entries, not raw crash counts (an unrelated crash family
         must not false-fail the fix).

    Idempotent; -Uninstall removes the task and worker (log retained).

.PARAMETER ProcessName
    The crashing executable to watch, e.g. 'mstsc.exe', 'EXCEL.EXE'.

.PARAMETER ClassifyRegex
    Optional regex matched against WER LoadedModule lines; hits mark the crash
    [MATCH] and the matching lines are logged. Example for RDP printer-redirection:
    'spool\\DRIVERS|PS5UI|ADUIGP|PrintConfig|prntvpt|mxdwdrv'

.PARAMETER LogDir
    Where the worker script and crash log live. Default C:\ProgramData\CrashLogger.

.PARAMETER Uninstall
    Remove the task + worker (keeps the log).

.EXAMPLE
    .\Install-AppCrashLogger.ps1 -ProcessName mstsc.exe -ClassifyRegex 'spool\\DRIVERS|PS5UI|PrintConfig'
    .\Install-AppCrashLogger.ps1 -ProcessName mstsc.exe -Uninstall
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ProcessName,
  [string]$ClassifyRegex = '',
  [string]$LogDir = 'C:\ProgramData\CrashLogger',
  [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$procBase   = [IO.Path]::GetFileNameWithoutExtension($ProcessName)
$taskName   = "CrashLogger-$procBase"
$workerPath = Join-Path $LogDir "$procBase-crash-capture.ps1"
$logPath    = Join-Path $LogDir "$procBase-crashlog.txt"

if ($Uninstall) {
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
  Remove-Item $workerPath -Force -ErrorAction SilentlyContinue
  Write-Output "Uninstalled $taskName (log retained at $logPath)"
  return
}

New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

# --- worker: runs once per Application-Error 1000 event ----------------------
# Single-quoted here-string: placeholders swapped in below via .Replace().
$worker = @'
$ErrorActionPreference = "SilentlyContinue"
$log   = "__LOG__"
$stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
$procRx = "__PROCRX__"
$classRx = "__CLASSRX__"

# --- only proceed for a target-process crash in the last 2 minutes -------------
$ev = Get-WinEvent -FilterHashtable @{
        LogName='Application'; ProviderName='Application Error'; Id=1000;
        StartTime=(Get-Date).AddMinutes(-2)
      } -ErrorAction SilentlyContinue |
      Where-Object { $_.Message -match $procRx } |
      Select-Object -First 1
if (-not $ev) { return }

$xml = [xml]$ev.ToXml()
$d   = $xml.Event.EventData.Data
# 1000 order: AppName,AppVer,AppTs,ModName,ModVer,ModTs,ExCode,Offset,Pid,AppStart,AppPath,ModPath,ReportId,...
$faultMod = $d[3]; $exCode = $d[6]; $offset = $d[7]; $reportId = $d[12]

# Find the matching WER report (machine + per-user stores), most recent one.
$werRoots = @(
  "$env:ProgramData\Microsoft\Windows\WER\ReportArchive",
  "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
)
Get-ChildItem -Path 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
  $werRoots += "$($_.FullName)\AppData\Local\Microsoft\Windows\WER\ReportArchive"
  $werRoots += "$($_.FullName)\AppData\Local\Microsoft\Windows\WER\ReportQueue"
}
$wer = Get-ChildItem -Path $werRoots -Recurse -Filter 'Report.wer' -ErrorAction SilentlyContinue |
       Where-Object {
         $_.LastWriteTime -gt (Get-Date).AddMinutes(-10) -and
         ((Get-Content $_.FullName -TotalCount 60 -ErrorAction SilentlyContinue) -join "`n") -match $procRx
       } |
       Sort-Object LastWriteTime -Descending | Select-Object -First 1

$werLines = if ($wer) { Get-Content $wer.FullName -ErrorAction SilentlyContinue } else { @() }

$class = '[OTHER]'
$hitMods = @()
if ($classRx) {
  $hitMods = $werLines | Where-Object { $_ -match 'LoadedModule' -and $_ -match $classRx }
  if ($hitMods -or ($faultMod -match $classRx)) { $class = '[MATCH]  <-- classify-regex hit; the tracked crash family' }
}

Add-Content $log ("==== {0}  crash  {1} ====" -f $stamp, $class)
Add-Content $log ("  FaultModule={0}  Exception={1}  Offset={2}  ReportId={3}" -f $faultMod, $exCode, $offset, $reportId)
if ($wer) {
  Add-Content $log ("  WER={0}" -f $wer.FullName)
  if ($hitMods) {
    Add-Content $log "  -- classify-matching loaded modules at fault --"
    foreach ($pm in $hitMods) { Add-Content $log ("    {0}" -f ($pm -replace '^LoadedModule\[\d+\]=','')) }
  }
} else {
  Add-Content $log "  WER=<no matching Report.wer in window> (Event-1000 line still valid; module proof best-effort)"
}
Add-Content $log ""
'@
$worker = $worker.Replace('__LOG__', $logPath).Replace('__PROCRX__', [regex]::Escape($ProcessName)).Replace('__CLASSRX__', $ClassifyRegex)

Set-Content -Path $workerPath -Value $worker -Encoding UTF8 -Force

# --- event-triggered scheduled task (Application 1000), runs as SYSTEM --------
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
  -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$workerPath`""

$class   = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
$trigger = New-CimInstance -CimClass $class -ClientOnly
$trigger.Enabled      = $true
$trigger.Subscription = @'
<QueryList><Query Id="0" Path="Application"><Select Path="Application">*[System[Provider[@Name='Application Error'] and (EventID=1000)]]</Select></Query></QueryList>
'@

$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
  -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings -Force | Out-Null

Write-Output "Installed $taskName on $env:COMPUTERNAME. Log -> $logPath"
if ($ClassifyRegex) { Write-Output "After a fix, success = ZERO new [MATCH] entries. [OTHER] entries are unrelated crash families." }
Write-Output "Uninstall later with: Install-AppCrashLogger.ps1 -ProcessName $ProcessName -Uninstall"
