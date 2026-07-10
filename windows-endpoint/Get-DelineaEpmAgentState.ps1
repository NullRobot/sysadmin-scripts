<#
.SYNOPSIS
    Read-only diagnostic dump of Delinea/Thycotic EPM (Privilege Manager) agent state.

.DESCRIPTION
    Collects service status, installed-program registry entries, install directories,
    agent configuration registry values (including any configured management URLs),
    Zscaler service presence, recent agent log tail/error lines, and right-click
    context-menu elevation handlers. Everything is written to a single output file
    so a partial run still leaves useful data behind. Nothing is modified on the
    system; all actions are read-only queries against services, the registry, and
    log files.

    Useful when troubleshooting why an endpoint isn't showing up in the EPM console,
    why elevation requests aren't working, or why the agent can't reach its
    management server (e.g. behind a proxy/SSL-inspection product like Zscaler).

.PARAMETER LogPath
    Path to write the diagnostic output to. Defaults to a file in the current user's
    temp directory.

.EXAMPLE
    .\Get-DelineaEpmAgentState.ps1
    Runs the check and writes output to $env:TEMP\epm-check-out.txt

.EXAMPLE
    .\Get-DelineaEpmAgentState.ps1 -LogPath 'C:\Temp\epm-out.txt'
    Runs the check and writes output to a specific path.

.NOTES
    Run elevated (or as SYSTEM via your RMM tool of choice) for full registry/log
    access, since some Delinea/Arellia keys and ProgramData log folders are not
    readable by a standard user.
    Matches on both legacy (Arellia/Thycotic) and current (Delinea) naming since
    the product has been rebranded twice.
#>

param(
    [string]$LogPath = (Join-Path $env:TEMP 'epm-check-out.txt')
)

$ErrorActionPreference = 'SilentlyContinue'
$LOG = $LogPath
Remove-Item -LiteralPath $LOG -Force -EA SilentlyContinue
function W($s){ $s = [string]$s; Add-Content -LiteralPath $LOG -Value $s -EA SilentlyContinue; $s }

W "===== HOST ====="
W ("{0}  user={1}  {2}" -f $env:COMPUTERNAME, $env:USERNAME, (Get-Date))

W ""
W "===== SERVICES ====="
$svc = Get-Service | Where-Object { $_.Name -match 'Thycotic|Delinea|Arellia|ApplicationControl|ACS' -or $_.DisplayName -match 'Thycotic|Delinea|Arellia|Application Control|Privilege Manager' }
if($svc){ foreach($s in $svc){ W ("   {0,-9} {1,-12} {2}  ({3})" -f $s.Status, $s.StartType, $s.Name, $s.DisplayName) } } else { W "   NONE" }

W ""
W "===== INSTALLED (uninstall reg) ====="
$u = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Thycotic|Delinea|Arellia|Privilege|Application Control|EPM' }
if($u){ foreach($p in $u){ W ("   {0}  v{1}  [{2}]  {3}" -f $p.DisplayName, $p.DisplayVersion, $p.Publisher, $p.InstallDate) } } else { W "   NONE" }

W ""
W "===== INSTALL DIRS ====="
foreach($d in 'C:\Program Files\Thycotic','C:\Program Files\Delinea','C:\Program Files (x86)\Thycotic','C:\Program Files (x86)\Delinea'){
  if(Test-Path -LiteralPath $d){ W "   FOUND $d"; (Get-ChildItem -LiteralPath $d -Directory -EA SilentlyContinue).Name | ForEach-Object { W "      sub: $_" } } else { W "   absent $d" }
}

W ""
W "===== AGENT CONFIG (reg values) ====="
foreach($k in 'HKLM:\SOFTWARE\Arellia\Agent','HKLM:\SOFTWARE\Policies\Arellia\AMS','HKLM:\SOFTWARE\Thycotic\Agent','HKLM:\SOFTWARE\Delinea\Agent','HKLM:\SOFTWARE\WOW6432Node\Arellia\Agent','HKLM:\SOFTWARE\Policies\Arellia\Agent'){
  if(Test-Path -LiteralPath $k){ W "   KEY $k"; (Get-ItemProperty -LiteralPath $k -EA SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { W ("      {0} = {1}" -f $_.Name, ($_.Value -join ',')) } }
}
W "   -- URL sweep (depth 2) --"
$seen = @{}
Get-ChildItem -Recurse -Depth 2 -LiteralPath 'HKLM:\SOFTWARE\Arellia','HKLM:\SOFTWARE\Policies\Arellia' -EA SilentlyContinue | ForEach-Object {
  (Get-ItemProperty -LiteralPath $_.PSPath -EA SilentlyContinue).PSObject.Properties | Where-Object { $_.Value -match 'https?://' } | ForEach-Object {
    $line = "{0} = {1}" -f $_.Name, $_.Value
    if(-not $seen.ContainsKey($line)){ $seen[$line]=1; W ("      " + $line) }
  }
}

W ""
W "===== ZSCALER ====="
$z = Get-Service | Where-Object { $_.Name -match 'Zscaler|ZSA' -or $_.DisplayName -match 'Zscaler' }
if($z){ foreach($s in $z){ W ("   {0,-9} {1}  ({2})" -f $s.Status, $s.Name, $s.DisplayName) } } else { W "   no zscaler svc" }

W ""
W "===== AGENT LOGS ====="
foreach($ld in 'C:\ProgramData\Arellia','C:\ProgramData\Thycotic','C:\ProgramData\Delinea'){
  if(Test-Path -LiteralPath $ld){
    W "   LOGDIR $ld"
    $logs = Get-ChildItem -LiteralPath $ld -Recurse -Include *.log -EA SilentlyContinue | Sort-Object LastWriteTime -Desc | Select-Object -First 6
    $logs | ForEach-Object { W ("      {0}  {1}  {2}KB" -f $_.LastWriteTime, $_.FullName, [int]($_.Length/1KB)) }
    $nw = $logs | Select-Object -First 1
    if($nw){
      W ("   --- last 30 lines: " + $nw.Name + " ---")
      Get-Content -LiteralPath $nw.FullName -Tail 30 -EA SilentlyContinue | ForEach-Object { W ("   | " + $_) }
      W "   --- error/conn/policy lines (last 1500) ---"
      Get-Content -LiteralPath $nw.FullName -Tail 1500 -EA SilentlyContinue | Select-String -Pattern 'error|fail|exception|certificat|\bssl\b|\btls\b|registr|policy|denied|unable|connect|forbidden|timeout|unauthor' | Select-Object -Last 25 | ForEach-Object { W ("   > " + $_.Line) }
    }
  } else { W "   absent $ld" }
}

W ""
W "===== CONTEXT MENU HANDLERS (right-click) ====="
foreach($c in 'HKLM:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers','HKLM:\SOFTWARE\Classes\exefile\shellex\ContextMenuHandlers','HKLM:\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers','HKLM:\SOFTWARE\Classes\Msi.Package\shellex\ContextMenuHandlers'){
  if(Test-Path -LiteralPath $c){ W ("   " + $c); (Get-ChildItem -LiteralPath $c -EA SilentlyContinue).PSChildName | ForEach-Object { $m = if($_ -match 'Arellia|Thycotic|Delinea|Privilege|Elevat|RunAs'){' <== ELEVATION HANDLER'}else{''}; W ("      " + $_ + $m) } }
}

W ""
W "===== DONE ====="
