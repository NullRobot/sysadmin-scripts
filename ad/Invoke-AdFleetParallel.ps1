<#
.SYNOPSIS
    Runs an arbitrary worker scriptblock against every computer in one or more OUs in
    PARALLEL using a runspace pool - sweeps hundreds of machines in minutes from a DC,
    on plain Windows PowerShell 5.1 (no ForEach-Object -Parallel, no PSRemoting fan-out
    dependency in the harness itself).

.DESCRIPTION
    The harness handles everything around the payload:
      1. Builds the target list from AD (-SearchBase OUs, enabled machines only,
         optionally restricted to those active within -ActiveWithinHours)
      2. Extra named machines can be forced in via -IncludeComputer even if outside
         the activity window
      3. Ping precheck per target, then invokes your -Worker scriptblock in a
         runspace pool (default throttle 25)
      4. Progress heartbeat, result collection, per-action summary, CSV export

    The -Worker scriptblock receives two arguments: the computer name and a
    PSCredential. It must RETURN one object (ideally with a PC property and an
    Action/status property for the summary grouping). Example worker that checks
    a registry value over CIM/DCOM:

      $worker = {
          param($name, $cred)
          $out = [pscustomobject]@{ PC = $name; Action = ''; Value = $null }
          try {
              $opt = New-CimSessionOption -Protocol Dcom
              $cs  = New-CimSession -ComputerName $name -Credential $cred -SessionOption $opt -OperationTimeoutSec 12 -ErrorAction Stop
              $os  = Get-CimInstance -CimSession $cs Win32_OperatingSystem
              $out.Value = $os.LastBootUpTime; $out.Action = 'ok'
              Remove-CimSession $cs
          } catch { $out.Action = 'failed' }
          $out
      }

    Run on a DC (or any domain box with RSAT AD) as a domain admin.

.PARAMETER SearchBase
    One or more OU distinguished names to pull computer objects from.

.PARAMETER Worker
    Scriptblock invoked per machine: param($ComputerName, $Credential), returns one object.

.PARAMETER Credential
    Credential passed through to the worker (prompted if omitted).

.PARAMETER ActiveWithinHours
    Only target machines with an AD LastLogonDate within this window. 0 = all enabled. Default 0.

.PARAMETER IncludeComputer
    Extra computer names to force into the target list.

.PARAMETER ThrottleLimit
    Max concurrent runspaces. Default 25.

.PARAMETER CsvPath
    Where to export results. Default C:\Temp\fleet-sweep-<timestamp>.csv.

.EXAMPLE
    .\Invoke-AdFleetParallel.ps1 -SearchBase 'OU=Workstations,DC=corp,DC=example,DC=com' `
        -Worker $worker -ActiveWithinHours 24
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$SearchBase,
    [Parameter(Mandatory)][scriptblock]$Worker,
    [pscredential]$Credential,
    [int]$ActiveWithinHours = 0,
    [string[]]$IncludeComputer,
    [int]$ThrottleLimit = 25,
    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
if (-not $Credential) { $Credential = Get-Credential -Message 'Admin credential for the fleet sweep' }

# --- Build target list ---
Write-Host "===== Building target list ====="
$pcs = @()
foreach ($sb in $SearchBase) {
    if ($ActiveWithinHours -gt 0) {
        $cutoff = (Get-Date).AddHours(-$ActiveWithinHours)
        $pcs += Get-ADComputer -Filter "Enabled -eq 'True'" -SearchBase $sb -Properties LastLogonDate |
            Where-Object { $_.LastLogonDate -gt $cutoff }
    } else {
        $pcs += Get-ADComputer -Filter "Enabled -eq 'True'" -SearchBase $sb
    }
}
foreach ($extra in $IncludeComputer) {
    if ($pcs.Name -notcontains $extra) {
        $c = Get-ADComputer -Filter "Name -eq '$extra'" -ErrorAction SilentlyContinue
        if ($c) { $pcs += $c; Write-Host "  Forced in: $extra" }
    }
}
$pcs = $pcs | Sort-Object Name -Unique
$names = @($pcs.Name)
Write-Host "  Final target count: $($names.Count)"
if ($names.Count -eq 0) { return }

# --- Wrap the user worker with a ping precheck ---
$wrapped = {
    param($name, $cred, $userWorkerText)
    if (-not (Test-Connection -ComputerName $name -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ PC = $name; Action = 'unreachable' }
    }
    $userWorker = [scriptblock]::Create($userWorkerText)
    & $userWorker $name $cred
}

# --- Runspace pool ---
$pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit)
$pool.Open()

Write-Host "===== Running parallel sweep (throttle $ThrottleLimit) ====="
$startTime = Get-Date
$jobs = @()
foreach ($n in $names) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($wrapped)
    [void]$ps.AddArgument($n)
    [void]$ps.AddArgument($Credential)
    [void]$ps.AddArgument($Worker.ToString())
    $jobs += [PSCustomObject]@{ PS = $ps; Handle = $ps.BeginInvoke(); Name = $n }
}
Write-Host "  Submitted $($jobs.Count) jobs"

# --- Wait + collect with progress heartbeat ---
$results = @()
$total = $jobs.Count
$done = 0
$lastProgress = Get-Date
while ($jobs | Where-Object { -not $_.Handle.IsCompleted }) {
    Start-Sleep -Milliseconds 1000
    $newDone = ($jobs | Where-Object { $_.Handle.IsCompleted }).Count
    if ($newDone -gt $done -and ((Get-Date) - $lastProgress).TotalSeconds -ge 15) {
        Write-Host "  Progress: $newDone/$total complete  ($([math]::Round($newDone/$total*100,1))%)"
        $done = $newDone
        $lastProgress = Get-Date
    }
}
foreach ($j in $jobs) {
    try {
        $r = $j.PS.EndInvoke($j.Handle)
        if ($r) { $results += $r }
    } catch {
        Write-Host "  Job EndInvoke failed for $($j.Name): $($_.Exception.Message)"
    } finally {
        $j.PS.Dispose()
    }
}
$pool.Close(); $pool.Dispose()
Write-Host "  Elapsed: $((((Get-Date) - $startTime)).TotalMinutes.ToString('F1')) min"

# --- Summary + export ---
Write-Host "`n===== SUMMARY (by Action) ====="
$results | Group-Object Action | Sort-Object Count -Descending | Format-Table @{n='Action';e={$_.Name}}, Count -AutoSize

if (-not $CsvPath) { $CsvPath = "C:\Temp\fleet-sweep-$((Get-Date).ToString('yyyyMMdd-HHmmss')).csv" }
$csvDir = Split-Path $CsvPath -Parent
if (-not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }
$results | Export-Csv -Path $CsvPath -NoTypeInformation
Write-Host "  Full results saved to: $CsvPath"

$results
