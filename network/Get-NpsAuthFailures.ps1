#Requires -Version 5.1
<#
.SYNOPSIS
    On an NPS/RADIUS server, identifies the DEVICE behind a user's failing WiFi/VPN
    authentications: MAC (Calling-Station), AP/NAS (Called-Station), reason codes.

.DESCRIPTION
    The classic "user keeps locking out and we can't find the device" ending: it is a
    phone or laptop with a stale WiFi password hammering the NPS. Run this ON the NPS
    server the auths hit (check both if there is a farm). Read-only. Pulls:

      1. Security-log NPS denial events (6273 = denied, 6274 = discarded) for the user,
         showing timestamp, device MAC (Calling Station), AP/NAS (Called Station),
         RADIUS client friendly name and reason - then distinct MAC and AP counts, which
         usually names the offending device outright (look the MAC up in the wireless
         controller / DHCP leases).
      2. 4625 failed logons for the user on this box (the MSCHAP path lands here too).
      3. The most recent IAS/NPS request log files and the user's last lines in them
         (covers the case where Security-log auditing for NPS is off).

.PARAMETER UserName
    Account name to hunt (matched as a substring of the event message).

.PARAMETER Days
    Lookback window in days. Default 3.

.EXAMPLE
    .\Get-NpsAuthFailures.ps1 -UserName jsmith -Days 2
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$UserName,
    [int]$Days = 3
)
$ErrorActionPreference = 'Continue'
$since = (Get-Date).AddDays(-$Days)
"Host: $env:COMPUTERNAME   Now: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')   Window: last $Days day(s)"

"`n=== [1] NPS denials (6273/6274) for $UserName ==="
try {
  $ev = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=6273,6274; StartTime=$since} -ErrorAction Stop |
        Where-Object { $_.Message -match [regex]::Escape($UserName) }
  if (-not $ev) { "  none in Security log" }
  else {
    "  COUNT: $($ev.Count)"
    $ev | Sort-Object TimeCreated | Select-Object -Last 15 | ForEach-Object {
      $m=$_.Message
      [PSCustomObject]@{
        Time = $_.TimeCreated
        MAC  = ([regex]::Match($m,'Calling Station Identifier:\s*(.+)')).Groups[1].Value.Trim()
        AP   = ([regex]::Match($m,'Called Station Identifier:\s*(.+)')).Groups[1].Value.Trim()
        Client = ([regex]::Match($m,'Client Friendly Name:\s*(.+)')).Groups[1].Value.Trim()
        Reason = ([regex]::Match($m,'Reason(?: Code)?:\s*(.+)')).Groups[1].Value.Trim()
      }
    } | Format-Table -AutoSize | Out-String
    "  --- distinct device MAC (Calling-Station) - this is the device to find ---"
    $ev | ForEach-Object { ([regex]::Match($_.Message,'Calling Station Identifier:\s*(.+)')).Groups[1].Value.Trim() } |
      Where-Object {$_} | Group-Object | Sort-Object Count -Descending | Select-Object Count,Name | Format-Table -AutoSize | Out-String
    "  --- distinct AP/NAS (Called-Station) ---"
    $ev | ForEach-Object { ([regex]::Match($_.Message,'Called Station Identifier:\s*(.+)')).Groups[1].Value.Trim() } |
      Where-Object {$_} | Group-Object | Sort-Object Count -Descending | Select-Object Count,Name | Format-Table -AutoSize | Out-String
  }
} catch { if ($_.Exception.Message -match 'No events were found'){'  none in Security log'} else {"  6273 err: $($_.Exception.Message)"} }

"`n=== [2] 4625 failed logons for $UserName on this box (MSCHAP/IAS path) ==="
try {
  $e = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$since} -ErrorAction Stop |
       Where-Object { $_.Properties[5].Value -eq $UserName }
  if (-not $e) { "  none" }
  else {
    "  COUNT: $($e.Count)"
    $e | Sort-Object TimeCreated | Select-Object -Last 12 TimeCreated,
      @{n='LogonProc';e={$_.Properties[11].Value}}, @{n='AuthPkg';e={$_.Properties[12].Value}},
      @{n='Wksta';e={$_.Properties[13].Value}}, @{n='IP';e={$_.Properties[19].Value}} | Format-Table -AutoSize | Out-String
  }
} catch { if ($_.Exception.Message -match 'No events were found'){'  none'} else {"  4625 err: $($_.Exception.Message)"} }

"`n=== [3] IAS/NPS request log files (most recent) ==="
$logdir='C:\Windows\System32\LogFiles'
if (Test-Path $logdir) {
  Get-ChildItem $logdir -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending |
    Select-Object -First 6 Name,Length,LastWriteTime | Format-Table -AutoSize | Out-String
  $latest = Get-ChildItem $logdir -Filter 'IN*.log' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($latest) {
    "  --- last $UserName lines in $($latest.Name) ---"
    Select-String -Path $latest.FullName -Pattern ([regex]::Escape($UserName)) -ErrorAction SilentlyContinue |
      Select-Object -Last 6 | ForEach-Object { $_.Line.Substring(0,[Math]::Min(220,$_.Line.Length)) }
  }
} else { "  no $logdir" }
