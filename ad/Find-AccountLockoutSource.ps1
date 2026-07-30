<#
.SYNOPSIS
    Hunts down the source of AD account lockouts by mining the DC Security log.

.DESCRIPTION
    Run directly on a domain controller (ideally the PDC emulator, which records
    every lockout). Pulls the four event types that reveal where bad passwords
    are coming from and cross-references them:
      4776 - NTLM credential validation FAILURES (keyword-filtered at the
             provider level so the query is fast even on a busy DC)
      4771 - Kerberos pre-auth failures (0x18 = bad password)
      4625 - Failed logons (has logon type, workstation, IP, and process)
      4740 - The lockout records themselves (caller computer)
    Ends with a per-user summary of source workstations/IPs ranked by hit count,
    which is usually enough to name the offending device or service outright.
    Optionally exports each event set to CSV. Read-only.

.PARAMETER UserName
    One or more account names to focus on. Default: all users seen in events.

.PARAMETER Hours
    How far back to search. Default 48.

.PARAMETER ExportDir
    If set, writes 4776/4771/4625/4740 CSVs there for offline analysis.

.EXAMPLE
    .\Find-AccountLockoutSource.ps1 -UserName jsmith,svc-backup -Hours 24
#>
[CmdletBinding()]
param(
    [string[]]$UserName,
    [int]$Hours = 48,
    [string]$ExportDir
)

$ErrorActionPreference = 'Continue'
$start = (Get-Date).AddHours(-$Hours)
$AuditFailureKw = 4503599627370496  # 0x10000000000000 - Audit Failure keyword

if ($ExportDir -and -not (Test-Path $ExportDir)) {
    New-Item -Path $ExportDir -ItemType Directory -Force | Out-Null
}

function Get-EvtData {
    param($record, $fieldName)
    $xml = [xml]$record.ToXml()
    ($xml.Event.EventData.Data | Where-Object { $_.Name -eq $fieldName }).'#text'
}

Write-Host "`n=== HOST: $env:COMPUTERNAME  Clock: $(Get-Date)  Window: last $Hours h ===" -ForegroundColor Cyan

# 4776 FAILURES ONLY (keyword filter at provider level = fast)
Write-Host "`n=== 4776 NTLM Credential Validation FAILURES ===" -ForegroundColor Yellow
$ntlm = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4776; StartTime=$start; Keywords=$AuditFailureKw} -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            Time        = $_.TimeCreated
            TargetUser  = Get-EvtData $_ 'TargetUserName'
            Workstation = Get-EvtData $_ 'Workstation'
            Status      = Get-EvtData $_ 'Status'
        }
    }
Write-Host ("Count: {0}" -f (@($ntlm).Count))
$ntlm | Sort-Object Time | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
if ($ExportDir) { $ntlm | Export-Csv (Join-Path $ExportDir '4776_ntlm_failures.csv') -NoTypeInformation }

# 4771 - only failures are logged anyway (0x18 = bad password)
Write-Host "`n=== 4771 Kerberos Pre-Auth FAILURES ===" -ForegroundColor Yellow
$krb = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4771; StartTime=$start} -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            Time          = $_.TimeCreated
            TargetUser    = Get-EvtData $_ 'TargetUserName'
            ClientAddress = Get-EvtData $_ 'IpAddress'
            FailureCode   = Get-EvtData $_ 'Status'
        }
    }
Write-Host ("Count: {0}" -f (@($krb).Count))
$krb | Sort-Object Time | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
if ($ExportDir) { $krb | Export-Csv (Join-Path $ExportDir '4771_kerberos_failures.csv') -NoTypeInformation }

# 4625 - always a failure by definition; carries logon type + process
Write-Host "`n=== 4625 Failed Logons ===" -ForegroundColor Yellow
$fail = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$start} -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            Time        = $_.TimeCreated
            TargetUser  = Get-EvtData $_ 'TargetUserName'
            LogonType   = Get-EvtData $_ 'LogonType'
            Workstation = Get-EvtData $_ 'WorkstationName'
            IpAddress   = Get-EvtData $_ 'IpAddress'
            ProcessName = Get-EvtData $_ 'ProcessName'
            Status      = Get-EvtData $_ 'Status'
            SubStatus   = Get-EvtData $_ 'SubStatus'
        }
    }
Write-Host ("Count: {0}" -f (@($fail).Count))
$fail | Sort-Object Time | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
if ($ExportDir) { $fail | Export-Csv (Join-Path $ExportDir '4625_failed_logons.csv') -NoTypeInformation }

# 4740 lockouts for cross-reference (caller computer)
Write-Host "`n=== 4740 Lockouts ===" -ForegroundColor Yellow
$lock = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740; StartTime=$start} -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            Time           = $_.TimeCreated
            TargetUser     = Get-EvtData $_ 'TargetUserName'
            CallerComputer = Get-EvtData $_ 'TargetDomainName'
        }
    }
Write-Host ("Count: {0}" -f (@($lock).Count))
$lock | Sort-Object Time | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
if ($ExportDir) { $lock | Export-Csv (Join-Path $ExportDir '4740_lockouts.csv') -NoTypeInformation }

# Summary: bad-password sources per user, ranked
Write-Host "`n=== SUMMARY: Sources per user ===" -ForegroundColor Cyan
$combined = @()
if ($ntlm) { $combined += $ntlm | Select-Object @{n='User';e={$_.TargetUser}}, @{n='Source';e={$_.Workstation}}, @{n='Kind';e={'NTLM-4776'}} }
if ($krb)  { $combined += $krb  | Select-Object @{n='User';e={$_.TargetUser}}, @{n='Source';e={$_.ClientAddress}}, @{n='Kind';e={'Kerb-4771'}} }
if ($fail) { $combined += $fail | Select-Object @{n='User';e={$_.TargetUser}}, @{n='Source';e={ if ($_.IpAddress -and $_.IpAddress -ne '-') { $_.IpAddress } else { $_.Workstation } }}, @{n='Kind';e={'Logon-4625'}} }

if ($UserName) {
    $combined = $combined | Where-Object { $UserName -contains $_.User }
}

if (@($combined).Count -eq 0) {
    Write-Host "No matching 4776/4771/4625 events captured." -ForegroundColor Red
} else {
    $combined | Group-Object User | Sort-Object Count -Descending | ForEach-Object {
        Write-Host ""
        Write-Host ("  User: {0}" -f $_.Name) -ForegroundColor Green
        $_.Group | Group-Object Source | Sort-Object Count -Descending | ForEach-Object {
            $src = if ([string]::IsNullOrEmpty($_.Name)) { '(blank)' } else { $_.Name }
            Write-Host ("    {0,-35}  {1,5} hits  ({2})" -f $src, $_.Count, (($_.Group.Kind | Sort-Object -Unique) -join ','))
        }
    }
}

Write-Host "`nDone. Tip: a blank/'-' source usually means a local process on this DC or an ADFS/NPS front end; check services and scheduled tasks next." -ForegroundColor Cyan
