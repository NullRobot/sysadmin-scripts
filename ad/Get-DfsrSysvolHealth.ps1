#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only DFSR SYSVOL health check on a DC: replication state, auto-recovery knob,
    SYSVOL/NETLOGON shares, recent DFSR events, and VSS shadow pressure.

.DESCRIPTION
    The classic "GPOs stopped replicating / SYSVOL missing on one DC" triage. Run on
    the suspect DC. Reports:
      - DFSR service state
      - the StopReplicationOnAutoRecovery registry value (unset defaults to 1, meaning
        DFSR PAUSES after a dirty shutdown and waits for a manual
        'wmic /namespace:\\root\microsoftdfs path dfsrVolumeConfig ... ResumeReplication'
        - the single most common cause of a silently stale SYSVOL)
      - per-replicated-folder state (4=Normal, 3=AutoRecovery, 5=InError, 2=InitialSync)
      - whether SYSVOL and NETLOGON are actually shared (absent = DFSR hasn't finished
        initial sync, so the DC is not advertising)
      - the last DFSR events
      - VSS shadow copies/storage on C: (a stuck application-rollback shadow from a
        backup/security agent is a known DFSR-wedge trigger)
      - optional GPO-replication spot check: GPT.INI version of a given GPO GUID on
        this DC's local SYSVOL vs other DCs (mismatch = not replicated)

.PARAMETER GpoGuid
    Optional GPO GUID (with or without braces) for the GPT.INI version comparison.

.PARAMETER CompareDc
    Other DC FQDNs to compare the GPT.INI version against (used with -GpoGuid).

.EXAMPLE
    .\Get-DfsrSysvolHealth.ps1
    .\Get-DfsrSysvolHealth.ps1 -GpoGuid '{11111111-2222-3333-4444-555555555555}' -CompareDc dc1.corp.example.com
#>
[CmdletBinding()]
param(
    [string]$GpoGuid,
    [string[]]$CompareDc
)
$ErrorActionPreference = 'Continue'

"=== HOST: $env:COMPUTERNAME ==="
"--- DFSR service ---"
Get-Service DFSR | Select-Object Name,Status,StartType | Format-Table -Auto | Out-String

"--- StopReplicationOnAutoRecovery reg value (the documented fix knob) ---"
$k='HKLM:\SYSTEM\CurrentControlSet\Services\DFSR\Parameters\Settings'
$v=(Get-ItemProperty -Path $k -Name StopReplicationOnAutoRecovery -ErrorAction SilentlyContinue).StopReplicationOnAutoRecovery
if($null -ne $v){ "  StopReplicationOnAutoRecovery = $v" } else { "  (value NOT set -> defaults to 1 = pause-on-autorecovery)" }

"--- DFSR replicated folder state (4=Normal, 3=AutoRecovery, 5=InError, 2=InitialSync) ---"
try {
  Get-WmiObject -Namespace 'root\microsoftdfs' -Class dfsrreplicatedfolderinfo -ErrorAction Stop |
    Select-Object ReplicationGroupName,ReplicatedFolderName,State | Format-Table -Auto | Out-String
} catch { "  WMI dfsr query failed: $($_.Exception.Message)" }

"--- SYSVOL / NETLOGON shares present? (absent = DFSR not sharing it, DC not advertising) ---"
Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -in 'SYSVOL','NETLOGON' } | Select-Object Name,Path | Format-Table -Auto | Out-String

"--- Recent DFSR events (last 8) ---"
Get-WinEvent -FilterHashtable @{LogName='DFS Replication'} -MaxEvents 8 -ErrorAction SilentlyContinue |
  Select-Object TimeCreated,Id,@{n='Msg';e={$_.Message.Split("`n")[0]}} | Format-Table -Auto | Out-String

"--- VSS shadows on C: (a stuck ApplicationRollback shadow can wedge DFSR) ---"
try { (vssadmin list shadows /for=C: 2>&1) | Select-String 'shadow copy set|creation time|Type:|Provider' } catch { "  vssadmin failed: $($_.Exception.Message)" }

"--- Shadowstorage on C: ---"
try { (vssadmin list shadowstorage /for=C: 2>&1) | Select-String 'Used|Allocated|Maximum' } catch { "  vssadmin shadowstorage failed: $($_.Exception.Message)" }

if ($GpoGuid) {
    $g = '{' + ($GpoGuid.Trim('{}').ToUpper()) + '}'
    $dom = $env:USERDNSDOMAIN
    "--- GPT.INI version comparison for GPO $g (mismatch = not replicated) ---"
    $localIni = "C:\Windows\SYSVOL\sysvol\$dom\Policies\$g\GPT.INI"
    if (-not (Test-Path $localIni)) { $localIni = "C:\Windows\SYSVOL_DFSR\sysvol\$dom\Policies\$g\GPT.INI" }
    if (Test-Path $localIni) { "  $env:COMPUTERNAME (local): " + ((Get-Content $localIni) | Where-Object { $_ -match 'Version' }) }
    else { "  $env:COMPUTERNAME (local): GPT.INI NOT FOUND" }
    foreach ($dc in $CompareDc) {
        $ini = "\\$dc\SYSVOL\$dom\Policies\$g\GPT.INI"
        if (Test-Path $ini) { "  ${dc}: " + ((Get-Content $ini) | Where-Object { $_ -match 'Version' }) }
        else { "  ${dc}: GPT.INI NOT FOUND (or SYSVOL unreachable)" }
    }
}
"=== done ==="
