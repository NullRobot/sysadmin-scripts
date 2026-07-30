<#
.SYNOPSIS
    Read-only performance snapshot of a Windows server: memory pressure, top processes, agents.
.DESCRIPTION
    The go-to "why is this server slow" first pass. Reports RAM total/free/used% and commit charge,
    the top processes by working set and by CPU time, logged-on sessions (a lingering admin RDP
    session is a classic memory hog), any heavy Java/agent stacks, and the state of common monitoring
    /security agents (LogicMonitor, SentinelOne, Defender, MDI, etc.) plus uptime. Run as SYSTEM
    (Datto RMM) or admin. Changes nothing.
.NOTES
    Especially useful on undersized DCs/app servers where a monitoring collector or EDR agent is
    quietly eating the box.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'SilentlyContinue'
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem

Write-Output "===== $($cs.Name) | $($os.Caption) ====="
[pscustomobject]@{
    LogicalProcs   = $cs.NumberOfLogicalProcessors
    TotalRAM_GB    = [math]::Round($cs.TotalPhysicalMemory/1GB,1)
    FreeRAM_GB     = [math]::Round($os.FreePhysicalMemory/1MB,1)
    UsedRAM_pct    = [math]::Round((1-($os.FreePhysicalMemory*1KB)/($cs.TotalPhysicalMemory))*100,1)
    CommitUsed_GB  = [math]::Round(($os.TotalVirtualMemorySize-$os.FreeVirtualMemory)/1MB,1)
    CommitLimit_GB = [math]::Round($os.TotalVirtualMemorySize/1MB,1)
} | Format-List

Write-Output "===== TOP 12 BY MEMORY (working set) ====="
Get-Process | Sort-Object WS -Descending | Select-Object -First 12 `
    Name, Id, @{n='WS_MB';e={[math]::Round($_.WS/1MB)}}, @{n='CPU_s';e={[math]::Round($_.CPU)}} | Format-Table -Auto

Write-Output "===== TOP 12 BY CPU TIME ====="
Get-Process | Sort-Object CPU -Descending | Select-Object -First 12 `
    Name, Id, @{n='CPU_s';e={[math]::Round($_.CPU)}}, @{n='WS_MB';e={[math]::Round($_.WS/1MB)}} | Format-Table -Auto

Write-Output "===== LOGGED-ON SESSIONS (quser) ====="
quser 2>&1

Write-Output "===== JAVA PROCESSES (agents/collectors often run on Java) ====="
Get-CimInstance Win32_Process -Filter "Name='java.exe'" |
    Select-Object ProcessId, @{n='WS_MB';e={[math]::Round($_.WorkingSetSize/1MB)}}, CommandLine | Format-List

Write-Output "===== MONITORING / SECURITY AGENT SERVICES ====="
Get-Service | Where-Object { $_.DisplayName -match 'LogicMonitor|Sentinel|Defender|Identity|MDI|Datadog|Nagios|Zabbix|Azure Recovery|Tanium' } |
    Select-Object Status, Name, DisplayName | Format-Table -Auto

Write-Output "===== UPTIME ====="
"Last boot: $($os.LastBootUpTime)  (uptime $([math]::Round(((Get-Date)-$os.LastBootUpTime).TotalDays,1)) days)"
