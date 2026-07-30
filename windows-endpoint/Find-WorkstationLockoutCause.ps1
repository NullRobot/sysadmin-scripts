<#
.SYNOPSIS
    Find what on THIS workstation is locking out a user account (stale-credential hunt).
.DESCRIPTION
    Read-only. Run as SYSTEM (Datto RMM / Web Remote) or admin ON the machine that a DC's 4740
    events point at as the lockout source. After a password change, an old credential keeps getting
    retried by something on the box until the account locks - often overnight with nobody logged in.
    This enumerates every usual culprit: logon sessions, stale app/updater processes (QuickBooks,
    Outlook, etc.), scheduled tasks and services running AS the user, persistent mapped drives,
    SYSTEM-context saved credentials (cmdkey), and - if the user is logged in - their per-user
    Credential Manager vault (read via a one-shot task in their interactive session, since the vault
    is per-user and invisible to SYSTEM). Also checks for a VPN client. Changes nothing.
.PARAMETER UserName
    The account being locked out (SamAccountName, no domain).
.PARAMETER AppProcesses
    Process names to treat as stale-credential suspects. Defaults to common offenders.
.NOTES
    The one transient scheduled task only READS the credential list (cmdkey /list never prints secrets).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$UserName,
    [string[]]$AppProcesses = @('QBW32','QBW','QBWebConnector','qbupdate','QBDBMgrN','IntuitUpdateService','OUTLOOK','olk')
)

$ErrorActionPreference = 'Continue'
Write-Output "=== Lockout-source diag for '$UserName' on $env:COMPUTERNAME  $(Get-Date) ==="

Write-Output "`n--- Sessions (quser): is $UserName logged in? ---"
quser 2>&1

Write-Output "`n--- Suspect app/updater processes (session + start time) ---"
Get-Process -Name $AppProcesses -ErrorAction SilentlyContinue |
    Select-Object Name, Id, SessionId, StartTime | Format-Table -AutoSize

Write-Output "`n--- Scheduled tasks running AS $UserName (runs with no interactive login = overnight suspect) ---"
Get-ScheduledTask | Where-Object { $_.Principal.UserId -match $UserName } |
    Select-Object TaskName, TaskPath, State, @{N='User';E={$_.Principal.UserId}}, @{N='LogonType';E={$_.Principal.LogonType}} | Format-Table -AutoSize

Write-Output "`n--- Services running as $UserName ---"
Get-CimInstance Win32_Service | Where-Object { $_.StartName -match $UserName } |
    Select-Object Name, StartName, State, StartMode | Format-Table -AutoSize

Write-Output "`n--- Persistent mapped drives (net use) ---"
cmd /c "net use" 2>&1

Write-Output "`n--- SYSTEM-context saved credentials (cmdkey as SYSTEM) ---"
cmdkey /list 2>&1

Write-Output "`n--- $UserName's Credential Manager (one-shot task in their session, if logged in) ---"
$line = (quser 2>$null) | Where-Object { $_ -match "(?i)\b$([regex]::Escape($UserName))\b" }
if ($line) {
    $helper = 'C:\Windows\Temp\credlist.ps1'
    $out    = 'C:\Windows\Temp\credlist.txt'
    Remove-Item $out -Force -ErrorAction SilentlyContinue
    'cmdkey /list | Out-File -Encoding utf8 C:\Windows\Temp\credlist.txt' | Set-Content $helper -Encoding ASCII
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File $helper"
    $principal = New-ScheduledTaskPrincipal -UserId $UserName -LogonType Interactive
    Register-ScheduledTask -TaskName 'LockoutCredList' -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName 'LockoutCredList'
    Start-Sleep -Seconds 8
    Unregister-ScheduledTask -TaskName 'LockoutCredList' -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $helper -Force -ErrorAction SilentlyContinue
    if (Test-Path $out) { Get-Content $out; Remove-Item $out -Force }
    else { Write-Output "cred task produced no output (session likely disconnected)" }
} else {
    Write-Output "No $UserName session now. If it's still locking out with nobody logged in, the source is a task/service/mapped-drive/machine-cred above."
}

Write-Output "`n--- VPN client present? ---"
Get-Process -Name vpnui, vpnagent, acwebsecagent, csc_ui -ErrorAction SilentlyContinue | Select-Object Name, Id, SessionId | Format-Table -AutoSize
Write-Output "`n=== diag done ==="
