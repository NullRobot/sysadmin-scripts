<#
.SYNOPSIS
    Trace account-lockout activity for a single user on a domain controller.
.DESCRIPTION
    Read-only. Run on a DC (the PDC emulator sees every lockout). Reports the account's
    current state (LockedOut, badPwdCount, LastBadPasswordAttempt), then pulls the
    Security-log evidence that explains WHERE the bad passwords are coming from:
      4740 - account lockout, with the source computer that triggered it
      4776 - NTLM auth results (error 0xC000006A = bad password), with source workstation
      4771 - Kerberos pre-auth failures
    This is the first thing to run when a user "keeps getting locked out" - it points at
    the machine/service spraying a stale credential so you can go clean it up there.
.PARAMETER SamAccountName
    The account to trace (e.g. 'jsmith').
.PARAMETER Hours
    How far back to search the Security log. Default 24.
.NOTES
    Requires the ActiveDirectory module and rights to read the Security log on the DC.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SamAccountName,
    [int]$Hours = 24
)

$ErrorActionPreference = 'Continue'
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
$start = (Get-Date).AddHours(-$Hours)

Write-Output "=== Account state: $SamAccountName ==="
try {
    Get-ADUser -Identity $SamAccountName -Properties LockedOut, badPwdCount, LastBadPasswordAttempt, lockoutTime, PasswordLastSet, LastLogonDate -ErrorAction Stop |
        Select-Object SamAccountName, Enabled, LockedOut, badPwdCount, LastBadPasswordAttempt, PasswordLastSet, LastLogonDate | Format-List
} catch { Write-Output "Get-ADUser failed: $($_.Exception.Message)" }

Write-Output "`n=== 4740 lockouts (last ${Hours}h) - source computer that locked the account ==="
try {
    $ev = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4740; StartTime=$start} -ErrorAction Stop |
          Where-Object { $_.Properties[0].Value -eq $SamAccountName }
    if ($ev) { $ev | Select-Object TimeCreated, @{N='Account';E={$_.Properties[0].Value}}, @{N='From';E={$_.Properties[1].Value}} | Format-Table -AutoSize }
    else { Write-Output "  NONE" }
} catch { Write-Output "  NONE" }

Write-Output "`n=== 4776 NTLM auth (last ${Hours}h)  0x0=success 0xC000006A=bad password ==="
try {
    $n = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4776; StartTime=$start} -MaxEvents 500 -ErrorAction Stop |
        Where-Object { $_.Message -match [regex]::Escape($SamAccountName) } |
        ForEach-Object {
            $ec = if ($_.Message -match 'Error Code:\s*(\S+)') { $Matches[1] } else { '?' }
            $ws = if ($_.Message -match 'Source Workstation:\s*(\S+)') { $Matches[1] } else { '?' }
            "$($_.TimeCreated)  err $ec  from $ws"
        }
    if ($n) { $n | Select-Object -First 40 } else { Write-Output "  NONE" }
} catch { Write-Output "  NONE" }

Write-Output "`n=== 4771 Kerberos pre-auth failures (last ${Hours}h) ==="
try {
    $k = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4771; StartTime=$start} -MaxEvents 500 -ErrorAction Stop |
        Where-Object { $_.Message -match [regex]::Escape($SamAccountName) } | ForEach-Object { "$($_.TimeCreated)" }
    if ($k) { $k | Select-Object -First 40 } else { Write-Output "  NONE" }
} catch { Write-Output "  NONE" }
Write-Output "`n=== done ==="
