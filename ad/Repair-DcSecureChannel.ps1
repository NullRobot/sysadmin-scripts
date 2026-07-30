#Requires -Version 5.1
<#
.SYNOPSIS
    Repairs a broken machine secure channel ON A DOMAIN CONTROLLER by forcing it to use
    a healthy peer DC's KDC for the machine password reset. No demote needed.

.DESCRIPTION
    A DC with a broken secure channel (e.g. after a snapshot restore / USN rollback /
    replication outage) cannot simply run netdom resetpwd, because it keeps talking to
    its OWN Kerberos KDC and the reset silently fails or does not stick. The correct
    sequence, run ON the broken DC:

      1. Stop the local KDC service (set to Manual) so this DC is FORCED to use the
         healthy peer DC's KDC.
      2. Purge cached Kerberos tickets (SYSTEM LUID 0x3e7 and the current session).
      3. netdom resetpwd against the healthy DC with a domain admin credential.
      4. Restart the KDC (back to Automatic).
      5. If resetpwd reported success: reboot this DC to finalize, then verify
         replication (repadmin /replsummary). If it failed: do NOT reboot; reassess.

    Credential: NEVER on the command line/script body. Set env vars before running:
      ADMIN_USER  domain admin (DOMAIN\user)      ADMIN_PW  its password

.PARAMETER HealthyDc
    FQDN of the known-good DC to reset the machine password against.

.PARAMETER ExpectedComputerName
    Safety guard: the script aborts unless it is running on this computer.

.EXAMPLE
    $env:ADMIN_USER='CORP\admin'; $env:ADMIN_PW='...'
    .\Repair-DcSecureChannel.ps1 -HealthyDc dc1.corp.example.com -ExpectedComputerName DC2
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$HealthyDc,
    [Parameter(Mandatory)][string]$ExpectedComputerName
)
$ErrorActionPreference = 'Continue'

if ($env:COMPUTERNAME -ne $ExpectedComputerName) { Write-Host "WRONG BOX ($env:COMPUTERNAME, expected $ExpectedComputerName) - aborting." -ForegroundColor Red; return }
if (-not $env:ADMIN_USER -or -not $env:ADMIN_PW) { Write-Host 'FATAL: set ADMIN_USER and ADMIN_PW environment variables (domain admin credential).' -ForegroundColor Red; return }

Write-Host "== stop local KDC so this DC must use $HealthyDc's KDC (the step usually missed) =="
Set-Service kdc -StartupType Manual
Stop-Service kdc -Force -ErrorAction SilentlyContinue
Start-Sleep 2
Write-Host ("  kdc now: " + (Get-Service kdc).Status)

Write-Host "== purge cached tickets (system + this session) =="
klist -li 0x3e7 purge | Out-Null
klist purge | Out-Null

Write-Host "== reset this DC's machine password against $HealthyDc =="
$out = & "$env:windir\System32\netdom.exe" resetpwd /server:$HealthyDc /userd:$env:ADMIN_USER /passwordd:$env:ADMIN_PW 2>&1
$out | ForEach-Object { Write-Host "   $_" }
$ok = ($out -join ' ') -match 'completed successfully'

Write-Host "== restart KDC (back to Automatic) =="
Set-Service kdc -StartupType Automatic
Start-Service kdc -ErrorAction SilentlyContinue
Start-Sleep 2
Write-Host ("  kdc now: " + (Get-Service kdc).Status)

if ($ok) { Write-Host "RESETPWD_OK -> reboot this DC next to finalize, then verify replication (repadmin /replsummary)." -ForegroundColor Green }
else     { Write-Host "RESETPWD_STILL_FAILED -> do not reboot; reassess (is $HealthyDc reachable on 88/389/445?)." -ForegroundColor Red }
