<#
.SYNOPSIS
    Point the PDC emulator at an external NTP peer list and verify it synced.
.DESCRIPTION
    A domain's authoritative time comes from the PDC emulator. If it drifts (common
    when a DC runs as a VM and falls back to the host/CMOS clock), Kerberos auth
    starts failing across the domain. This configures the PDC to sync from a set of
    external NTP servers, restarts the time service, forces a resync, and prints the
    before/after source so you can confirm it took. Run this ON the PDC emulator.
    Read Get-DomainTimeSource state first with 'w32tm /query /source'.
.PARAMETER NtpPeers
    Space-separated NTP peer list in w32tm format. Default is a solid public set.
.NOTES
    Requires local admin on the PDC. Idempotent; safe to re-run.
#>
[CmdletBinding()]
param(
    [string]$NtpPeers = 'time.windows.com,0x9 time.nist.gov,0x9 pool.ntp.org,0x9'
)

$ErrorActionPreference = 'Continue'

"Before source : $(w32tm /query /source 2>&1)"
"--- applying external NTP peer list ---"
(w32tm /config /manualpeerlist:"$NtpPeers" /syncfromflags:manual /reliable:yes /update 2>&1) | Out-String

Restart-Service w32time -ErrorAction SilentlyContinue
Start-Sleep -Seconds 6
(w32tm /resync /rediscover 2>&1) | Out-String
Start-Sleep -Seconds 6

"After source  : $(w32tm /query /source 2>&1)"
(w32tm /query /status 2>&1 | Select-String 'Source|Stratum|Last Successful|Leap') | Out-String
"--- configured peers ---"
(w32tm /query /peers 2>&1) | Out-String
