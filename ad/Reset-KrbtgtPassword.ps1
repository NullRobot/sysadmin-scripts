<#
.SYNOPSIS
    Rotate the krbtgt account password safely, with a max-ticket-age window check.
.DESCRIPTION
    krbtgt rotation is the remediation for a suspected Golden Ticket / AD compromise, and is done
    TWICE with a wait in between. The catch: the second rotation must not happen until longer than
    the domain's max Kerberos ticket lifetime (default 10h) has elapsed since the first, or every
    live ticket issued under the old key is invalidated at once.
    This script:
      -CheckOnly : read-only. Reports krbtgt PasswordLastSet, elapsed time, and whether the wait
                   window has passed (safe to do the next rotation yet).
      (default)  : if the window has passed (or -Force), sets a fresh 64-byte random password, then
                   runs post-rotation health checks (DC services, SYSVOL/NETLOGON shares, and recent
                   Kerberos/Netlogon/KDC/LSA errors) so a problem surfaces immediately.
    The password is never typed by a human - a random value is correct. Run on a DC.
.PARAMETER MaxTicketAgeHours
    The domain's Kerberos MaxTicketAge. Default 10 (Windows default).
.PARAMETER CheckOnly
    Only report the window; make no change.
.PARAMETER Force
    Rotate even if the window has not passed (only for the FIRST rotation, where there is no prior key to protect).
.NOTES
    Requires the ActiveDirectory module and Domain Admin. On a single-DC domain there is no
    inter-DC replication window to wait on between the two rotations, only the ticket-age window.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [int]$MaxTicketAgeHours = 10,
    [switch]$CheckOnly,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$k   = Get-ADUser krbtgt -Properties PasswordLastSet
$gap = (Get-Date) - $k.PasswordLastSet
Write-Output ("krbtgt PasswordLastSet: {0}  ({1}h {2}m ago)" -f $k.PasswordLastSet, [math]::Floor($gap.TotalHours), $gap.Minutes)
$safeAt = $k.PasswordLastSet.AddHours($MaxTicketAgeHours)
Write-Output ("Required wait: {0}h.  Safe to (re)rotate at: {1}" -f $MaxTicketAgeHours, $safeAt)
$windowPassed = $gap.TotalHours -ge $MaxTicketAgeHours
Write-Output ("Window passed: {0}" -f $windowPassed)

if ($CheckOnly) { Write-Output ($(if ($windowPassed) { "VERDICT: SAFE to rotate." } else { "VERDICT: NOT SAFE yet." })); return }

if (-not $windowPassed -and -not $Force) {
    Write-Output "SAFETY STOP: ticket-age window has not passed. Use -Force only for the first rotation. Nothing changed."
    return
}

if ($PSCmdlet.ShouldProcess('krbtgt', "Reset password (rotate)")) {
    $before = $k.PasswordLastSet
    $bytes = New-Object byte[] 64
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $sec = ConvertTo-SecureString ([Convert]::ToBase64String($bytes)) -AsPlainText -Force
    Set-ADAccountPassword -Identity 'krbtgt' -Reset -NewPassword $sec
    Remove-Variable bytes, sec -ErrorAction SilentlyContinue
    $after = (Get-ADUser krbtgt -Properties PasswordLastSet).PasswordLastSet
    Write-Output ("  {0}  ->  {1}" -f $before, $after)
    if ($after -eq $before) { Write-Output "  WARNING: timestamp did not move, rotation may not have taken" }
    else { Write-Output "  rotation complete" }

    Write-Output "`n--- POST-ROTATION HEALTH"
    foreach ($svc in 'Netlogon','NTDS','DNS','KDC','W32Time') {
        try { Write-Output ("  {0} = {1}" -f $svc, (Get-Service -Name $svc -ErrorAction Stop).Status) } catch { Write-Output "  $svc = not found" }
    }
    Get-SmbShare | Where-Object { $_.Name -in 'SYSVOL','NETLOGON' } | ForEach-Object { Write-Output ("  share {0} -> {1}" -f $_.Name, $_.Path) }
    Write-Output "  Recent Kerberos/Netlogon/KDC/LSA errors (last 15 min):"
    try {
        $ev = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddMinutes(-15)} -ErrorAction Stop |
              Where-Object { $_.LevelDisplayName -in 'Error','Critical' -and $_.ProviderName -match 'Kerberos|Netlogon|KDC|LSA' }
        if ($ev) { $ev | Select-Object -First 8 | ForEach-Object { Write-Output ("    {0} | {1} | {2}" -f $_.TimeCreated, $_.ProviderName, ($_.Message -split "`n")[0]) } }
        else { Write-Output "    none" }
    } catch { Write-Output "    none" }
}
