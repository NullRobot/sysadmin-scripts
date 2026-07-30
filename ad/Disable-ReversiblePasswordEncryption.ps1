<#
.SYNOPSIS
    Turn OFF reversible (cleartext-recoverable) password encryption domain-wide.
.DESCRIPTION
    Reversible password encryption stores recoverable cleartext copies of passwords - a serious
    finding in any security assessment. The effective setting lives in the domain object's
    pwdProperties bitmask (bit 0x10 = DOMAIN_PASSWORD_STORE_CLEARTEXT), NOT in what a GPO reports.
    This reads the current bitmask, clears only bit 0x10 (leaving complexity and every other bit
    intact), and verifies. Note: it does NOT retroactively delete already-stored recoverable copies;
    those clear per user as each one next changes their password. Reversible encryption is
    occasionally required by legacy CHAP/digest/RADIUS - if anything depends on it, that app's auth
    will fail and you can set the bit back. Run on a DC. Use -WhatIf to preview.
.NOTES
    Requires the ActiveDirectory module and Domain Admin.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param()

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$dom    = Get-ADDomain
$dn     = $dom.DistinguishedName
$before = [int](Get-ADObject -Identity $dn -Properties pwdProperties).pwdProperties
Write-Output ("BEFORE pwdProperties = $before (0x{0:X})" -f $before)
Write-Output ("  cleartext-storage bit (0x10) currently: " + ((($before -band 0x10) -ne 0)))

if (($before -band 0x10) -eq 0) { Write-Output "Already off, nothing to do."; return }

$after = $before -band (-bnot 0x10)
if ($PSCmdlet.ShouldProcess($dn, "Set pwdProperties to $after (clear reversible-encryption bit)")) {
    Set-ADObject -Identity $dn -Replace @{pwdProperties = $after}
    $now = [int](Get-ADObject -Identity $dn -Properties pwdProperties).pwdProperties
    Write-Output ("AFTER  pwdProperties = $now (0x{0:X})" -f $now)
    Write-Output ("  cleartext-storage bit now: " + ((($now -band 0x10) -ne 0)))
    Write-Output ("  complexity still enforced: " + ((($now -band 0x01) -ne 0)))
    if (($now -band 0x10) -eq 0) { Write-Output "`nCONFIRMED: reversible encryption is off." }
    else { Write-Output "`nWARNING: the bit is still set, change did not take." }
}
