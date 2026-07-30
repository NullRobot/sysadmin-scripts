<#
.SYNOPSIS
    Force "must change password at next logon" on a list of accounts, safely.
.DESCRIPTION
    Used after a breach/assessment when a set of accounts must be reset without locking anyone out
    or distributing temp passwords - each user picks their own at next sign-in. For each target it
    skips (with a reason) any account that a forced change would break or that cannot take the flag:
      - disabled accounts (nothing to reset)
      - accounts with an SPN (service dependency; a change breaks the service)
      - CannotChangePassword set
      - PasswordNeverExpires (mutually exclusive with the force-change flag)
    Then re-reads every account it changed to confirm PasswordExpired flipped true. Also prints the
    password policy the users will be setting against. Use -WhatIf to preview.
.PARAMETER Identity
    Accounts (SamAccountNames) to flag.
.NOTES
    Requires the ActiveDirectory module. Notify users first - they will be prompted at next logon.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
param(
    [Parameter(Mandatory)][string[]]$Identity
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$done = @(); $skipped = @()

Write-Output "Target accounts: $($Identity.Count)`n--- APPLYING"
foreach ($n in $Identity) {
    try {
        $u = Get-ADUser $n -Properties Enabled, PasswordNeverExpires, CannotChangePassword, ServicePrincipalName -ErrorAction Stop
        if (-not $u.Enabled)         { $skipped += "$n (disabled)";             Write-Output "  SKIP $n: disabled"; continue }
        if ($u.ServicePrincipalName) { $skipped += "$n (has SPN)";              Write-Output "  SKIP $n: has an SPN, service dependency"; continue }
        if ($u.CannotChangePassword) { $skipped += "$n (cannot change pw)";     Write-Output "  SKIP $n: CannotChangePassword set"; continue }
        if ($u.PasswordNeverExpires) { $skipped += "$n (PasswordNeverExpires)"; Write-Output "  SKIP $n: PasswordNeverExpires blocks a forced change"; continue }
        if ($PSCmdlet.ShouldProcess($n, "Set ChangePasswordAtLogon")) {
            Set-ADUser -Identity $n -ChangePasswordAtLogon $true
            $done += $n; Write-Output "  SET  $n"
        }
    } catch { Write-Output "  ERROR ${n}: $($_.Exception.Message)" }
}

Write-Output "`n--- VERIFY"
$bad = @()
foreach ($n in $done) {
    $v = Get-ADUser $n -Properties PasswordExpired
    if ($v.PasswordExpired) { Write-Output "  OK   $n will be prompted at next logon" }
    else { Write-Output "  FAIL $n flag did not take"; $bad += $n }
}

Write-Output "`n--- SUMMARY"
Write-Output ("  forced change set on : {0}" -f $done.Count)
Write-Output ("  skipped              : {0}" -f $skipped.Count)
$skipped | ForEach-Object { Write-Output "      $_" }
if ($bad.Count) { Write-Output ("  DID NOT TAKE         : {0}" -f ($bad -join ', ')) }

$d = Get-ADDefaultDomainPasswordPolicy
Write-Output "`n--- POLICY THEY WILL BE SETTING AGAINST"
Write-Output ("  MinLength={0} MaxAgeDays={1} History={2} Complexity={3}" -f `
    $d.MinPasswordLength, $d.MaxPasswordAge.Days, $d.PasswordHistoryCount, $d.ComplexityEnabled)
