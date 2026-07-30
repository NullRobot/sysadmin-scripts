<#
.SYNOPSIS
    Read-only audit of privileged accounts, password policy, and krbtgt on a domain.
.DESCRIPTION
    The core "how bad is this AD" security snapshot to run before any hardening. Read-only.
    Reports:
      - Membership of every default privileged group (Domain/Enterprise/Schema Admins, built-in
        Administrators, DnsAdmins, Account/Backup/Server/Print Operators, GPO Creator Owners),
        with each member's Enabled state, last logon, and password age so stale and disabled
        admins jump out.
      - All adminCount=1 users (currently or formerly privileged / AdminSDHolder-protected).
      - The default domain password policy, any fine-grained policies (PSOs), and the raw
        pwdProperties bitmask (so you can see reversible-encryption / complexity directly).
      - krbtgt password age (drives whether a rotation is overdue).
      - Domain accounts used to run services/scheduled tasks on THIS DC (don't rotate blind).
    Run on a DC. Nothing is changed.
.NOTES
    Requires the ActiveDirectory module.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
Import-Module ActiveDirectory -ErrorAction Stop

$d = Get-ADDomain
Write-Output "=== DOMAIN $($d.DNSRoot)  PDC $($d.PDCEmulator) ==="

Write-Output "`n=== DEFAULT DOMAIN PASSWORD POLICY ==="
$p = Get-ADDefaultDomainPasswordPolicy
Write-Output ("MinLength={0} History={1} MaxAgeDays={2} Complexity={3} Reversible={4} LockoutThreshold={5}" -f `
    $p.MinPasswordLength, $p.PasswordHistoryCount, $p.MaxPasswordAge.Days, $p.ComplexityEnabled, $p.ReversiblePasswordEncryptionEnabled, $p.LockoutThreshold)
$pp = [int](Get-ADObject $d.DistinguishedName -Properties pwdProperties).pwdProperties
Write-Output ("pwdProperties(raw)={0} (0x{1:X})  bit0x01=complexity bit0x10=store-reversible" -f $pp, $pp)

Write-Output "`n=== FINE-GRAINED PASSWORD POLICIES (PSOs) ==="
$fg = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
if (-not $fg) { Write-Output "NONE - privileged accounts inherit the default policy above." }
else { $fg | ForEach-Object { Write-Output ("{0}: MinLen={1} MaxAgeDays={2} Precedence={3}" -f $_.Name, $_.MinPasswordLength, $_.MaxPasswordAge.Days, $_.Precedence) } }

$k = Get-ADUser krbtgt -Properties PasswordLastSet, 'msDS-KeyVersionNumber'
Write-Output ("`n=== krbtgt  PasswordLastSet={0}  KVNO={1}  ({2} days old) ===" -f `
    $k.PasswordLastSet, $k.'msDS-KeyVersionNumber', [math]::Round(((Get-Date) - $k.PasswordLastSet).TotalDays,1))

$groups = 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators',
          'Backup Operators','Server Operators','Print Operators','Group Policy Creator Owners','DnsAdmins'
foreach ($g in $groups) {
    try {
        $m = @(Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop)
        Write-Output "`n=== $g  (members: $($m.Count)) ==="
        foreach ($u in $m) {
            if ($u.objectClass -eq 'user') {
                $x = Get-ADUser $u.SID -Properties Enabled, LastLogonDate, PasswordLastSet, Description, PasswordNeverExpires
                Write-Output ("  {0,-20} Enabled={1,-5} LastLogon={2} PwdSet={3} NeverExp={4}" -f `
                    $x.SamAccountName, $x.Enabled, $x.LastLogonDate, $x.PasswordLastSet, $x.PasswordNeverExpires)
            } else { Write-Output ("  {0,-20} (nested {1})" -f $u.SamAccountName, $u.objectClass) }
        }
    } catch { Write-Output "`n=== ${g}: ERROR $($_.Exception.Message)" }
}

Write-Output "`n=== ALL adminCount=1 USERS (protected / currently-or-formerly privileged) ==="
Get-ADUser -LDAPFilter '(adminCount=1)' -Properties Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires |
    Sort-Object SamAccountName | ForEach-Object {
        Write-Output ("  {0,-20} Enabled={1,-5} LastLogon={2} PwdSet={3} NeverExp={4}" -f `
            $_.SamAccountName, $_.Enabled, $_.LastLogonDate, $_.PasswordLastSet, $_.PasswordNeverExpires)
    }

Write-Output "`n=== DOMAIN ACCOUNTS RUNNING SERVICES / TASKS ON THIS DC (don't rotate blind) ==="
Get-CimInstance Win32_Service | Where-Object { $_.StartName -and $_.StartName -notmatch '^(LocalSystem|NT AUTHORITY|NT Service)' } |
    ForEach-Object { Write-Output ("  service {0} | {1} | {2}" -f $_.Name, $_.StartName, $_.State) }
try {
    Get-ScheduledTask | ForEach-Object {
        $u = $_.Principal.UserId
        if ($u -and $u -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|Users|Administrators|INTERACTIVE|Authenticated Users)$') {
            Write-Output ("  task {0}{1} | {2}" -f $_.TaskPath, $_.TaskName, $u)
        }
    }
} catch {}
Write-Output "`n=== AUDIT COMPLETE ==="
