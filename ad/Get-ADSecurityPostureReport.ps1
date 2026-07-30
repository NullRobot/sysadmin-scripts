<#
.SYNOPSIS
    Read-only AD security posture recon: privileged group membership, stale/suspect
    accounts, legacy OS inventory, security-related GPOs, krbtgt age, DCs, and trusts.

.DESCRIPTION
    The sweep to run after a pentest report lands, during incident-response triage,
    or when sizing a hardening/remediation project. Everything is a read-only AD or
    GPO query; safe on production DCs.

    Sections:
      1. Membership of every high-privilege group (Domain/Enterprise/Schema Admins,
         Administrators, Account/Server/Backup Operators), recursive
      2. Optional suspect-account hunt (-SuspectFilters name patterns)
      3. User counts: enabled / disabled / enabled-but-stale (no logon in -StaleDays)
      4. Admin-pattern account names (*admin*, *.adm)
      5. Computer inventory + OS distribution of active machines
      6. Optional named-host liveness check (-CheckHosts, e.g. hosts from a report)
      7. All EOL Windows machines still enabled (XP/7/8/2003/2008)
      8. Full GPO inventory + the subset that looks security/hardening-related
      9. krbtgt password age (needs 2 resets if the domain was compromised)
     10. Domain controllers and trusts

    Run on a DC or any box with RSAT AD + GPO modules, as a domain admin.

.PARAMETER StaleDays
    Days without logon that counts as stale. Default 90.

.PARAMETER SuspectFilters
    Optional array of SamAccountName -like patterns to hunt (e.g. '*test*','svc-x*').

.PARAMETER CheckHosts
    Optional array of computer names (e.g. from a pentest report) to check for
    existence/liveness in AD.

.EXAMPLE
    .\Get-ADSecurityPostureReport.ps1 -SuspectFilters '*test*','*temp*' -CheckHosts 'OLDFILESRV','WIN7-ACCT'
#>
[CmdletBinding()]
param(
    [int]$StaleDays = 90,
    [string[]]$SuspectFilters,
    [string[]]$CheckHosts
)

$ErrorActionPreference = 'Continue'
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module GroupPolicy   -ErrorAction SilentlyContinue

function Section($t) { Write-Host "`n========== $t ==========" -ForegroundColor Yellow }

Section "1. Privileged Group Membership (recursive)"
foreach ($g in @('Domain Admins','Enterprise Admins','Administrators','Schema Admins','Account Operators','Server Operators','Backup Operators')) {
    Write-Host "`n[$g]" -ForegroundColor Cyan
    try {
        Get-ADGroupMember -Identity $g -Recursive | Select-Object SamAccountName, ObjectClass | Format-Table -AutoSize | Out-String -Stream
    } catch { "  (group not found or error: $_)" }
}

if ($SuspectFilters) {
    Section "2. Suspect Account Hunt"
    $filter = ($SuspectFilters | ForEach-Object { "SamAccountName -like '$_'" }) -join ' -or '
    Get-ADUser -Filter $filter -Properties Created, Enabled, LastLogonDate, Description |
        Select-Object SamAccountName, Created, Enabled, LastLogonDate, Description | Format-Table -AutoSize
}

Section "3. User Counts and Stale Accounts"
$users = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet
$cutoff = (Get-Date).AddDays(-$StaleDays)
"Total users:       $($users.Count)"
"Enabled:           $(@($users | Where-Object Enabled).Count)"
"Disabled:          $(@($users | Where-Object {-not $_.Enabled}).Count)"
"Enabled but stale (no logon in ${StaleDays}d): $(@($users | Where-Object { $_.Enabled -and ($_.LastLogonDate -lt $cutoff -or -not $_.LastLogonDate) }).Count)"

Section "4. Admin-pattern accounts (*admin* or *.adm)"
Get-ADUser -Filter "SamAccountName -like '*admin*' -or SamAccountName -like '*.adm'" -Properties Enabled, LastLogonDate |
    Select-Object SamAccountName, Enabled, LastLogonDate | Format-Table -AutoSize

Section "5. Computer Inventory + OS Distribution"
$comps = Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion, LastLogonDate, Enabled, IPv4Address
$active = $comps | Where-Object { $_.LastLogonDate -gt $cutoff -and $_.Enabled }
"Total computers in AD: $($comps.Count)"
"Active (logon within ${StaleDays}d, enabled): $(@($active).Count)"
"`nOS distribution (active only):"
$active | Group-Object OperatingSystem | Sort-Object Count -Descending |
    Select-Object Count, Name | Format-Table -AutoSize

if ($CheckHosts) {
    Section "6. Named-host liveness check"
    foreach ($name in $CheckHosts) {
        $c = Get-ADComputer -Filter "Name -eq '$name'" -Properties OperatingSystem, LastLogonDate, Enabled, IPv4Address -ErrorAction SilentlyContinue
        if ($c) {
            "{0,-22} OS={1,-30} Last={2}  Enabled={3}  IP={4}" -f $c.Name, $c.OperatingSystem, $c.LastLogonDate, $c.Enabled, $c.IPv4Address
        } else {
            "{0,-22} NOT FOUND IN AD" -f $name
        }
    }
}

Section "7. EOL Windows machines still enabled (retirement scope)"
$comps | Where-Object { $_.OperatingSystem -match 'Windows 7|Windows 8|2008|2003|XP' -and $_.Enabled } |
    Select-Object Name, OperatingSystem, LastLogonDate, IPv4Address | Format-Table -AutoSize

Section "8. GPO Inventory"
Get-GPO -All | Select-Object DisplayName, GpoStatus, ModificationTime | Sort-Object DisplayName | Format-Table -AutoSize

Section "9. GPOs that look security/hardening-related"
$kw = 'SMB|LLMNR|NetBIOS|NBT|TLS|SSL|Cipher|Schannel|Multicast|mDNS|Broadcast|Hardening|Security|LAPS|Audit'
Get-GPO -All | Where-Object { $_.DisplayName -match $kw } | Format-Table DisplayName, ModificationTime -AutoSize

Section "10. krbtgt password age (needs 2 resets if compromised)"
Get-ADUser krbtgt -Properties PasswordLastSet, 'msDS-KeyVersionNumber' |
    Format-List Name, PasswordLastSet, msDS-KeyVersionNumber

Section "11. Domain Controllers"
Get-ADDomainController -Filter * | Select-Object HostName, IPv4Address, OperatingSystem, IsGlobalCatalog, IsReadOnly | Format-Table -AutoSize

Section "12. Trusts"
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType | Format-Table -AutoSize

Write-Host "`n========== DONE ==========" -ForegroundColor Green
