<#
.SYNOPSIS
    Audits AD privileged group membership (Domain/Enterprise/Schema Admins and
    more) with account health details, for security reviews and cleanups.

.DESCRIPTION
    For each privileged group, expands membership RECURSIVELY (nested groups
    hide members from a casual GPMC look) and reports each member's enabled
    state, last logon, creation date, and description - exactly what you need
    to spot stale vendor accounts, ex-employees, and service accounts that
    never should have been Domain Admins. Also prints per-account detail for
    any extra accounts you name, total user counts, and the state of the
    built-in Administrator account. Read-only; run on a DC (or any machine
    with RSAT) as a domain user with read rights.

.PARAMETER Group
    Groups to audit. Default: Domain Admins, Enterprise Admins, Schema Admins,
    Administrators, Account Operators, Backup Operators.

.PARAMETER CheckAccount
    Optional extra account names (Name or SamAccountName) to dump full detail
    for (group memberships, password last set, etc.).

.EXAMPLE
    .\Get-PrivilegedGroupAudit.ps1 -CheckAccount svc-backup,vendor-temp
#>
[CmdletBinding()]
param(
    [string[]]$Group = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators'),
    [string[]]$CheckAccount
)

Import-Module ActiveDirectory -ErrorAction Stop

foreach ($g in $Group) {
    Write-Host "`n========== $($g.ToUpper()) ==========" -ForegroundColor Cyan
    $members = Get-ADGroupMember $g -Recursive -ErrorAction SilentlyContinue
    if (-not $members) {
        Write-Host "  (empty or group not found)"
        continue
    }
    $members | ForEach-Object {
        $u = Get-ADObject $_.distinguishedName -Properties Enabled,LastLogonDate,Description,SamAccountName,ObjectClass,WhenCreated
        [PSCustomObject]@{
            Name           = $u.Name
            SamAccountName = $u.SamAccountName
            ObjectClass    = $u.ObjectClass
            Enabled        = $u.Enabled
            LastLogon      = $u.LastLogonDate
            Created        = $u.WhenCreated
            Description    = $u.Description
        }
    } | Format-Table -AutoSize
}

if ($CheckAccount) {
    Write-Host "`n========== NAMED ACCOUNT DETAIL ==========" -ForegroundColor Cyan
    foreach ($name in $CheckAccount) {
        $found = Get-ADUser -Filter "Name -eq '$name' -or SamAccountName -eq '$name'" -Properties Enabled,LastLogonDate,Description,MemberOf,WhenCreated,PasswordLastSet -ErrorAction SilentlyContinue
        if ($found) {
            Write-Host "`n--- $($found.Name) ($($found.SamAccountName)) ---" -ForegroundColor Yellow
            Write-Host "  Enabled:      $($found.Enabled)"
            Write-Host "  LastLogon:    $($found.LastLogonDate)"
            Write-Host "  PwdLastSet:   $($found.PasswordLastSet)"
            Write-Host "  Created:      $($found.WhenCreated)"
            Write-Host "  Description:  $($found.Description)"
            Write-Host "  Groups:       $(($found.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ', ')"
        } else {
            Write-Host "`n--- $name --- NOT FOUND" -ForegroundColor Red
        }
    }
}

Write-Host "`n========== TOTAL USER COUNT ==========" -ForegroundColor Cyan
$allUsers = Get-ADUser -Filter * -Properties Enabled
$enabled = ($allUsers | Where-Object { $_.Enabled -eq $true }).Count
$disabled = ($allUsers | Where-Object { $_.Enabled -eq $false }).Count
Write-Host "  Total: $($allUsers.Count)  |  Enabled: $enabled  |  Disabled: $disabled"

Write-Host "`n========== BUILT-IN ADMINISTRATOR STATUS ==========" -ForegroundColor Cyan
$admin = Get-ADUser -Identity "Administrator" -Properties Enabled,LastLogonDate,PasswordLastSet,Description -ErrorAction SilentlyContinue
if ($admin) {
    Write-Host "  Enabled:    $($admin.Enabled)"
    Write-Host "  LastLogon:  $($admin.LastLogonDate)"
    Write-Host "  PwdLastSet: $($admin.PasswordLastSet)"
    Write-Host "  Description: $($admin.Description)"
    Write-Host "`nNote: Built-in Administrator cannot be removed from Domain Admins."
    Write-Host "Best practice is to disable it and use dedicated admin accounts."
}

Write-Host "`nAudit complete." -ForegroundColor Green
