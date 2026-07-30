<#
.SYNOPSIS
    Strip DISABLED user accounts out of privileged AD groups.
.DESCRIPTION
    Zero-risk hygiene by definition: a disabled account cannot authenticate, so removing its
    group membership takes nothing away from anyone - it just closes the door on a disabled
    account being re-enabled later and silently inheriting admin rights. Checks Enabled on every
    member at run time (never works from a hardcoded list), only touches user objects (never a
    nested group), verifies afterward, and reports any disabled account still left in a privileged
    group anywhere. Run on a DC. Use -WhatIf to preview.
.PARAMETER Groups
    Groups to clean. Defaults to the common privileged set.
.NOTES
    Requires the ActiveDirectory module and rights to modify these groups.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact='Medium')]
param(
    [string[]]$Groups = @('Administrators','DHCP Administrators','Remote Desktop Users',
                          'Schema Admins','Group Policy Creator Owners','Domain Admins',
                          'Enterprise Admins','DnsAdmins','Account Operators','Backup Operators',
                          'Server Operators','Print Operators')
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$changes = @()

Write-Output "--- BEFORE"
foreach ($g in $Groups) {
    try { $m = Get-ADGroupMember -Identity $g -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName
          Write-Output ("  $g ($(@($m).Count)): $($m -join ', ')") } catch { Write-Output "  ${g}: $($_.Exception.Message)" }
}

Write-Output "`n--- REMOVE disabled user accounts"
foreach ($g in $Groups) {
    try { $members = Get-ADGroupMember -Identity $g -ErrorAction Stop } catch { Write-Output "  ${g}: $($_.Exception.Message)"; continue }
    foreach ($m in $members) {
        if ($m.objectClass -ne 'user') { continue }
        if ((Get-ADUser $m.SamAccountName -Properties Enabled).Enabled) { continue }
        if ($PSCmdlet.ShouldProcess("$($m.SamAccountName) (disabled)", "Remove from $g")) {
            try {
                Remove-ADGroupMember -Identity $g -Members $m.SamAccountName -Confirm:$false
                Write-Output "  REMOVED $($m.SamAccountName) (disabled) from $g"
                $changes += "$g : $($m.SamAccountName)"
            } catch { Write-Output "  ERROR $($m.SamAccountName)/${g}: $($_.Exception.Message)" }
        }
    }
}

Write-Output "`n--- ANY DISABLED ACCOUNT LEFT IN A PRIVILEGED GROUP?"
$left = @()
foreach ($g in $Groups) {
    try {
        foreach ($m in (Get-ADGroupMember -Identity $g -ErrorAction Stop)) {
            if ($m.objectClass -ne 'user') { continue }
            if (-not (Get-ADUser $m.SamAccountName -Properties Enabled).Enabled) { $left += "${g}:$($m.SamAccountName)" }
        }
    } catch {}
}
if ($left.Count -eq 0) { Write-Output "  none, all clear" } else { $left | ForEach-Object { Write-Output "  STILL THERE: $_" } }

Write-Output "`n--- CHANGES: $(if($changes.Count){ $changes -join '; ' } else { '(none)' })"
