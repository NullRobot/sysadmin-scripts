#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only reality check on a GPO: does it actually APPLY, to whom, and to how many
    computers?

.DESCRIPTION
    A GPO's settings only matter if the GPO actually applies. This reconciles the GPO
    against reality, which is the fastest way to triage a "scary-looking" policy or a
    "why isn't this applying" complaint:
      - creation/modification times and version numbers (and whether the AD (DS) and
        SYSVOL versions agree; a mismatch = replication issue)
      - security filtering: WHO holds Apply Group Policy (the #1 reason a
        scary-looking GPO does nothing). Flags user-only filtering that silently
        disables the computer half.
      - WMI filter, link status, block-inheritance on each linked OU
      - how many COMPUTERS actually sit under each linked OU (the real blast radius),
        with per-machine enabled/lastLogon detail

    Run on a DC or RSAT box, elevated. Changes nothing.

.PARAMETER GpoName
    Display name of the GPO to inspect.

.EXAMPLE
    .\Get-GpoScopeReport.ps1 -GpoName 'Workstation Lockdown'
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$GpoName)
$ErrorActionPreference = 'Continue'
Import-Module GroupPolicy -ErrorAction SilentlyContinue
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
function Say { param([string]$m,[string]$c='Gray') Write-Host $m -ForegroundColor $c }

$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) { Say "GPO '$GpoName' not found." 'Red'; return }

Say "`n========  $($gpo.DisplayName)  ========" 'Cyan'
Say ("Created : {0}" -f $gpo.CreationTime)
Say ("Modified: {0}   <-- last updated" -f $gpo.ModificationTime) 'Cyan'
Say ("Status  : {0}" -f $gpo.GpoStatus)
$cMis = ($gpo.Computer.DSVersion -ne $gpo.Computer.SysvolVersion)
Say ("Computer-side version  AD={0}  SYSVOL={1}{2}" -f $gpo.Computer.DSVersion, $gpo.Computer.SysvolVersion, $(if($cMis){'   <-- MISMATCH: AD and SYSVOL disagree, replication issue'}else{''})) $(if($cMis){'Red'}else{'Gray'})
$uMis = ($gpo.User.DSVersion -ne $gpo.User.SysvolVersion)
Say ("User-side version      AD={0}  SYSVOL={1}{2}" -f $gpo.User.DSVersion, $gpo.User.SysvolVersion, $(if($uMis){'   <-- MISMATCH'}else{''})) $(if($uMis){'Red'}else{'Gray'})
if ($gpo.Computer.DSVersion -eq 0) { Say "Computer-side version is 0 -> the computer half looks like it was never populated/processed." 'Yellow' }
Say ("WMI filter: {0}" -f $(if($gpo.WmiFilter){$gpo.WmiFilter.Name}else{'(none)'})) $(if($gpo.WmiFilter){'Yellow'}else{'Gray'})

# ---- security filtering: who actually gets to APPLY it ----
Say "`n----- security filtering (who it actually applies to) -----" 'White'
$perms = Get-GPPermission -Guid $gpo.Id -All -ErrorAction SilentlyContinue
$apply = @($perms | Where-Object { $_.Permission -eq 'GpoApply' })
if ($apply.Count -eq 0) {
    Say "  NOBODY holds 'Apply Group Policy'. As written this GPO applies to NOTHING." 'Red'
} else {
    foreach ($a in $apply) { Say ("  APPLY: {0}  ({1})" -f $a.Trustee.Name, $a.Trustee.SidType) 'Yellow' }
}
$authU = @($apply | Where-Object { $_.Trustee.Name -match '(?i)Authenticated Users' })
$domC  = @($apply | Where-Object { $_.Trustee.Name -match '(?i)Domain Computers' })
if ($apply.Count -gt 0 -and $authU.Count -eq 0 -and $domC.Count -eq 0) {
    Say "  It is filtered to the principal(s) above ONLY (not all computers)." 'Yellow'
    Say "  If those are USER groups, computer-side settings will NOT apply (computers need Apply themselves)." 'Yellow'
}

# ---- links + the OU's computer count (the real blast radius) ----
Say "`n----- links, and how many computers sit under them -----" 'White'
[xml]$rpt = Get-GPOReport -Guid $gpo.Id -ReportType Xml
function SomToDN { param([string]$som)
    $parts = $som -split '/'
    $dc  = (($parts[0] -split '\.') | ForEach-Object { "DC=$_" }) -join ','
    $ous = @()
    for ($i = $parts.Count - 1; $i -ge 1; $i--) { $ous += "OU=$($parts[$i])" }
    if ($ous.Count) { ($ous -join ',') + ',' + $dc } else { $dc }
}
foreach ($l in $rpt.SelectNodes("//*[local-name()='LinksTo']")) {
    $som = ($l.SelectSingleNode("*[local-name()='SOMPath']")).InnerText
    $en  = ($l.SelectSingleNode("*[local-name()='Enabled']")).InnerText
    $dn  = SomToDN $som
    Say ("  link: {0}   (enabled={1})" -f $som, $en) 'Gray'
    Say ("    OU DN: {0}" -f $dn) 'DarkGray'
    try {
        $comps   = @(Get-ADComputer -SearchBase $dn -SearchScope Subtree -Filter * -Properties Enabled, LastLogonTimestamp, OperatingSystem -ErrorAction Stop)
        $enabled = @($comps | Where-Object { $_.Enabled })
        Say ("    COMPUTERS in scope: {0} total, {1} enabled" -f $comps.Count, $enabled.Count) 'Cyan'
        $comps | Sort-Object Name | ForEach-Object {
            $ll = if ($_.LastLogonTimestamp) { [DateTime]::FromFileTime([int64]$_.LastLogonTimestamp).ToString('yyyy-MM-dd') } else { 'never' }
            Say ("      {0,-18} enabled={1,-5} lastLogon={2}  {3}" -f $_.Name, $_.Enabled, $ll, $_.OperatingSystem) 'Gray'
        }
        try { $inh = Get-GPInheritance -Target $dn -ErrorAction Stop; if ("$($inh.GpoInheritanceBlocked)" -notmatch '(?i)no|false') { Say "    NOTE: this OU blocks inheritance." 'Yellow' } } catch {}
    } catch { Say ("    could not enumerate computers under {0}: {1}" -f $dn, $_.Exception.Message) 'Yellow' }
}

Say "`nGROUND TRUTH: to confirm the effect on one endpoint, check the setting directly on a machine listed above" 'Cyan'
Say "(e.g. for a Restricted Groups local-admin grant:  net localgroup Administrators)." 'Cyan'
