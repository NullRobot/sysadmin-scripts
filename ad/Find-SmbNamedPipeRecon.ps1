<#
.SYNOPSIS
    Detect AD-recon (BloodHound/SharpHound-style) named-pipe access in the Security log.
.DESCRIPTION
    Read-only. AD enumeration tools open the lsarpc, samr, and srvsvc named pipes in quick
    succession. On a DC with "Detailed File Share" auditing on, each shows up as Security event
    5145 with a RelativeTargetName of the pipe. This scans the retained 5145 log, finds every case
    where the SAME account hit all three pipes in the same second (the recon signature), and - to
    cut false positives from normal Group Policy processing - flags whether a GptTmpl.inf/Registry.pol
    read preceded it within 5s (legitimate) or not (worth investigating). Reports distinct accounts
    and how many are machine accounts. Run on a DC. Requires "Detailed File Share" auditing enabled.
.PARAMETER MaxEvents
    Max 5145 events to pull. Default 40000.
.NOTES
    A read-only detection/threat-hunting aid, not a block. Machine accounts (name ending in $) doing
    the triplet during GP refresh are usually benign; a user or unexpected source is the interesting case.
#>
[CmdletBinding()]
param(
    [int]$MaxEvents = 40000
)

$ErrorActionPreference = 'Continue'
$pipes = @('lsarpc','samr','srvsvc')

$evts = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145} -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
Write-Output ("5145 events pulled: {0}" -f @($evts).Count)
if (@($evts).Count -eq 0) { Write-Output "No 5145 events. Is 'Detailed File Share' auditing enabled on this DC?"; return }
Write-Output ("Window: {0} to {1}" -f @($evts)[-1].TimeCreated, @($evts)[0].TimeCreated)

$rows = foreach ($e in $evts) {
    [pscustomobject]@{
        T    = $e.TimeCreated
        User = [string]$e.Properties[1].Value
        Ip   = [string]$e.Properties[5].Value
        Tgt  = ([string]$e.Properties[9].Value).ToLower()
    }
}

$triplets = @()
foreach ($g in ($rows | Group-Object User)) {
    foreach ($s in ($g.Group | Group-Object { $_.T.ToString('yyyy-MM-dd HH:mm:ss') })) {
        $tgts = @($s.Group.Tgt | Sort-Object -Unique)
        if (@($pipes | Where-Object { $tgts -contains $_ }).Count -eq 3) {
            $t0  = [datetime]::Parse($s.Name)
            $pre = @($g.Group | Where-Object { $_.T -lt $t0 -and $_.T -ge $t0.AddSeconds(-5) -and ($_.Tgt -like '*gpttmpl.inf' -or $_.Tgt -like '*registry.pol') })
            $triplets += [pscustomobject]@{ User = $g.Name; Time = $s.Name; Ip = @($s.Group.Ip)[0]; GpoFileWithin5s = ($pre.Count -gt 0) }
        }
    }
}

Write-Output ("`nTRIPLET HITS (all three pipes, same account, same second): {0}" -f $triplets.Count)
Write-Output ("  preceded by GptTmpl.inf/Registry.pol within 5s (likely GP): {0}" -f @($triplets | Where-Object GpoFileWithin5s).Count)
Write-Output ("  NOT preceded (worth investigating): {0}" -f @($triplets | Where-Object { -not $_.GpoFileWithin5s }).Count)
Write-Output ("  distinct accounts: {0}  (machine accounts: {1})" -f `
    @($triplets.User | Sort-Object -Unique).Count, @($triplets.User | Sort-Object -Unique | Where-Object { $_ -like '*$' }).Count)

Write-Output "`nTriplet hits NOT preceded by a GPO file read:"
$triplets | Where-Object { -not $_.GpoFileWithin5s } | Select-Object -First 20 |
    ForEach-Object { Write-Output ("  {0} | {1} | {2}" -f $_.Time, $_.User, $_.Ip) }
