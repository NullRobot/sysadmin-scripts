<#
.SYNOPSIS
    Sweep the local /24 for live SMB hosts and flag which are NOT domain-managed.
.DESCRIPTION
    Read-only. Run as SYSTEM or admin on ONE online Windows box at the site you want to map. It
    auto-detects the box's own /24 (so the same script works at any site with no editing), TCP-connect
    sweeps 1-254 on port 445 to find every live Windows host (managed or not), then classifies each:
    a host that resolves to a name in your AD domain is "managed"; anything else (a foreign .local,
    a workgroup box, no DNS record) is a legacy/unmanaged candidate - the rogue XP/7/8.1 units and
    shadow-IT boxes a vulnerability scan often misses. Uses only TCP connect + DNS/NetBIOS name lookup;
    it does not authenticate to any other host and changes nothing.
.PARAMETER DomainMatch
    Substring that marks a resolved name as domain-managed (e.g. your AD DNS suffix like 'contoso').
    Defaults to the env domain's first label.
.PARAMETER TimeoutMs
    Per-host TCP connect timeout. Default 250.
.NOTES
    An OS/port sweep from inside the network can trip EDR - give the SOC a heads-up on noisy sites.
#>
[CmdletBinding()]
param(
    [string]$DomainMatch = ($env:USERDNSDOMAIN -split '\.')[0],
    [int]$TimeoutMs = 250
)

$ErrorActionPreference = 'SilentlyContinue'

$me = Get-NetIPAddress -AddressFamily IPv4 |
      Where-Object { $_.PrefixLength -eq 24 -and $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } |
      Select-Object -First 1
if (-not $me) { Write-Output 'No /24 IPv4 interface found on this box'; return }
$base = ($me.IPAddress -split '\.')[0..2] -join '.'
Write-Output "This box: $($me.IPAddress)   sweeping $base.1-254 (SMB/445)   domain-match='$DomainMatch'"

$live = foreach ($n in 1..254) {
    $ip = "$base.$n"
    $t  = New-Object Net.Sockets.TcpClient
    $ar = $t.BeginConnect($ip, 445, $null, $null)
    if ($ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { try { $t.EndConnect($ar); $ip } catch {} }
    $t.Close()
}
Write-Output "Live SMB hosts: $($live.Count)"

$managed = @(); $unmanaged = @()
foreach ($ip in $live) {
    $dns = try { ([Net.Dns]::GetHostEntry($ip)).HostName } catch { $null }
    if ($dns -and $DomainMatch -and $dns -match [regex]::Escape($DomainMatch)) {
        $managed += [pscustomobject]@{ IP = $ip; Name = $dns }
    } else {
        $nb = (nbtstat -A $ip 2>$null | Select-String '<00>\s+UNIQUE' | Select-Object -First 1) -replace '.*?(\S+)\s+<00>.*', '$1'
        $name = if ($dns) { $dns } elseif ($nb) { "$($nb.Trim()) (NetBIOS)" } else { '(no name)' }
        $unmanaged += [pscustomobject]@{ IP = $ip; Name = $name }
    }
}

Write-Output "`n=== Domain-managed on $base.0/24: $($managed.Count) ==="
$managed   | Sort-Object { [version]$_.IP } | ForEach-Object { "  {0,-15} {1}" -f $_.IP, $_.Name }
Write-Output "=== NOT domain-managed (legacy / unmanaged candidates): $($unmanaged.Count) ==="
$unmanaged | Sort-Object { [version]$_.IP } | ForEach-Object { "  {0,-15} {1}" -f $_.IP, $_.Name }
Write-Output "=== DONE ==="
