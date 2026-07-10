<#
.SYNOPSIS
    Locates and removes a specific DNS server address from a network adapter's
    static DNS configuration, only if it is statically set on the NIC.

.DESCRIPTION
    Public DNS resolvers like 8.8.8.8 sometimes end up statically configured
    on a NIC (manually, by malware, or by a misconfigured provisioning script)
    when the environment expects internal DNS servers instead. This script:
      1. Reads the active NIC's registry-level static and DHCP-provided DNS
         settings directly (avoids caching quirks in Get-DnsClientServerAddress).
      2. If the target DNS address is present in the STATIC NameServer value,
         removes just that address and re-applies the remaining static servers
         (or reverts the NIC to DHCP if no static servers remain).
      3. If the target address is instead coming from DHCP, makes NO changes
         and reports the DHCP server responsible, since the real fix is in the
         DHCP scope's DNS option (006), not on the endpoint.
      4. If the target address isn't present at all, makes no changes and
         prints the current per-interface DNS configuration for review.

    This script is intentionally conservative: it will not touch DNS settings
    that are coming from DHCP, and it will not guess which server to fall back
    to beyond removing the target address from the existing static list.

.PARAMETER TargetDnsServer
    The DNS server IP address to look for and remove if statically configured.
    Defaults to 8.8.8.8.

.EXAMPLE
    .\Remove-StaticDnsServerEntry.ps1
    Checks the first "Up" physical NIC for a static entry of 8.8.8.8 and
    removes it if found.

.EXAMPLE
    .\Remove-StaticDnsServerEntry.ps1 -TargetDnsServer 1.1.1.1
    Same behavior, but looks for 1.1.1.1 instead.

.NOTES
    Run elevated (Administrator). Intended for interactive or remote-session
    use against a single endpoint; adjust the NIC selection logic if you need
    to target a specific adapter by name/index instead of "first Up physical NIC".
#>

[CmdletBinding()]
param(
    [string]$TargetDnsServer = '8.8.8.8'
)

$targetPattern = [regex]::Escape($TargetDnsServer)

$nic = Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1
if (-not $nic) {
    throw "No active physical network adapter found."
}

$guid = $nic.InterfaceGuid
$key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$guid"
$p = Get-ItemProperty $key

"NIC               : $($nic.Name) (ifIndex $($nic.ifIndex))"
"Static NameServer : '$($p.NameServer)'"
"DHCP NameServer   : '$($p.DhcpNameServer)'"
"DHCP Server       : '$($p.DhcpServer)'"

if ($p.NameServer -match $targetPattern) {
    $new = @($p.NameServer -split '[,\s]+' | Where-Object { $_ -and $_ -ne $TargetDnsServer })
    if ($new.Count -gt 0) {
        Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $new
        "FIXED: static DNS now $($new -join ', ') (removed $TargetDnsServer)"
    } else {
        Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ResetServerAddresses
        "FIXED: NIC reverted to DHCP-provided DNS (static entry was only $TargetDnsServer)"
    }
    Clear-DnsClientCache
    Register-DnsClient
    "Verify:"
    Get-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 | ForEach-Object { "  DNS now: $($_.ServerAddresses -join ', ')" }
} elseif ($p.DhcpNameServer -match $targetPattern) {
    "NO CHANGE MADE: $TargetDnsServer is handed out by DHCP (server $($p.DhcpServer)). Fix = remove $TargetDnsServer from DNS servers (option 006) in that DHCP scope; it will hit every machine at the site on lease renewal."
} else {
    "NO CHANGE MADE: $TargetDnsServer not in this NIC's registry DNS config. Per-interface view:"
    Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object ServerAddresses | ForEach-Object { "  $($_.InterfaceAlias) (ifIndex $($_.InterfaceIndex)): $($_.ServerAddresses -join ', ')" }
}
