<#
.SYNOPSIS
    Probe a Dell iDRAC over the network and read basic system info via Redfish.
.DESCRIPTION
    Read-only. Confirms an IP is a Dell iDRAC and pulls its identity and power state without needing
    a browser. First does a fast TCP port probe (443/22/623/80/5900) and grabs the 443 cert subject
    (iDRAC certs identify the box), then queries the Redfish root for version/vendor. If iDRAC
    credentials are supplied (via env var, never a literal), it reads /redfish/v1/Systems for model,
    power state, host name, serial, and BIOS version. Handy for finding a "which box is 10.x.x.x"
    and checking whether a server is actually powered on when it's unreachable by other means.
.PARAMETER Address
    iDRAC IP or hostname.
.PARAMETER Username
    iDRAC user for the authenticated system query. Default 'root'. Password comes from $env:IDRAC_PW.
.NOTES
    Set $env:IDRAC_PW for the authenticated portion; without it you still get ports, cert, and Redfish
    root. Certificate validation is bypassed (iDRACs ship self-signed certs). Read-only - no changes.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Address,
    [string]$Username = 'root'
)

$ErrorActionPreference = 'SilentlyContinue'

$ports = foreach ($p in 443,22,623,80,5900) {
    $t = New-Object Net.Sockets.TcpClient
    $a = $t.BeginConnect($Address, $p, $null, $null)
    if ($a.AsyncWaitHandle.WaitOne(800)) { try { $t.EndConnect($a); $p } catch {} }
    $t.Close()
}
"Ports open on ${Address}: $(($ports -join ',') -replace '^$','none')"

try {
    $tc  = New-Object Net.Sockets.TcpClient($Address, 443)
    $cb  = [Net.Security.RemoteCertificateValidationCallback] { param($a,$b,$c,$d) $true }
    $ssl = New-Object Net.Security.SslStream($tc.GetStream(), $false, $cb)
    $ssl.AuthenticateAsClient($Address)
    "443 cert subject: $(([Security.Cryptography.X509Certificates.X509Certificate2]$ssl.RemoteCertificate).Subject)"
    $ssl.Close(); $tc.Close()
} catch { "cert grab failed: $($_.Exception.Message)" }

Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class IDracTA : ICertificatePolicy { public bool CheckValidationResult(ServicePoint s, X509Certificate c, WebRequest r, int p) { return true; } }
"@
[Net.ServicePointManager]::CertificatePolicy = New-Object IDracTA
[Net.ServicePointManager]::SecurityProtocol  = [Net.SecurityProtocolType]::Tls12

try {
    $r = Invoke-RestMethod -Uri "https://$Address/redfish/v1" -TimeoutSec 12
    "Redfish: version=$($r.RedfishVersion) product=$($r.Product) vendor=$($r.Vendor)"
} catch { "Redfish root failed (may be a pre-Redfish iDRAC): $($_.Exception.Message)" }

if ($env:IDRAC_PW) {
    try {
        $b = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${Username}:$($env:IDRAC_PW)"))
        $s = Invoke-RestMethod -Uri "https://$Address/redfish/v1/Systems/System.Embedded.1" -Headers @{ Authorization = "Basic $b" } -TimeoutSec 15
        "System: Model=$($s.Model)  Power=$($s.PowerState)  Host=$($s.HostName)  SN=$($s.SerialNumber)  BIOS=$($s.BiosVersion)"
    } catch { "Redfish system query failed: $($_.Exception.Message)" }
} else {
    "Set `$env:IDRAC_PW to read Model/PowerState/Serial/BIOS via the authenticated Redfish endpoint."
}
"DONE"
