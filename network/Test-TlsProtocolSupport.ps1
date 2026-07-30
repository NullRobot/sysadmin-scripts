<#
.SYNOPSIS
    Proves which TLS protocol versions (1.0/1.1/1.2) each target actually
    accepts by making real handshake attempts.

.DESCRIPTION
    Registry checks only show intent; auditors want proof. This script opens a
    TCP connection to a TLS-capable port on each target and attempts an SSL
    handshake pinned to each protocol version in turn. A machine passes when
    TLS 1.0 and 1.1 are REJECTED and TLS 1.2 is ACCEPTED.
    The default port 3389 (RDP) works on nearly every Windows box with no
    extra services; use 443 for web servers, 636 for LDAPS, etc.
    Certificate validation is intentionally ignored - only the protocol
    negotiation matters here. Read-only; produces a pass/partial/fail table
    suitable for handing to an auditor.

.PARAMETER Target
    Hostnames or IPs to test.

.PARAMETER Port
    TLS-capable port to handshake against. Default 3389.

.PARAMETER OutputFile
    Optional path to also write the results table to.

.EXAMPLE
    .\Test-TlsProtocolSupport.ps1 -Target FS01,DC01,10.0.0.55 -Port 3389
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$Target,
    [int]$Port = 3389,
    [string]$OutputFile
)

function Test-TLSVersion {
    param([string]$TargetHost, [string]$Protocol, [int]$TcpPort)
    $tcp = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($TargetHost, $TcpPort)
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false,
            {param($s,$c,$ch,$e) return $true})  # ignore cert errors; we only care about protocol
        $sslProtocol = switch ($Protocol) {
            "TLS10" { [System.Security.Authentication.SslProtocols]::Tls }
            "TLS11" { [System.Security.Authentication.SslProtocols]::Tls11 }
            "TLS12" { [System.Security.Authentication.SslProtocols]::Tls12 }
        }
        $ssl.AuthenticateAsClient($TargetHost, $null, $sslProtocol, $false)
        $ssl.Close()
        $tcp.Close()
        return "ACCEPTED"
    } catch {
        if ($tcp -and $tcp.Connected) { $tcp.Close() }
        return "REJECTED"
    }
}

$results = @()
$total = $Target.Count
$i = 0

foreach ($t in $Target) {
    $i++
    Write-Host "[$i/$total] Testing ${t}:${Port} ..." -NoNewline

    $tls10 = Test-TLSVersion -TargetHost $t -Protocol "TLS10" -TcpPort $Port
    $tls11 = Test-TLSVersion -TargetHost $t -Protocol "TLS11" -TcpPort $Port
    $tls12 = Test-TLSVersion -TargetHost $t -Protocol "TLS12" -TcpPort $Port

    $status = if ($tls10 -eq "REJECTED" -and $tls11 -eq "REJECTED" -and $tls12 -eq "ACCEPTED") { "PASS" }
              elseif ($tls12 -eq "ACCEPTED") { "PARTIAL" }
              else { "FAIL" }

    Write-Host " TLS1.0=$tls10 TLS1.1=$tls11 TLS1.2=$tls12 [$status]"

    $results += [PSCustomObject]@{
        Host   = $t
        TLS10  = $tls10
        TLS11  = $tls11
        TLS12  = $tls12
        Result = $status
    }
}

Write-Host "`n=== TLS VERIFICATION RESULTS - $(Get-Date) ===`n"
$table = $results | Format-Table -AutoSize | Out-String -Width 200
Write-Host $table

$pass = @($results | Where-Object Result -eq "PASS").Count
$partial = @($results | Where-Object Result -eq "PARTIAL").Count
$fail = @($results | Where-Object Result -eq "FAIL").Count
$summary = @"
PASS    = TLS 1.0 REJECTED + TLS 1.1 REJECTED + TLS 1.2 ACCEPTED (fully remediated)
PARTIAL = TLS 1.2 works but older protocols still accepted (usually pending a reboot)
FAIL    = TLS 1.2 not working (investigate before doing anything else)

Passed: $pass | Partial: $partial | Failed: $fail | Total: $($results.Count)
"@
Write-Host $summary

if ($OutputFile) {
    $table + $summary | Set-Content $OutputFile
    Write-Host "Results saved to: $OutputFile"
}
