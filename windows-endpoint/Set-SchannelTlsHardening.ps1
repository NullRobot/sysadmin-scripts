<#
.SYNOPSIS
    Disables TLS 1.0/1.1 and weak ciphers, enables TLS 1.2, and sets a
    GCM-only cipher suite order, on one or many Windows machines.

.DESCRIPTION
    The standard remediation for a security risk assessment finding of
    "legacy TLS enabled". Per target machine it:
      1. Disables TLS 1.0 and 1.1 (Server + Client SCHANNEL keys:
         Enabled=0, DisabledByDefault=1)
      2. Explicitly enables TLS 1.2 (Server + Client)
      3. Sets the cipher suite order policy to ECDHE/DHE + AES-GCM only
      4. Disables RC4, DES, and 3DES ciphers outright
    A REBOOT is required on each target before the changes take effect.
    Verify afterward with network/Test-TlsProtocolSupport.ps1.

    CAUTION: legacy clients or apps pinned to TLS 1.0/1.1 will break.
    Confirm nothing on the machine still needs the old protocols first.
    Safe on Server 2016+ / Windows 10+ in practice.

.PARAMETER ComputerName
    Target machines (uses Invoke-Command / WinRM for remote targets).
    Default: local machine only.

.PARAMETER SkipCipherOrder
    Only disable/enable protocols; leave the cipher suite order alone.

.EXAMPLE
    .\Set-SchannelTlsHardening.ps1 -ComputerName FS01,FS02,DC01
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [switch]$SkipCipherOrder
)

$ScriptBlock = {
    param([bool]$SetCipherOrder)
    $changes = @()

    # --- TLS 1.0 / 1.1 Disable (Server + Client) ---
    $paths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"
    )
    foreach ($path in $paths) {
        if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "Enabled" -Value 0 -Type DWord
        Set-ItemProperty -Path $path -Name "DisabledByDefault" -Value 1 -Type DWord
        $changes += "Disabled: $($path -replace '.*Protocols\\','')"
    }

    # --- TLS 1.2 Enable (Server + Client) ---
    $tlsPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
    )
    foreach ($path in $tlsPaths) {
        if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name "Enabled" -Value 1 -Type DWord
        Set-ItemProperty -Path $path -Name "DisabledByDefault" -Value 0 -Type DWord
        $changes += "Enabled: $($path -replace '.*Protocols\\','')"
    }

    if ($SetCipherOrder) {
        # --- Cipher Suite Order (GCM + ECDHE/DHE only) ---
        $cipherOrder = @(
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
        ) -join ","
        $cipherPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
        if (!(Test-Path $cipherPath)) { New-Item -Path $cipherPath -Force | Out-Null }
        Set-ItemProperty -Path $cipherPath -Name "Functions" -Value $cipherOrder -Type String
        $changes += "Cipher suite order set to GCM-only (6 suites)"
    }

    # --- Disable weak ciphers explicitly ---
    $weakCiphers = @("RC4 40/128", "RC4 56/128", "RC4 64/128", "RC4 128/128", "DES 56/56", "Triple DES 168")
    foreach ($cipher in $weakCiphers) {
        $cPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
        if (!(Test-Path $cPath)) { New-Item -Path $cPath -Force | Out-Null }
        Set-ItemProperty -Path $cPath -Name "Enabled" -Value 0 -Type DWord
    }
    $changes += "Disabled weak ciphers: RC4, DES, 3DES"

    [PSCustomObject]@{
        Computer = $env:COMPUTERNAME
        Status   = "SUCCESS"
        Changes  = ($changes -join "; ")
        Note     = "Reboot required for changes to take full effect"
    }
}

$results = @()
foreach ($server in $ComputerName) {
    if (-not $PSCmdlet.ShouldProcess($server, "Apply SCHANNEL TLS hardening (reboot required)")) { continue }
    Write-Host "Applying to $server ..." -NoNewline
    try {
        if ($server -eq $env:COMPUTERNAME -or $server -eq 'localhost') {
            $r = & $ScriptBlock (-not $SkipCipherOrder)
        } else {
            $r = Invoke-Command -ComputerName $server -ScriptBlock $ScriptBlock -ArgumentList (-not $SkipCipherOrder) -ErrorAction Stop
        }
        Write-Host " OK"
        $results += $r
    } catch {
        Write-Host " FAILED: $($_.Exception.Message)"
        $results += [PSCustomObject]@{
            Computer = $server; Status = "FAILED"; Changes = $_.Exception.Message; Note = ""
        }
    }
}

Write-Host "`n=== TLS HARDENING RESULTS - $(Get-Date) ===`n"
$results | Format-Table Computer, Status, Note -AutoSize
$succeeded = @($results | Where-Object Status -eq "SUCCESS").Count
$failed = @($results | Where-Object Status -eq "FAILED").Count
Write-Host "`nSucceeded: $succeeded | Failed: $failed"
Write-Host "Reboot each target, then verify with Test-TlsProtocolSupport.ps1."
