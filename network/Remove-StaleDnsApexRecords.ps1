<#
.SYNOPSIS
    Removes unwanted "same as parent" (apex/@) A records from an AD-integrated DNS
    zone and stops domain controllers from re-registering their own IPs at the apex.

.DESCRIPTION
    Classic problem when the AD domain name matches the public website domain
    (company.com is both): every DC's Netlogon registers its own IP as an apex
    LdapIpAddress A record, DNS round-robins the apex, and internal users
    intermittently hit a DC instead of the website.

    This script, run ON the DNS server / DC:
      1. Shows the BEFORE state of apex A records
      2. Deletes each -StaleIp apex A record
      3. Adds 'LdapIpAddress' to Netlogon's DnsAvoidRegisterRecords multi-string
         (HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters), merging with
         any existing entries, so the DC stops re-registering itself at the apex
      4. Restarts Netlogon and verifies with repeated Resolve-DnsName queries

    NOTE: set DnsAvoidRegisterRecords on EVERY DC in the domain (each one registers
    itself), and remember domain-joined clients that genuinely need LDAP find DCs
    via SRV records, not the apex A record, so this is safe for AD operation.

.PARAMETER ZoneName
    The DNS zone (usually the AD domain name).

.PARAMETER StaleIp
    The apex A-record IPs to delete (the DC self-registrations).

.PARAMETER SkipNetlogonFix
    Only delete the records; don't touch DnsAvoidRegisterRecords.

.EXAMPLE
    .\Remove-StaleDnsApexRecords.ps1 -ZoneName corp.example.com -StaleIp 10.0.1.10,10.0.2.10
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$ZoneName,
    [Parameter(Mandatory)][string[]]$StaleIp,
    [switch]$SkipNetlogonFix
)

$ErrorActionPreference = 'Stop'

Write-Host "`n=== BEFORE: apex (@) A records on $ZoneName ===" -ForegroundColor Cyan
Get-DnsServerResourceRecord -ZoneName $ZoneName -RRType A |
    Where-Object { $_.HostName -eq '@' } |
    Format-Table HostName, Timestamp, @{N='IP';E={$_.RecordData.IPv4Address.IPAddressToString}}, TimeToLive -AutoSize

foreach ($ip in $StaleIp) {
    if ($PSCmdlet.ShouldProcess("$ZoneName apex", "delete A record -> $ip")) {
        Write-Host "=== Delete @ -> $ip ===" -ForegroundColor Yellow
        Remove-DnsServerResourceRecord -ZoneName $ZoneName -Name '@' -RRType A -RecordData $ip -Force -ErrorAction Stop
        Write-Host "  Deleted" -ForegroundColor Green
    }
}

if (-not $SkipNetlogonFix) {
    Write-Host "=== Set DnsAvoidRegisterRecords -> LdapIpAddress ===" -ForegroundColor Yellow
    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    $existing = (Get-ItemProperty -Path $regPath -Name 'DnsAvoidRegisterRecords' -ErrorAction SilentlyContinue).DnsAvoidRegisterRecords
    Write-Host "  Existing: $(($existing | Out-String).Trim())"
    if ($existing -and ($existing -contains 'LdapIpAddress')) {
        Write-Host "  LdapIpAddress already present - no change needed" -ForegroundColor Yellow
    } else {
        $newValue = @($existing) + 'LdapIpAddress' | Where-Object { $_ } | Sort-Object -Unique
        Set-ItemProperty -Path $regPath -Name 'DnsAvoidRegisterRecords' -Value $newValue -Type MultiString
        Write-Host "  Set to: $($newValue -join ', ')" -ForegroundColor Green
    }

    Write-Host "=== Restart Netlogon ===" -ForegroundColor Yellow
    Restart-Service Netlogon -Force
    Write-Host "  Restarted" -ForegroundColor Green
    Start-Sleep -Seconds 8
}

Write-Host "`n=== AFTER: apex (@) A records ===" -ForegroundColor Cyan
Get-DnsServerResourceRecord -ZoneName $ZoneName -RRType A |
    Where-Object { $_.HostName -eq '@' } |
    Format-Table HostName, Timestamp, @{N='IP';E={$_.RecordData.IPv4Address.IPAddressToString}}, TimeToLive -AutoSize

Write-Host "=== VERIFY: 5 resolves (should all return only the intended IPs) ===" -ForegroundColor Cyan
for ($i = 1; $i -le 5; $i++) {
    $r = Resolve-DnsName $ZoneName -Server localhost -Type A -DnsOnly | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress }
    Write-Host ("  Query {0}: {1}" -f $i, ($r -join ', '))
}
Write-Host "`nRemember: apply the DnsAvoidRegisterRecords change on EVERY DC in the domain."
