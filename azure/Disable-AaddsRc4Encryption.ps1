<#
.SYNOPSIS
    Disables RC4 Kerberos encryption (and optionally enables Kerberos armoring) on a
    Microsoft Entra Domain Services managed domain, preserving every other security
    setting. Clears the AADDS123 "weak cipher" health alert.

.DESCRIPTION
    The AADDS domainSecuritySettings blob must be submitted whole - a naive PATCH of
    just kerberosRc4Encryption wipes the other flags. This script:
      1. Finds the Microsoft.AAD/domainServices resource in the current subscription
      2. Prints the BEFORE state as a baseline
      3. Copies ALL existing domainSecuritySettings, flipping only
         kerberosRc4Encryption -> Disabled (and kerberosArmoring -> Enabled unless
         -SkipArmoring)
      4. Applies via Set-AzResource and verifies the AFTER state
      5. Lists any still-active AADDS health alerts (AADDS123 can take up to 2 hours
         to clear on its own)

    BEFORE RUNNING: confirm nothing still authenticates with RC4-HMAC, or those
    clients break. Enable AADDS diagnostic logging to a Log Analytics workspace and
    query AADDomainServicesAccountLogon for TicketEncryptionType 0x17 (RC4) events
    over several days first.

    Requires Az.Resources and a connected Az context in the customer tenant.

.PARAMETER SkipArmoring
    Only disable RC4; leave kerberosArmoring untouched.

.EXAMPLE
    Connect-AzAccount -Tenant <customer-tenant-id>
    .\Disable-AaddsRc4Encryption.ps1
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [switch]$SkipArmoring
)

$WarningPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'

Write-Host "`n=== Step 1: Find the AADDS resource ===" -ForegroundColor Cyan
$res = Get-AzResource -ResourceType 'Microsoft.AAD/domainServices' -ExpandProperties
if (-not $res) { throw 'No Microsoft.AAD/domainServices resource found in the current subscription.' }
if ($res.Count -gt 1) { throw 'Multiple AADDS resources found; narrow the Az context first.' }
Write-Host "  $($res.Name) in $($res.ResourceGroupName)" -ForegroundColor Green

Write-Host "`n=== Step 2: BEFORE state (baseline) ===" -ForegroundColor Yellow
$res.Properties.domainSecuritySettings | Format-List

Write-Host "`n=== Step 3: Build new settings (preserve everything else) ===" -ForegroundColor Cyan
$newHash = @{}
$res.Properties.domainSecuritySettings.PSObject.Properties | ForEach-Object {
    $newHash[$_.Name] = $_.Value
}
$newHash['kerberosRc4Encryption'] = 'Disabled'
if (-not $SkipArmoring) { $newHash['kerberosArmoring'] = 'Enabled' }

Write-Host "  New values to be submitted:" -ForegroundColor Cyan
$newHash.GetEnumerator() | Sort-Object Name | ForEach-Object {
    Write-Host ("    {0,-25} = {1}" -f $_.Name, $_.Value)
}

if (-not $PSCmdlet.ShouldProcess($res.Name, 'Disable RC4 Kerberos encryption on the managed domain')) { return }

Write-Host "`n=== Step 4: Apply via Set-AzResource ===" -ForegroundColor Cyan
$properties = @{ domainSecuritySettings = $newHash }
$result = Set-AzResource -Id $res.ResourceId -Properties $properties -ApiVersion '2021-03-01' -Force
Write-Host "  Submitted. Provisioning state: $($result.Properties.provisioningState)" -ForegroundColor Green

Write-Host "`n=== Step 5: Verify (wait 15s for propagation) ===" -ForegroundColor Cyan
Start-Sleep -Seconds 15
$res2 = Get-AzResource -ResourceType 'Microsoft.AAD/domainServices' -ExpandProperties
Write-Host "  AFTER state:" -ForegroundColor Green
$res2.Properties.domainSecuritySettings | Format-List

$rc4After = $res2.Properties.domainSecuritySettings.kerberosRc4Encryption
Write-Host "`n=== Verdict ===" -ForegroundColor Cyan
if ($rc4After -eq 'Disabled') {
    Write-Host "  SUCCESS: RC4 Disabled." -ForegroundColor Green
    Write-Host "  The AADDS123 health alert should clear within about 2 hours." -ForegroundColor Green
} else {
    Write-Host "  MISMATCH: kerberosRc4Encryption=$rc4After - investigate before declaring done." -ForegroundColor Red
}

Write-Host "`n=== Active health alerts (now) ===" -ForegroundColor Cyan
$alerts = $res2.Properties.health.healthAlerts
if ($alerts) {
    $alerts | ForEach-Object {
        [PSCustomObject]@{ Id = $_.id; Name = $_.name; IssueOn = $_.issueOn; LastDetect = $_.lastDetected }
    } | Format-Table -AutoSize
} else {
    Write-Host "  No active alerts." -ForegroundColor Green
}
