<<'EOF'
<#
.SYNOPSIS
    Tests whether the currently cached Az PowerShell context has direct ARM
    read access to a given Azure subscription.

.DESCRIPTION
    Useful when troubleshooting delegated-admin or cross-tenant access
    scenarios (e.g. CSP partner access, Azure Lighthouse, guest accounts)
    where it's not obvious whether your current sign-in can actually reach
    a target subscription. Grabs an ARM access token from the cached Az
    context and attempts a direct GET on the subscription resource. On
    failure it prints the ARM error body, which typically includes the
    tenant ID the subscription actually belongs to - handy for spotting a
    tenant mismatch at a glance.

.PARAMETER SubscriptionId
    The Azure subscription ID (GUID) to test access against.

.EXAMPLE
    .\test-subscription-arm-access.ps1 -SubscriptionId '11111111-2222-3333-4444-555555555555'

    Requires an existing Az PowerShell login (Connect-AzAccount) in the
    current session; the script uses the cached context rather than
    prompting for credentials.

.NOTES
    Requires the Az.Accounts module and an active Connect-AzAccount session.
    Exits with code 1 if no cached Az context is found.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string]$SubscriptionId
)

$ErrorActionPreference = 'Continue'

$ctx = Get-AzContext
if (-not $ctx) {
    Write-Output 'No cached Az context, re-auth needed.'
    exit 1
}
Write-Output "Using cached context: $($ctx.Account.Id) tenant $($ctx.Tenant.Id)"

$t = Get-AzAccessToken -ResourceUrl 'https://management.azure.com/'
# Az 14+ returns Token as SecureString; convert to plain text for the header
$plain = if ($t.Token -is [securestring]) { [System.Net.NetworkCredential]::new('', $t.Token).Password } else { $t.Token }
$headers = @{ Authorization = "Bearer $plain" }

try {
    $r = Invoke-RestMethod -Uri "https://management.azure.com/subscriptions/${SubscriptionId}?api-version=2020-01-01" -Headers $headers
    Write-Output "Direct read WORKED: $($r.displayName) state=$($r.state)"
} catch {
    Write-Output '--- ARM error (look for the expected tenant GUID) ---'
    Write-Output $_.ErrorDetails.Message
}
EOF