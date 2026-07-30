<#
.SYNOPSIS
    Read-only audit of why an Azure Files share is (or isn't) mountable: identity-based
    auth mode, shared-key state, network rules, key rotation age, and share inventory.

.DESCRIPTION
    The first-pass diagnostic for "the mapped drive to Azure Files stopped working"
    (AVD hosts, VDI, file-server-replacement scenarios). For each storage account:
      1. AzureFilesIdentityBasedAuthentication - the big question: AD / AADDS /
         AADKERB / None, plus DefaultSharePermission and AD properties
      2. Top-level toggles: AllowSharedKeyAccess (a common breaker - cmdkey-mapped
         drives die when this is flipped off), PublicNetworkAccess, MinimumTlsVersion
      3. Network rules: DefaultAction, VNet rules, IP allowlist (another common
         breaker when the office IP changed)
      4. Key rotation timestamps (rotated keys invalidate stored cmdkey credentials)
      5. File share inventory
      6. Per-auth-mode guidance on what to validate next

    Read-only. Requires Az.Accounts + Az.Storage and a connected context, or pass
    -TenantId/-SubscriptionId to connect interactively.

.PARAMETER ResourceGroupName
    Resource group containing the storage accounts.

.PARAMETER StorageAccountName
    One or more storage account names to audit.

.PARAMETER TenantId
    Optional tenant to connect to if no matching Az context exists.

.PARAMETER SubscriptionId
    Optional subscription to select.

.EXAMPLE
    .\Get-AzureFilesAuthReport.ps1 -ResourceGroupName Production -StorageAccountName companyfiles,companyarchive
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [Parameter(Mandatory)][string[]]$StorageAccountName,
    [string]$TenantId,
    [string]$SubscriptionId
)

$InformationPreference = 'Continue'

# Az.Accounts startup can emit a harmless Join-Path error when $HOME is empty (e.g. under
# SSH). Load modules tolerantly, then go strict.
$ErrorActionPreference = 'Continue'
if (-not $env:HOME) { $env:HOME = $env:USERPROFILE }
Import-Module Az.Accounts 2>$null
Import-Module Az.Storage  2>$null
$ErrorActionPreference = 'Stop'
if (-not (Get-Command Connect-AzAccount -ErrorAction SilentlyContinue)) { throw 'Az.Accounts failed to load' }
if (-not (Get-Command Get-AzStorageAccount -ErrorAction SilentlyContinue)) { throw 'Az.Storage failed to load' }

# Connect / reuse context
$existing = Get-AzContext -ErrorAction SilentlyContinue
if ($existing -and (-not $TenantId -or $existing.Tenant.Id -eq $TenantId)) {
    Write-Information "Using existing context: $($existing.Account.Id)"
    if ($SubscriptionId -and $existing.Subscription.Id -ne $SubscriptionId) { Set-AzContext -Subscription $SubscriptionId | Out-Null }
} else {
    $connectArgs = @{}
    if ($TenantId) { $connectArgs.Tenant = $TenantId }
    if ($SubscriptionId) { $connectArgs.Subscription = $SubscriptionId }
    Connect-AzAccount @connectArgs | Out-Null
}
$ctx = Get-AzContext
Write-Information "Account: $($ctx.Account.Id)   Tenant: $($ctx.Tenant.Id)   Sub: $($ctx.Subscription.Name)"

foreach ($name in $StorageAccountName) {
    Write-Information ''
    Write-Information '============================================================'
    Write-Information " Storage account: $name"
    Write-Information '============================================================'

    $sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $name

    Write-Information ''
    Write-Information '----- Identity-Based Authentication (the big question) -----'
    if ($null -ne $sa.AzureFilesIdentityBasedAuthentication) {
        $auth = $sa.AzureFilesIdentityBasedAuthentication
        "DirectoryServiceOptions  : $($auth.DirectoryServiceOptions)"
        "DefaultSharePermission   : $($auth.DefaultSharePermission)"
        if ($auth.ActiveDirectoryProperties) {
            Write-Information '  ActiveDirectoryProperties:'
            $auth.ActiveDirectoryProperties | Format-List | Out-String | Write-Information
        }
    } else {
        Write-Information '  NULL -- no identity-based auth configured (storage account key only)'
    }

    Write-Information ''
    Write-Information '----- Top-level toggles -----'
    "AllowSharedKeyAccess     : $($sa.AllowSharedKeyAccess)"
    "AllowBlobPublicAccess    : $($sa.AllowBlobPublicAccess)"
    "PublicNetworkAccess      : $($sa.PublicNetworkAccess)"
    "MinimumTlsVersion        : $($sa.MinimumTlsVersion)"
    "EnableHttpsTrafficOnly   : $($sa.EnableHttpsTrafficOnly)"
    "LargeFileSharesState     : $($sa.LargeFileSharesState)"

    Write-Information ''
    Write-Information '----- Network Rules (firewall + VNets + IP allowlist) -----'
    "DefaultAction            : $($sa.NetworkRuleSet.DefaultAction)"
    "Bypass                   : $($sa.NetworkRuleSet.Bypass)"
    Write-Information '  Virtual Network Rules:'
    $sa.NetworkRuleSet.VirtualNetworkRules | Format-Table Action, State, VirtualNetworkResourceId -AutoSize | Out-String | Write-Information
    Write-Information '  IP Rules:'
    $sa.NetworkRuleSet.IpRules | Format-Table Action, IPAddressOrRange -AutoSize | Out-String | Write-Information

    Write-Information ''
    Write-Information '----- Key Rotation Timestamps -----'
    if ($sa.KeyCreationTime) {
        "key1 created: $($sa.KeyCreationTime.Key1)"
        "key2 created: $($sa.KeyCreationTime.Key2)"
    } else {
        Write-Information '  Key creation timestamps not exposed by API'
    }

    Write-Information ''
    Write-Information '----- File Shares on this account -----'
    try {
        Get-AzStorageShare -Context $sa.Context |
            Select-Object Name, @{n='QuotaGiB';e={$_.Quota}}, LastModified |
            Format-Table -AutoSize | Out-String | Write-Information
    } catch {
        Write-Warning "Could not enumerate shares: $_"
    }

    Write-Information ''
    Write-Information '----- What to validate next for this auth mode -----'
    $opt = $sa.AzureFilesIdentityBasedAuthentication.DirectoryServiceOptions
    switch ($opt) {
        'AADKERB' {
            Write-Information '  AADKERB: check the AzureADKerberosServer object (Get-AzureADKerberosServer on a hybrid DC,'
            Write-Information '  or Graph directory federation config). Compare AD vs Cloud key versions and key age.'
        }
        'AD' {
            Write-Information '  AD DS: validate the storage account computer object in AD has SPNs for cifs/<name>.file.core.windows.net'
            Write-Information '  and that its password has been rotated within the rotation window.'
        }
        'AADDS' {
            Write-Information '  Azure AD DS (legacy): verify AADDS managed domain health.'
        }
        default {
            Write-Information '  Identity-based auth DISABLED: drive maps rely on the storage account key (cmdkey) or SAS.'
            Write-Information '  Check Credential Manager on the client and whether AllowSharedKeyAccess/keys changed.'
        }
    }
}

Write-Information ''
Write-Information 'Done. Az session left connected for follow-up queries.'
