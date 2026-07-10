<#
.SYNOPSIS
    Diagnoses a common cause of "can't reply to a Microsoft 365 Group" failures in Outlook/OWA.

.DESCRIPTION
    When a user reports they can't reply (or reply-all) to a Microsoft 365 (Unified) Group
    address in Outlook/OWA, this script walks through the usual suspects in one pass:
      1. Confirms the target address is actually a Microsoft 365 Group (not a DL or shared mailbox)
      2. Lists the group's members and owners
      3. Lists the affected user's inbox rules (a rule silently moving/deleting group mail
         can look like a "can't reply" issue)
      4. Checks retention / MRM (litigation hold, retention policy) on both the user's
         mailbox and the group mailbox
      5. Checks Send As / Send on Behalf permissions on the group

    Requires an active Exchange Online connection with rights to the target tenant
    (e.g. via delegated/partner admin access for multi-tenant management scenarios).
    Each run is a single self-contained session; the script does not disconnect at the
    end so you can continue investigating interactively if desired.

.PARAMETER TenantId
    The target tenant ID or domain to connect to (for delegated/partner admin scenarios).
    Omit for a direct connection to your own tenant.

.PARAMETER UserPrincipalName
    UPN or primary SMTP address of the user who reported the issue.

.PARAMETER GroupAddress
    Primary SMTP address of the Microsoft 365 Group (or DL/shared mailbox) being replied to.

.EXAMPLE
    .\diagnose-m365-group-reply-failure.ps1 -TenantId contoso.onmicrosoft.com -UserPrincipalName jdoe@contoso.com -GroupAddress payroll@contoso.com

.NOTES
    Uses device code authentication (Connect-ExchangeOnline -Device). If you're connecting
    directly to your own tenant, drop the -DelegatedOrganization parameter.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,

    [Parameter(Mandatory = $true)]
    [string]$GroupAddress
)

$ErrorActionPreference = 'Stop'

if ($TenantId) {
    Connect-ExchangeOnline -Device -DelegatedOrganization $TenantId -ShowBanner:$false
} else {
    Connect-ExchangeOnline -Device -ShowBanner:$false
}

Write-Host "`n===== 1. What kind of object is the target address? =====" -ForegroundColor Cyan
# If this returns, it's a Microsoft 365 (Unified) Group, which is the most common trigger
# for silent reply failures in OWA/Outlook.
try {
    Get-UnifiedGroup -Identity $GroupAddress |
        Format-List DisplayName,PrimarySmtpAddress,GroupType,AccessType,
            HiddenFromAddressListsEnabled,AutoSubscribeNewMembers,
            SubscriptionEnabled,WhenCreated,RetentionPolicy
} catch {
    Write-Host "Not a Unified Group. Checking DL / shared mailbox..." -ForegroundColor Yellow
    Get-DistributionGroup -Identity $GroupAddress -ErrorAction SilentlyContinue | Format-List
    Get-Mailbox -Identity $GroupAddress -ErrorAction SilentlyContinue |
        Format-List Name,RecipientTypeDetails,PrimarySmtpAddress
}

Write-Host "`n===== 2. Group membership + owners (is the user a member/owner?) =====" -ForegroundColor Cyan
Get-UnifiedGroupLinks -Identity $GroupAddress -LinkType Members -ErrorAction SilentlyContinue |
    Select-Object DisplayName,PrimarySmtpAddress
Write-Host "--- Owners ---"
Get-UnifiedGroupLinks -Identity $GroupAddress -LinkType Owners -ErrorAction SilentlyContinue |
    Select-Object DisplayName,PrimarySmtpAddress

Write-Host "`n===== 3. User's inbox rules (a rule moving group mail can remove the original mid-draft) =====" -ForegroundColor Cyan
Get-InboxRule -Mailbox $UserPrincipalName |
    Format-List Name,Enabled,Priority,Description

Write-Host "`n===== 4. Retention / MRM on the user's mailbox and on the group =====" -ForegroundColor Cyan
Get-Mailbox -Identity $UserPrincipalName | Format-List Name,RetentionPolicy,LitigationHoldEnabled,ElcProcessingDisabled
Write-Host "--- Group mailbox retention ---"
Get-Mailbox -Identity $GroupAddress -GroupMailbox -ErrorAction SilentlyContinue |
    Format-List Name,RetentionPolicy,LitigationHoldEnabled

Write-Host "`n===== 5. Send-As / Send-on-Behalf on the group (needed to send as the group) =====" -ForegroundColor Cyan
Get-RecipientPermission -Identity $GroupAddress -ErrorAction SilentlyContinue |
    Where-Object { $_.AccessRights -contains 'SendAs' } |
    Select-Object Trustee,AccessRights
Get-UnifiedGroup -Identity $GroupAddress -ErrorAction SilentlyContinue |
    Select-Object DisplayName,@{n='GrantSendOnBehalfTo';e={$_.GrantSendOnBehalfTo -join '; '}}

Write-Host "`nDone. Review section 1 (group type), 3 (inbox rules), 4 (retention) first." -ForegroundColor Green
