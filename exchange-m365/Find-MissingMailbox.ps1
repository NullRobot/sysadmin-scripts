<#
.SYNOPSIS
    Finds out what happened to a mailbox that "disappeared" - checks every
    place it could be hiding in Exchange Online and who deleted it.

.DESCRIPTION
    "User X's mailbox is gone" has half a dozen possible truths. This script
    checks them all in one pass:
      1. Active mailbox (with forwarding config, in case it was repurposed)
      2. Soft-deleted mailboxes (recoverable ~30 days)
      3. Inactive mailboxes (on hold after deletion)
      4. MailUser / MailContact (converted rather than deleted)
      5. Any recipient type matching the search string
      6. All shared mailboxes in the tenant (commonly converted-to-shared)
      7. Transport rules and tenant-wide forwarding referencing the name
      8. Unified Audit Log: Remove-/Disable-Mailbox, soft/hard delete, and
         license-change events for the name (last 90 days) - names WHO did it
    Read-only. Requires an Exchange Online admin connection
    (Connect-ExchangeOnline runs in-script; use -Device for headless auth).

.PARAMETER SearchString
    Distinctive fragment of the user's name/alias/address (e.g. "jsmith").

.PARAMETER PrimaryAddress
    The exact expected SMTP address, if known (sharpens checks 1 and 4).

.PARAMETER Device
    Use device-code auth instead of interactive browser auth.

.EXAMPLE
    .\Find-MissingMailbox.ps1 -SearchString smith -PrimaryAddress jsmith@contoso.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SearchString,
    [string]$PrimaryAddress,
    [switch]$Device
)

if ($Device) { Connect-ExchangeOnline -Device -ShowBanner:$false }
else { Connect-ExchangeOnline -ShowBanner:$false }

if (-not $PrimaryAddress) { $PrimaryAddress = $SearchString }

Write-Host "`n=== CHECK 1: Active mailbox ($PrimaryAddress) ==="
$mb = Get-Mailbox -Identity $PrimaryAddress -ErrorAction SilentlyContinue
if ($mb) {
    $mb | Select-Object DisplayName, PrimarySmtpAddress, RecipientTypeDetails, WhenCreated, WhenChanged, IsInactiveMailbox, ForwardingSmtpAddress, DeliverToMailboxAndForward | Format-List
} else {
    Write-Host "NOT FOUND as active mailbox"
}

Write-Host "`n=== CHECK 2: Soft-deleted mailbox ==="
$sd = Get-Mailbox -SoftDeletedMailbox | Where-Object { $_.PrimarySmtpAddress -like "*$SearchString*" -or $_.DisplayName -like "*$SearchString*" -or $_.Alias -like "*$SearchString*" }
if ($sd) {
    $sd | Select-Object DisplayName, PrimarySmtpAddress, RecipientTypeDetails, WhenSoftDeleted, WhenCreated, ExchangeGuid | Format-List
    Write-Host "RECOVERABLE: soft-deleted mailboxes can be restored for ~30 days (Undo-SoftDeletedMailbox)."
} else {
    Write-Host "NOT FOUND in soft-deleted mailboxes"
}

Write-Host "`n=== CHECK 3: Inactive mailbox ==="
$inactive = Get-Mailbox -InactiveMailbox | Where-Object { $_.PrimarySmtpAddress -like "*$SearchString*" -or $_.DisplayName -like "*$SearchString*" }
if ($inactive) {
    $inactive | Select-Object DisplayName, PrimarySmtpAddress, RecipientTypeDetails, WhenSoftDeleted, WhenCreated, InPlaceHolds, LitigationHoldEnabled | Format-List
} else {
    Write-Host "NOT FOUND as inactive mailbox"
}

Write-Host "`n=== CHECK 4: Mail user / mail contact ==="
$mu = Get-MailUser -Identity $PrimaryAddress -ErrorAction SilentlyContinue
if ($mu) { Write-Host "Found as MailUser:"; $mu | Select-Object DisplayName, PrimarySmtpAddress, ExternalEmailAddress | Format-List }
else { Write-Host "NOT FOUND as mail user" }

$mc = Get-MailContact -Filter "DisplayName -like '*$SearchString*'" -ErrorAction SilentlyContinue
if ($mc) { Write-Host "Found as MailContact:"; $mc | Select-Object DisplayName, PrimarySmtpAddress, ExternalEmailAddress | Format-List }
else { Write-Host "NOT FOUND as mail contact" }

Write-Host "`n=== CHECK 5: Any recipient type ==="
Get-Recipient -Filter "PrimarySmtpAddress -like '*$SearchString*' -or DisplayName -like '*$SearchString*'" -ErrorAction SilentlyContinue |
    Select-Object DisplayName, PrimarySmtpAddress, RecipientType, RecipientTypeDetails | Format-Table -AutoSize

Write-Host "`n=== CHECK 6: All shared mailboxes in tenant (converted-to-shared is common) ==="
Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited |
    Select-Object DisplayName, PrimarySmtpAddress, WhenCreated, WhenChanged | Format-Table -AutoSize

Write-Host "`n=== CHECK 7: Transport rules / tenant forwarding referencing '$SearchString' ==="
Get-TransportRule | Where-Object { $_.Description -like "*$SearchString*" -or $_.Name -like "*$SearchString*" } |
    Select-Object Name, State, Description | Format-List
Get-Mailbox -ResultSize Unlimited | Where-Object { $_.ForwardingSmtpAddress -like "*$SearchString*" -or $_.ForwardingAddress -like "*$SearchString*" } |
    Select-Object DisplayName, PrimarySmtpAddress, ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward | Format-Table -AutoSize

Write-Host "`n=== CHECK 8: Unified Audit Log - mailbox removal events (last 90 days) ==="
$startDate = (Get-Date).AddDays(-90)
$endDate = Get-Date
$auditResults = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -Operations "Remove-Mailbox","Disable-Mailbox","Set-Mailbox","SoftDelete","HardDelete" -FreeText $SearchString -ResultSize 25 -ErrorAction SilentlyContinue
if ($auditResults) {
    $auditResults | Select-Object CreationDate, UserIds, Operations, AuditData | Format-List
} else {
    Write-Host "No audit log entries found for '$SearchString' mailbox removal (last 90 days)"
}

Write-Host "`n=== CHECK 9: Audit Log - license changes (unlicensing deletes the mailbox) ==="
$licAudit = Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -Operations "Change user license." -FreeText $SearchString -ResultSize 25 -ErrorAction SilentlyContinue
if ($licAudit) {
    $licAudit | Select-Object CreationDate, UserIds, Operations, AuditData | Format-List
} else {
    Write-Host "No license change audit entries found for '$SearchString' (last 90 days)"
}

Write-Host "`n=== DONE ==="
Disconnect-ExchangeOnline -Confirm:$false
