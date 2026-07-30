<#
.SYNOPSIS
    Fixes the "all my mail goes to Junk, even internal" mailbox problem:
    finds and removes self/own-domain entries from the user's Blocked Senders
    list and resets the server-side Junk Email Rule.

.DESCRIPTION
    A surprisingly common end-user self-inflicted wound: the user (or a
    sync'd mobile app) adds their own address or their own domain to Outlook's
    Blocked Senders, and from then on internal mail lands in Junk with no
    trace in the mail flow logs or quarantine. This script:
      1. Dumps the mailbox's full BlockedSendersAndDomains list
      2. Removes any entry matching the mailbox's own address or the domains
         you specify (typically the org's own domains)
      3. Optionally toggles the junk filter off/on (-ResetJunkRule), which
         rebuilds a corrupted server-side Junk Email Rule
      4. Prints the resulting config for verification
    Requires Exchange Online admin. Have the user restart Outlook after.

.PARAMETER Mailbox
    The affected mailbox (SMTP address).

.PARAMETER OwnDomain
    Domains that must never be in the user's blocked list (your org's own
    domains). Default: the domain of the mailbox address.

.PARAMETER ResetJunkRule
    Also disable and re-enable the junk filter to rebuild the junk rule.

.PARAMETER Device
    Use device-code auth instead of interactive browser auth.

.EXAMPLE
    .\Repair-MailboxJunkSelfBlock.ps1 -Mailbox jsmith@contoso.com -ResetJunkRule
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$Mailbox,
    [string[]]$OwnDomain,
    [switch]$ResetJunkRule,
    [switch]$Device
)

if ($Device) { Connect-ExchangeOnline -Device -ShowBanner:$false }
else { Connect-ExchangeOnline -ShowBanner:$false }

if (-not $OwnDomain) { $OwnDomain = @(($Mailbox -split '@')[1]) }
$pattern = ($OwnDomain + $Mailbox | ForEach-Object { [regex]::Escape($_) }) -join '|'

Write-Host "`n=== CURRENT BLOCKED SENDERS ($Mailbox) ===" -ForegroundColor Cyan
$junk = Get-MailboxJunkEmailConfiguration -Identity $Mailbox
$blocked = @($junk.BlockedSendersAndDomains)
Write-Host "Total blocked entries: $($blocked.Count)"

$selfBlocked = $blocked | Where-Object { $_ -match $pattern }
if ($selfBlocked) {
    Write-Host "FOUND self/own-domain block entries:" -ForegroundColor Yellow
    $selfBlocked | ForEach-Object { Write-Host "  $_" }
    $newBlocked = $blocked | Where-Object { $_ -notmatch $pattern }
    if ($PSCmdlet.ShouldProcess($Mailbox, "Remove $(@($selfBlocked).Count) self-block entries")) {
        Set-MailboxJunkEmailConfiguration -Identity $Mailbox -BlockedSendersAndDomains $newBlocked -ErrorAction Stop
        Write-Host "Removed. New blocked count: $(@($newBlocked).Count)" -ForegroundColor Green
    }
} else {
    Write-Host "No self/own-domain entries found. Full list for review:" -ForegroundColor Yellow
    $blocked | ForEach-Object { Write-Host "  $_" }
}

if ($ResetJunkRule) {
    Write-Host "`n=== RESETTING JUNK EMAIL RULE (toggle off/on) ===" -ForegroundColor Cyan
    if ($PSCmdlet.ShouldProcess($Mailbox, "Toggle junk filter off/on")) {
        Set-MailboxJunkEmailConfiguration -Identity $Mailbox -Enabled $false -ErrorAction Stop
        Write-Host "Disabled." -ForegroundColor Yellow
        Set-MailboxJunkEmailConfiguration -Identity $Mailbox -Enabled $true -ErrorAction Stop
        Write-Host "Re-enabled." -ForegroundColor Green
    }
}

Write-Host "`n=== VERIFY ===" -ForegroundColor Cyan
Get-MailboxJunkEmailConfiguration -Identity $Mailbox |
    Select-Object Enabled, TrustedListsOnly, ContactsTrusted, BlockedSendersAndDomains, TrustedSendersAndDomains | Format-List

Write-Host "Done. Have the user restart Outlook and test." -ForegroundColor Green
Disconnect-ExchangeOnline -Confirm:$false
