<#
.SYNOPSIS
    Diagnose Direct Send domain-spoofing exposure in Exchange Online before blocking it.
.DESCRIPTION
    Read-only. When someone reports spoofed internal email (a message that appears to come from your
    own domain but never hit your spam filter), the usual cause is Direct Send - mail injected
    straight into the M365 tenant's smtp endpoint, skipping any inbound gateway. The fix is to enable
    RejectDirectSend, but that can also break LEGITIMATE unauthenticated senders (an MFP scan-to-email,
    a line-of-business app). This script checks before you flip the switch: current RejectDirectSend
    and DKIM state, inbox rules on the affected mailboxes (compromise check), and a message trace that
    groups domain-to-domain mail by source IP so you can tell the office/SaaS IPs that WOULD break from
    the random attacker IPs that are safe to block. Changes nothing.
.PARAMETER Domain
    The customer's primary domain (e.g. contoso.com).
.PARAMETER Mailboxes
    Mailbox local-parts or addresses to check inbox rules on (compromise check). Optional.
.PARAMETER ScanAddress
    The scan-to-email / MFP sender to trace (e.g. scan@contoso.com). Optional.
.PARAMETER Days
    Message-trace look-back window. Default 10.
.NOTES
    Connect first: Connect-ExchangeOnline. Requires View-Only Recipients / message-trace rights.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Domain,
    [string[]]$Mailboxes = @(),
    [string]$ScanAddress,
    [int]$Days = 10
)

$ErrorActionPreference = 'SilentlyContinue'

Write-Host "`n===== RejectDirectSend (current) =====" -ForegroundColor Cyan
Get-OrganizationConfig | Format-List Name, RejectDirectSend

Write-Host "`n===== DKIM =====" -ForegroundColor Cyan
Get-DkimSigningConfig | Format-Table Domain, Enabled, Status -Auto

if ($Mailboxes.Count) {
    Write-Host "`n===== Inbox rules (compromise check) =====" -ForegroundColor Cyan
    foreach ($u in $Mailboxes) {
        $mb = if ($u -like '*@*') { $u } else { "$u@$Domain" }
        Write-Host "--- $mb ---"
        Get-InboxRule -Mailbox $mb | Format-Table Name, Enabled, RedirectTo, ForwardTo, MoveToFolder, DeleteMessage -Auto
    }
}

$start = (Get-Date).AddDays(-$Days); $end = Get-Date

if ($ScanAddress) {
    Write-Host "`n===== $ScanAddress sends (MFP scan-to-email), last $Days d =====" -ForegroundColor Cyan
    Get-MessageTrace -SenderAddress $ScanAddress -StartDate $start -EndDate $end |
        Format-Table Received, FromIP, RecipientAddress, Status -Auto
}

Write-Host "`n===== Who is submitting AS the domain, grouped by source IP =====" -ForegroundColor Cyan
Write-Host "An office/SaaS IP with real senders = legit Direct Send (would break); random/bad IPs = the spoof (safe to block)."
$msgs = Get-MessageTrace -StartDate $start -EndDate $end -PageSize 5000 |
    Where-Object { $_.SenderAddress -like "*@$Domain" -and $_.RecipientAddress -like "*@$Domain" }
$msgs | Group-Object FromIP | Sort-Object Count -Descending |
    Select-Object Count, Name, @{n='Senders';e={ ($_.Group.SenderAddress | Select-Object -Unique) -join ', ' }} |
    Format-Table -Auto -Wrap
Write-Host ("domain-to-domain messages pulled: {0} (if =5000, list was capped)" -f $msgs.Count)
Write-Host "`n===== DONE - no changes made =====" -ForegroundColor Green
