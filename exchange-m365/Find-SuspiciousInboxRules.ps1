<#
.SYNOPSIS
    Scans every user mailbox in a Microsoft 365 tenant for inbox-rule patterns
    commonly used to hide mail during a business email compromise (BEC), and
    lists any mailbox-level forwarding.

.DESCRIPTION
    Read-only. This script only reports; it does not change anything.

    It connects to Exchange Online, enumerates all user mailboxes, and checks
    each mailbox's inbox rules for the following patterns:

      - Rules that move mail to a low-visibility folder (RSS Feeds, Junk,
        Archive, Conversation History, Deleted, Notes)
      - Rules that delete incoming mail
      - Rules that mark mail as read and move it
      - Rules that forward or redirect mail
      - Rules with a blank or single-character name (".", "...", etc.)

    It also lists any mailbox with SMTP forwarding or a legacy forwarding
    address configured.

    Flagged rules are printed to the console and exported to a CSV file.

    Note: this catches rules created the normal way (the large majority of
    cases). A rare few can be planted deep enough that they only show up in
    a low-level MAPI inspection tool (e.g. MFCMAPI), which this script does
    not attempt to check.

.PARAMETER OutputPath
    Path to write the CSV of flagged rules. Defaults to inbox-rule-scan.csv
    on the current user's Desktop.

.EXAMPLE
    .\Find-SuspiciousInboxRules.ps1

    Connects to Exchange Online (prompts for sign-in), scans all user
    mailboxes, and writes results to the Desktop.

.EXAMPLE
    .\Find-SuspiciousInboxRules.ps1 -OutputPath C:\Reports\rules.csv

.NOTES
    Requirements:
      - ExchangeOnlineManagement module:
            Install-Module ExchangeOnlineManagement -Scope CurrentUser
      - An account with Global Administrator or Exchange Administrator rights
        in the target tenant (sign in when the browser prompt appears).

    To remove a rule once you've confirmed it's malicious:
        Remove-InboxRule -Mailbox user@yourdomain.com -Identity "RULE NAME"
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path ([Environment]::GetFolderPath('Desktop')) 'inbox-rule-scan.csv')
)

Import-Module ExchangeOnlineManagement -ErrorAction Stop
Connect-ExchangeOnline -ShowBanner:$false          # sign in as a Global/Exchange Admin

$SuspectFolders = @('RSS','RSS Feeds','RSS Subscriptions','Archive','Conversation History','Junk','Deleted','Notes')

$boxes = Get-ExoMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox |
    Select-Object -ExpandProperty PrimarySmtpAddress
Write-Host "Scanning $($boxes.Count) mailboxes for inbox rules..." -ForegroundColor Cyan

$flagged = foreach ($mb in $boxes) {
    try { $rules = Get-InboxRule -Mailbox $mb -ErrorAction Stop } catch { continue }
    foreach ($r in $rules) {
        $sus = $false
        if ($r.DeleteMessage) { $sus = $true }
        if ($r.ForwardTo -or $r.ForwardAsAttachmentTo -or $r.RedirectTo) { $sus = $true }
        if ($r.MarkAsRead -and $r.MoveToFolder) { $sus = $true }
        if ($r.MoveToFolder -and ($SuspectFolders | Where-Object { $r.MoveToFolder -match $_ })) { $sus = $true }
        if ([string]::IsNullOrWhiteSpace($r.Name) -or $r.Name.Trim().Length -le 1) { $sus = $true }
        if ($sus) {
            [pscustomobject]@{
                Mailbox         = $mb
                Rule            = $r.Name
                Enabled         = $r.Enabled
                MoveToFolder    = $r.MoveToFolder
                Delete          = $r.DeleteMessage
                MarkAsRead      = $r.MarkAsRead
                ForwardTo       = ($r.ForwardTo -join ';')
                RedirectTo      = ($r.RedirectTo -join ';')
                FromContains    = ($r.FromAddressContainsWords -join ';')
                SubjectContains = ($r.SubjectContainsWords -join ';')
            }
        }
    }
}

Write-Host "`n===== FLAGGED INBOX RULES =====" -ForegroundColor Yellow
if ($flagged) { $flagged | Format-List } else { Write-Host "None found." -ForegroundColor Green }

Write-Host "`n===== MAILBOXES WITH FORWARDING SET =====" -ForegroundColor Yellow
$fwd = Get-ExoMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox -PropertySets Delivery |
    Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } |
    Select-Object PrimarySmtpAddress, ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward
if ($fwd) { $fwd | Format-List } else { Write-Host "None found." -ForegroundColor Green }

if ($flagged) {
    $flagged | Export-Csv -NoTypeInformation -Path $OutputPath
    Write-Host "`nFlagged rules exported to $OutputPath" -ForegroundColor Cyan
}
