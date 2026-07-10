<#
.SYNOPSIS
    Reports Exchange Online mailbox retention/Managed Folder Assistant (MFA) settings, mailbox sizes, and ELC diagnostic log properties for a user.

.DESCRIPTION
    Pulls a quick snapshot of a mailbox's retention configuration and size for
    troubleshooting retention policy application, litigation hold, or archive
    issues. Reports:
      - Mailbox retention settings (RetentionPolicy, RetentionHoldEnabled,
        ElcProcessingDisabled, LitigationHoldEnabled, ArchiveStatus,
        AutoExpandingArchiveEnabled)
      - Primary mailbox size and item count
      - Archive mailbox size and item count (if an archive exists)
      - ELC (Extensible Logging / Managed Folder Assistant) processing
        properties pulled from the mailbox diagnostic logs

    Note: "MFA" here refers to the Managed Folder Assistant (the Exchange
    background process that applies retention policies), not Multi-Factor
    Authentication.

.PARAMETER User
    The UserPrincipalName, primary SMTP address, or alias of the mailbox to check.

.EXAMPLE
    .\Get-MailboxRetentionAndSizeReport.ps1 -User "user@contoso.com"

.NOTES
    Requires an active Exchange Online PowerShell session (Connect-ExchangeOnline)
    with sufficient permissions to run Get-Mailbox, Get-MailboxStatistics, and
    Export-MailboxDiagnosticLogs against the target mailbox before running this
    script.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$User
)

Write-Host "`nChecking mailbox retention/MFA status for: ${User}" -ForegroundColor Cyan
Write-Host "$('=' * 60)" -ForegroundColor Cyan

# Mailbox settings
Write-Host "`n--- Mailbox Settings ---" -ForegroundColor Yellow
Get-Mailbox -Identity $User | Select-Object DisplayName, PrimarySmtpAddress, `
    RetentionPolicy, RetentionHoldEnabled, ElcProcessingDisabled, `
    LitigationHoldEnabled, ArchiveStatus, AutoExpandingArchiveEnabled | Format-List

# Primary mailbox size
Write-Host "--- Primary Mailbox ---" -ForegroundColor Yellow
Get-MailboxStatistics -Identity $User | Select-Object TotalItemSize, ItemCount | Format-List

# Archive size
Write-Host "--- Archive Mailbox ---" -ForegroundColor Yellow
try {
    Get-MailboxStatistics -Identity $User -Archive -ErrorAction Stop | Select-Object TotalItemSize, ItemCount | Format-List
} catch {
    Write-Host "No archive mailbox or unable to query" -ForegroundColor Red
}

# MFA (Managed Folder Assistant) / retention processing logs
Write-Host "--- MFA Processing Logs ---" -ForegroundColor Yellow
try {
    $logs = Export-MailboxDiagnosticLogs -Identity $User -ExtendedProperties -ErrorAction Stop
    $xml = [xml]$logs.MailboxLog
    $elcProps = $xml.Properties.MailboxTable.Property | Where-Object {
        $_.Name -like "*ELC*" -or $_.Name -like "*Elc*" -or $_.Name -like "*Retention*"
    }
    if ($elcProps) {
        $elcProps | Format-Table Name, Value -AutoSize -Wrap
    } else {
        Write-Host "No ELC/MFA properties found" -ForegroundColor Red
    }
} catch {
    Write-Host "Could not pull diagnostic logs: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Done.`n" -ForegroundColor Cyan
