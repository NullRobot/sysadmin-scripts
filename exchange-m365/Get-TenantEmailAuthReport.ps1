<#
.SYNOPSIS
    One-shot Exchange Online email-authentication discovery: accepted domains,
    direct-send posture, DKIM state, and the exact DKIM CNAMEs to publish in DNS.

.DESCRIPTION
    The standard first pass on any spoofing / SPF-DKIM-DMARC / mail-delivery case.
    Reports:
      1. Accepted domains (type, default)
      2. Organization config relevant to auth (RejectDirectSend, SendFromAliasEnabled)
      3. DKIM signing config for every domain (enabled, status, key size)
      4. For -Domain (or every non-onmicrosoft domain), the two selector CNAME
         records to publish at the DNS host, ready to paste into a registrar UI
      5. Transport rules that prepend subjects or stamp disclaimers (common cause
         of "external" tagging complaints)

    Read-only. Connects to Exchange Online interactively if not already connected.

.PARAMETER AdminUpn
    Admin UPN to authenticate with.

.PARAMETER Domain
    Optional: limit the DKIM CNAME output to one domain.

.PARAMETER DeviceCode
    Use device-code auth (some tenants' CA policies block it; default is browser).

.EXAMPLE
    .\Get-TenantEmailAuthReport.ps1 -AdminUpn admin@contoso.com -Domain contoso.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$AdminUpn,
    [string]$Domain,
    [switch]$DeviceCode
)

$ErrorActionPreference = 'Stop'

if (-not (Get-ConnectionInformation | Where-Object { $_.UserPrincipalName -eq $AdminUpn -and $_.State -eq 'Connected' })) {
    Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan
    if ($DeviceCode) { Connect-ExchangeOnline -UserPrincipalName $AdminUpn -Device -ShowBanner:$false }
    else             { Connect-ExchangeOnline -UserPrincipalName $AdminUpn -ShowBanner:$false }
}

Write-Host "`n===== Accepted Domains =====" -ForegroundColor Cyan
Get-AcceptedDomain | Select-Object Name, DomainName, DomainType, Default | Format-Table -AutoSize

Write-Host "`n===== Organization Config (Direct Send / Auth) =====" -ForegroundColor Cyan
Get-OrganizationConfig | Select-Object Name, RejectDirectSend, SendFromAliasEnabled, AuditDisabled | Format-List

Write-Host "`n===== DKIM Signing Config (all domains) =====" -ForegroundColor Cyan
Get-DkimSigningConfig | Select-Object Domain, Enabled, Status, KeySize, LastChecked | Format-Table -AutoSize

# --- DKIM CNAMEs to publish ---
$dkimTargets = if ($Domain) {
    @(Get-DkimSigningConfig -Identity $Domain)
} else {
    Get-DkimSigningConfig | Where-Object { $_.Domain -notmatch '\.onmicrosoft\.com$' }
}

foreach ($cfg in $dkimTargets) {
    Write-Host "`n===== DNS records to publish for $($cfg.Domain) =====" -ForegroundColor Green
    Write-Host "Record 1:" -ForegroundColor Yellow
    Write-Host "  Type:  CNAME"
    Write-Host "  Host:  selector1._domainkey"
    Write-Host "  Value: $($cfg.Selector1CNAME)"
    Write-Host "Record 2:" -ForegroundColor Yellow
    Write-Host "  Type:  CNAME"
    Write-Host "  Host:  selector2._domainkey"
    Write-Host "  Value: $($cfg.Selector2CNAME)"
    if (-not $cfg.Enabled) {
        Write-Host "  NOTE: DKIM signing is currently DISABLED for this domain." -ForegroundColor Yellow
        Write-Host "  After the CNAMEs resolve, enable with:" -ForegroundColor Yellow
        Write-Host "    Set-DkimSigningConfig -Identity $($cfg.Domain) -Enabled `$true"
    }
}

Write-Host "`n===== Transport rules with subject prepends / disclaimers =====" -ForegroundColor Cyan
Get-TransportRule | Where-Object { $_.PrependSubject -or $_.ApplyHtmlDisclaimerText } |
    Select-Object Name, State, Priority, PrependSubject, ApplyHtmlDisclaimerLocation | Format-Table -AutoSize -Wrap

Write-Host "`nDiscovery complete. Session left open intentionally." -ForegroundColor Green
