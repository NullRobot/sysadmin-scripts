<#
.SYNOPSIS
    Revokes all active sign-in sessions (refresh tokens) for a Microsoft 365 / Entra ID user.

.DESCRIPTION
    Connects to Microsoft Graph and revokes all refresh tokens for the specified user,
    forcing re-authentication everywhere the account is currently signed in. This is a
    common containment step after a compromised-account incident, run immediately after
    resetting the user's password and/or MFA, to kill off any attacker session/refresh
    token that survived the credential reset.

.PARAMETER TenantId
    The Entra ID (Azure AD) tenant ID (GUID) or verified domain of the target tenant.

.PARAMETER UserPrincipalName
    The UPN (email address) of the user whose sessions should be revoked.

.EXAMPLE
    .\Revoke-UserSignInSessions.ps1 -TenantId 'contoso.onmicrosoft.com' -UserPrincipalName 'jdoe@contoso.com'

.NOTES
    Requires the Microsoft.Graph.Authentication module and an account with the
    User.RevokeSessions.All and User.Read.All Graph scopes (e.g. Global Administrator,
    Privileged Authentication Administrator, or a custom role with those permissions).
    Uses device code authentication so it can be run from any machine, including one
    without a browser readily available.

    Revoking sessions invalidates refresh tokens but does not immediately kill existing
    access tokens (which remain valid until they expire, typically up to ~1 hour).
    For full containment also consider disabling the account and reviewing sign-in logs
    for other indicators of compromise.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName
)

Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Connect-MgGraph -TenantId $TenantId -Scopes "User.RevokeSessions.All","User.Read.All" -UseDeviceCode -NoWelcome

$ctx = Get-MgContext
Write-Host "Connected to tenant: $($ctx.TenantId) as $($ctx.Account)" -ForegroundColor Cyan

$u = Get-MgUser -UserId $UserPrincipalName -Property Id,DisplayName,UserPrincipalName,AccountEnabled
Write-Host "Target: $($u.DisplayName)  <$($u.UserPrincipalName)>  Enabled=$($u.AccountEnabled)" -ForegroundColor Cyan

Write-Host "`nRevoking all sign-in sessions..." -ForegroundColor Yellow
$res = Revoke-MgUserSignInSession -UserId $u.Id
if ($res.Value -eq $true) { Write-Host "SUCCESS - all refresh tokens/sessions revoked. User must re-sign-in everywhere." -ForegroundColor Green }
else { Write-Host "Revoke returned: $($res.Value)" -ForegroundColor Red }
