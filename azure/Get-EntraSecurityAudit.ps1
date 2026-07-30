<#
.SYNOPSIS
    Entra ID (Azure AD) security posture audit: Security Defaults, Conditional
    Access, per-user MFA registration, password policy, and licensing.

.DESCRIPTION
    Read-only sweep of a Microsoft 365 tenant's identity security state:
      1. Tenant info and verified domains
      2. Security Defaults enabled/disabled
      3. Every Conditional Access policy with state, grant controls,
         sign-in frequency, and user/app scoping
      4. Per-user MFA registration: what auth methods each enabled member
         user actually has registered, flagging PASSWORD ONLY accounts in red
      5. Domain password expiration policy
      6. License SKUs relevant to CA/MFA entitlement (P1/P2 etc.)
    Uses Microsoft Graph PowerShell with device-code auth so it can run from
    a remote/headless session. Requires delegated scopes: Policy.Read.All,
    User.Read.All, UserAuthenticationMethod.Read.All, Directory.Read.All.

.PARAMETER TenantId
    Tenant ID or a verified domain name of the tenant to audit.

.EXAMPLE
    .\Get-EntraSecurityAudit.ps1 -TenantId contoso.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TenantId
)

# Clear any cached/stale credential before connecting fresh
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}

Connect-MgGraph -Scopes "Policy.Read.All","User.Read.All","UserAuthenticationMethod.Read.All","Directory.Read.All" -UseDeviceCode -TenantId $TenantId -NoWelcome -ErrorAction Stop

$ctx = Get-MgContext
if (-not $ctx) {
    Write-Host "FATAL: Authentication failed. Exiting." -ForegroundColor Red
    exit 1
}
Write-Host "Connected as: $($ctx.Account) to tenant $($ctx.TenantId)" -ForegroundColor Green

Write-Host "`n=== TENANT INFO ===" -ForegroundColor Cyan
$org = Get-MgOrganization
Write-Host "Tenant: $($org.DisplayName)"
Write-Host "Tenant ID: $($org.Id)"
Write-Host "Verified Domains: $(($org.VerifiedDomains | ForEach-Object { $_.Name }) -join ', ')"

Write-Host "`n=== SECURITY DEFAULTS ===" -ForegroundColor Cyan
try {
    $secDefaults = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
    Write-Host "Security Defaults Enabled: $($secDefaults.isEnabled)"
} catch {
    Write-Host "ERROR checking Security Defaults: $_" -ForegroundColor Red
}

Write-Host "`n=== CONDITIONAL ACCESS POLICIES ===" -ForegroundColor Cyan
try {
    $policies = Get-MgIdentityConditionalAccessPolicy -All
    if ($policies.Count -eq 0) {
        Write-Host "NO Conditional Access policies found." -ForegroundColor Yellow
    } else {
        Write-Host "Found $($policies.Count) policies:`n"
        foreach ($p in $policies) {
            Write-Host "Policy: $($p.DisplayName)" -ForegroundColor Green
            Write-Host "  State: $($p.State)"
            Write-Host "  Created: $($p.CreatedDateTime)  Modified: $($p.ModifiedDateTime)"
            if ($p.GrantControls) {
                Write-Host "  Grant Controls: $(($p.GrantControls.BuiltInControls) -join ', ') (Operator: $($p.GrantControls.Operator))"
            }
            if ($p.SessionControls.SignInFrequency) {
                Write-Host "  Sign-In Frequency: $($p.SessionControls.SignInFrequency.Value) $($p.SessionControls.SignInFrequency.Type) (Enabled: $($p.SessionControls.SignInFrequency.IsEnabled))" -ForegroundColor Yellow
            }
            if ($p.Conditions.Users.IncludeUsers) {
                Write-Host "  Include Users: $(($p.Conditions.Users.IncludeUsers) -join ', ')"
            }
            if ($p.Conditions.Users.ExcludeUsers) {
                Write-Host "  Exclude Users: $(($p.Conditions.Users.ExcludeUsers) -join ', ')"
            }
            if ($p.Conditions.Applications.IncludeApplications) {
                Write-Host "  Include Apps: $(($p.Conditions.Applications.IncludeApplications) -join ', ')"
            }
            Write-Host ""
        }
    }
} catch {
    Write-Host "ERROR checking CA policies: $_" -ForegroundColor Red
}

Write-Host "`n=== USER MFA REGISTRATION STATUS ===" -ForegroundColor Cyan
try {
    $users = Get-MgUser -All -Filter "accountEnabled eq true" -Property Id,DisplayName,UserPrincipalName,UserType | Where-Object { $_.UserType -eq 'Member' }
    Write-Host "Found $($users.Count) enabled member users`n"
    foreach ($u in $users) {
        try {
            $methods = Get-MgUserAuthenticationMethod -UserId $u.Id
            $methodTypes = $methods | ForEach-Object { $_.AdditionalProperties.'@odata.type' }
            $hasAuthenticator = $methodTypes -contains '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'
            $hasPhone = $methodTypes -contains '#microsoft.graph.phoneAuthenticationMethod'
            $hasFido = $methodTypes -contains '#microsoft.graph.fido2AuthenticationMethod'
            $hasSoftwareOath = $methodTypes -contains '#microsoft.graph.softwareOathAuthenticationMethod'
            $hasPasswordOnly = ($methods.Count -eq 1) -and ($methodTypes -contains '#microsoft.graph.passwordAuthenticationMethod')

            $status = if ($hasAuthenticator) { "Authenticator App" }
                      elseif ($hasSoftwareOath) { "Software OATH Token" }
                      elseif ($hasPhone) { "Phone/SMS" }
                      elseif ($hasFido) { "FIDO2 Key" }
                      elseif ($hasPasswordOnly) { "PASSWORD ONLY - NO MFA" }
                      else { "Other: $(($methodTypes | Where-Object { $_ -notmatch 'password' }) -join ', ')" }

            $color = if ($hasPasswordOnly) { "Red" } else { "Green" }
            Write-Host "  $($u.DisplayName) ($($u.UserPrincipalName)): $status" -ForegroundColor $color
        } catch {
            Write-Host "  $($u.DisplayName): Error reading auth methods" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "ERROR enumerating users: $_" -ForegroundColor Red
}

Write-Host "`n=== PASSWORD EXPIRATION POLICY ===" -ForegroundColor Cyan
try {
    Get-MgDomain -All | ForEach-Object {
        Write-Host "Domain: $($_.Id) - Password Validity (days): $($_.PasswordValidityPeriodInDays) - Notification (days): $($_.PasswordNotificationWindowInDays)"
    }
} catch {
    Write-Host "ERROR checking password policy: $_" -ForegroundColor Red
}

Write-Host "`n=== LICENSING (Entra P1/P2 check) ===" -ForegroundColor Cyan
try {
    Get-MgSubscribedSku -All | Where-Object { $_.SkuPartNumber -match 'AAD_PREMIUM|ENTRA|EMS|BUSINESS_PREMIUM|E3|E5|BUSINESS_BASIC|EXCHANGE' } | ForEach-Object {
        Write-Host "SKU: $($_.SkuPartNumber) - Consumed: $($_.ConsumedUnits)/$($_.PrepaidUnits.Enabled)"
    }
} catch {
    Write-Host "ERROR checking licenses: $_" -ForegroundColor Red
}

Write-Host "`n=== AUDIT COMPLETE ===" -ForegroundColor Cyan
