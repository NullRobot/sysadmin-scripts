#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only Entra ID diagnostic for a user with lockouts / suspicious sign-ins:
    auth method, 14-day sign-in analysis, Conditional Access policies, named
    locations, and Identity Protection risk state.

.DESCRIPTION
    The standard first pass on "user keeps locking out" or "is this account
    compromised?" when the tenant is cloud or hybrid. Connects with Microsoft Graph
    (interactive browser sign-in) and pulls, read-only:

      1. Directory sync + per-domain auth type (Managed = PHS/PTA, Federated = ADFS).
         With PTA, a cloud password spray locks the ON-PREM account, which is the
         classic "mystery lockout" mechanism.
      2. The target user's core properties (enabled, synced, on-prem DN/sam).
      3. Sign-ins for the last N days (interactive + non-interactive), split
         success/fail, flagging SUCCESSFUL sign-ins from outside the home country
         (compromise signal), grouped by app/client/country/error code, and a full
         CSV export. Error-code legend included (50126 bad pw / spray, 50053
         locked/smart-lockout, 53003 blocked by CA, ...).
      4. Every Conditional Access policy with apps, users/groups, locations, grant
         controls (IDs resolved to display names).
      5. Named locations.
      6. Identity Protection risky-user state (needs Entra ID P2).

    Requires Microsoft.Graph modules and delegated scopes:
    User.Read.All, Group.Read.All, Policy.Read.All, AuditLog.Read.All,
    Directory.Read.All, IdentityRiskyUser.Read.All. Sign-in logs need Entra ID P1.

.PARAMETER UserPrincipalName
    UPN of the user to diagnose.

.PARAMETER TenantId
    Optional tenant GUID/domain (helps when the admin account is multi-tenant).

.PARAMETER Days
    Sign-in lookback window. Default 14.

.PARAMETER HomeCountry
    Two-letter country code treated as "expected". Default US.

.PARAMETER ReportDir
    Output dir for the text report + sign-in CSV. Default C:\temp.

.EXAMPLE
    .\Get-EntraSignInDiagnostics.ps1 -UserPrincipalName jsmith@contoso.com -TenantId contoso.onmicrosoft.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$UserPrincipalName,
    [string]$TenantId,
    [int]$Days = 14,
    [string]$HomeCountry = 'US',
    [string]$ReportDir = 'C:\temp'
)
$ErrorActionPreference = 'Stop'
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not (Test-Path $ReportDir)) { New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null }
$safeName = ($UserPrincipalName -split '@')[0] -replace '[^\w\.\-]','_'
$report  = Join-Path $ReportDir "signin-diag-$safeName-$ts.txt"
$csvPath = Join-Path $ReportDir "signin-diag-$safeName-$ts.csv"

$script:lines = New-Object System.Collections.Generic.List[string]
function Add-Line($s){ $script:lines.Add([string]$s); Write-Host $s }

Add-Line "===================================================================="
Add-Line " Entra sign-in diagnostic for $UserPrincipalName (READ-ONLY)  $ts"
Add-Line "===================================================================="

# ---- Connect (interactive browser; some tenants block device code) ----
$scopes = @('User.Read.All','Group.Read.All','Policy.Read.All','AuditLog.Read.All','Directory.Read.All','IdentityRiskyUser.Read.All')
try {
  if ($TenantId) { Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome }
  else           { Connect-MgGraph -Scopes $scopes -NoWelcome }
} catch {
  Add-Line ("[FATAL] Could not connect to Graph: {0}" -f $_.Exception.Message)
  $script:lines | Out-File -FilePath $report -Encoding utf8
  throw
}
$ctx = Get-MgContext
Add-Line ("Connected as: {0}  | Tenant: {1}" -f $ctx.Account, $ctx.TenantId)

# ---- caches / resolvers ----
$groupCache = @{}
function Resolve-Group($id){
  if ([string]::IsNullOrEmpty($id)) { return $id }
  if ($id -in @('All','None')) { return $id }
  if (-not $groupCache.ContainsKey($id)) {
    try { $g = Get-MgGroup -GroupId $id -Property displayName -ErrorAction Stop; $groupCache[$id] = $g.DisplayName } catch { $groupCache[$id] = $id }
  }
  $groupCache[$id]
}
$userCache = @{}
function Resolve-U($id){
  if ([string]::IsNullOrEmpty($id)) { return $id }
  if ($id -in @('All','None','GuestsOrExternalUsers')) { return $id }
  if (-not $userCache.ContainsKey($id)) {
    try { $u = Get-MgUser -UserId $id -Property userPrincipalName -ErrorAction Stop; $userCache[$id] = $u.UserPrincipalName } catch { $userCache[$id] = $id }
  }
  $userCache[$id]
}
# Well-known first-party app IDs (identical in every tenant)
$appMap = @{
 '797f4846-ba00-4fd7-ba43-dae3f348f5bc' = 'Microsoft Azure Management (Azure CLI/PowerShell/portal/ARM)'
 '00000002-0000-0ff1-ce00-000000000000' = 'Office 365 Exchange Online'
 '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
 '00000003-0000-0ff1-ce00-000000000000' = 'Office 365 SharePoint Online'
 '00000004-0000-0ff1-ce00-000000000000' = 'Skype/Teams (legacy)'
 '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = 'Microsoft Azure CLI'
 '1b730954-1685-4b74-9bfd-dac224a7b894' = 'Azure Active Directory PowerShell (legacy)'
 '1950a258-227b-4e31-a9cf-717495945fc2' = 'Microsoft Azure PowerShell'
 'All'      = 'ALL cloud apps'
 'Office365'= 'Office 365 (suite)'
}
function Resolve-App($id){ if ($appMap.ContainsKey($id)) { "$id ($($appMap[$id]))" } else { $id } }

# ---- Org / sync / auth method ----
Add-Line ""
Add-Line "------ AUTH METHOD / DIRECTORY SYNC ------"
try {
  $org = Get-MgOrganization
  Add-Line ("Org: {0}" -f $org.DisplayName)
  Add-Line ("On-prem sync enabled: {0}" -f $org.OnPremisesSyncEnabled)
} catch { Add-Line ("  [!] Org read failed: {0}" -f $_.Exception.Message) }
try {
  $domains = Get-MgDomain
  Add-Line "Domains (Managed = Password Hash Sync OR Pass-Through Auth; Federated = ADFS):"
  foreach ($d in $domains) { Add-Line ("  - {0}: {1}{2}" -f $d.Id, $d.AuthenticationType, $(if ($d.IsDefault){' (default)'}else{''})) }
} catch { Add-Line ("  [!] Domain read failed: {0}" -f $_.Exception.Message) }
Add-Line "NOTE: If lockouts are on-prem AD, confirm PHS vs PTA on the AD Connect server. PTA"
Add-Line "      validates cloud sign-ins against on-prem AD, so a cloud spray can lock the on-prem account."

# ---- The user ----
Add-Line ""
Add-Line "------ TARGET USER ------"
$user = $null
$uProps = 'id,displayName,userPrincipalName,accountEnabled,onPremisesSyncEnabled,onPremisesDistinguishedName,onPremisesSamAccountName,createdDateTime'
try { $user = Get-MgUser -UserId $UserPrincipalName -Property $uProps } catch { Add-Line ("  [!] User lookup failed: {0}" -f $_.Exception.Message) }
if ($user) {
  Add-Line ("DisplayName : {0}" -f $user.DisplayName)
  Add-Line ("UPN         : {0}" -f $user.UserPrincipalName)
  Add-Line ("Id          : {0}" -f $user.Id)
  Add-Line ("Enabled     : {0}" -f $user.AccountEnabled)
  Add-Line ("Synced      : {0}" -f $user.OnPremisesSyncEnabled)
  Add-Line ("SamAccount  : {0}" -f $user.OnPremisesSamAccountName)
  Add-Line ("On-prem DN  : {0}" -f $user.OnPremisesDistinguishedName)
} else {
  Add-Line "  [!] Could not resolve the user. Sign-in section will be skipped."
}

# ---- Sign-in activity ----
Add-Line ""
Add-Line ("------ SIGN-IN ACTIVITY (last {0} days) ------" -f $Days)
$since = (Get-Date).AddDays(-$Days).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$signins = @()
if ($user) {
  foreach ($evt in @('interactiveUser','nonInteractiveUser')) {
    try {
      $f = "userId eq '$($user.Id)' and createdDateTime ge $since and signInEventTypes/any(t: t eq '$evt')"
      $part = Get-MgAuditLogSignIn -Filter $f -Top 1000 -ErrorAction Stop
      Add-Line ("  pulled {0} {1} sign-ins" -f ($part | Measure-Object).Count, $evt)
      if ($part) { $signins += $part }
    } catch { Add-Line ("  [!] {0} sign-in pull failed: {1}" -f $evt, $_.Exception.Message) }
  }
  if ($signins.Count -eq 0) {
    try {
      $signins = Get-MgAuditLogSignIn -Filter "userId eq '$($user.Id)'" -Top 500 -ErrorAction Stop
      Add-Line ("  fallback pull: {0}" -f ($signins | Measure-Object).Count)
    } catch { Add-Line ("  [!] fallback sign-in pull failed: {0}" -f $_.Exception.Message) }
  }
}
if ($signins.Count) {
  $success = @($signins | Where-Object { $_.Status.ErrorCode -eq 0 })
  $failed  = @($signins | Where-Object { $_.Status.ErrorCode -ne 0 })
  $foreignSuccess = @($success | Where-Object { $_.Location.CountryOrRegion -and $_.Location.CountryOrRegion -ne $HomeCountry })
  Add-Line ("Total records: {0}  |  Successful: {1}  |  Failed: {2}" -f $signins.Count, $success.Count, $failed.Count)
  if ($foreignSuccess.Count) {
    Add-Line ""
    Add-Line ("  *** CRITICAL: SUCCESSFUL sign-ins from OUTSIDE {0} (possible compromise) ***" -f $HomeCountry)
    foreach ($s in ($foreignSuccess | Sort-Object CreatedDateTime -Descending | Select-Object -First 25)) {
      Add-Line ("    {0}  SUCCESS  {1}/{2}  app={3}  client={4}  IP={5}" -f $s.CreatedDateTime, $s.Location.CountryOrRegion, $s.Location.City, $s.AppDisplayName, $s.ClientAppUsed, $s.IpAddress)
    }
  } else {
    Add-Line ("  No successful sign-ins from outside {0} in the window (consistent with failed spray, not compromise)." -f $HomeCountry)
  }
  Add-Line ""
  Add-Line "  Grouped: App | Client | Country | ErrorCode | Result  (count):"
  $grp = $signins | Group-Object { "{0} | {1} | {2} | {3} | {4}" -f $_.AppDisplayName, $_.ClientAppUsed, $_.Location.CountryOrRegion, $_.Status.ErrorCode, $(if ($_.Status.ErrorCode -eq 0){'SUCCESS'}else{'fail'}) } | Sort-Object Count -Descending
  foreach ($g in $grp) { Add-Line ("    {0,5}x  {1}" -f $g.Count, $g.Name) }
  Add-Line ""
  Add-Line "  Error code legend: 0=success, 50126=bad password (spray), 50053=account locked / smart-lockout,"
  Add-Line "    50055=password expired, 50074=MFA required, 53003=blocked by Conditional Access,"
  Add-Line "    50034=user not found, 700016=app not found in directory."
  try {
    $signins | Select-Object CreatedDateTime, AppDisplayName, ClientAppUsed, IpAddress,
      @{n='Country';e={$_.Location.CountryOrRegion}}, @{n='City';e={$_.Location.City}},
      @{n='ErrorCode';e={$_.Status.ErrorCode}}, @{n='Failure';e={$_.Status.FailureReason}},
      ConditionalAccessStatus, IsInteractive |
      Sort-Object CreatedDateTime -Descending | Export-Csv -Path $csvPath -NoTypeInformation
    Add-Line ("  Full sign-in detail -> {0}" -f $csvPath)
  } catch { Add-Line ("  [!] CSV export failed: {0}" -f $_.Exception.Message) }
} else {
  Add-Line "  No sign-in records returned (check that the user resolved and the tenant has Entra ID P1)."
}

# ---- Conditional Access policies ----
Add-Line ""
Add-Line "------ CONDITIONAL ACCESS POLICIES ------"
try {
  $locs = @{}
  try { Get-MgIdentityConditionalAccessNamedLocation -All | ForEach-Object { $locs[$_.Id] = $_.DisplayName } } catch {}
  function Resolve-Loc($id){ if ($id -eq 'All'){'All locations'} elseif ($id -eq 'AllTrusted'){'All trusted'} elseif ($locs.ContainsKey($id)){ $locs[$id] } else { $id } }
  $caps = Get-MgIdentityConditionalAccessPolicy -All
  Add-Line ("Total CA policies: {0}" -f ($caps | Measure-Object).Count)
  foreach ($p in $caps) {
    Add-Line ""
    Add-Line ("  [{0}] {1}" -f $p.State, $p.DisplayName)
    $incApps = $p.Conditions.Applications.IncludeApplications
    $excApps = $p.Conditions.Applications.ExcludeApplications
    Add-Line ("     Include apps : {0}" -f (($incApps | ForEach-Object { Resolve-App $_ }) -join '; '))
    if ($excApps) { Add-Line ("     Exclude apps : {0}" -f (($excApps | ForEach-Object { Resolve-App $_ }) -join '; ')) }
    Add-Line ("     Client types : {0}" -f (($p.Conditions.ClientAppTypes) -join ', '))
    $incU = $p.Conditions.Users.IncludeUsers; $incG = $p.Conditions.Users.IncludeGroups
    $excU = $p.Conditions.Users.ExcludeUsers; $excG = $p.Conditions.Users.ExcludeGroups
    Add-Line ("     Incl users : [{0}]  groups : [{1}]" -f (($incU | ForEach-Object { Resolve-U $_ }) -join ', '), (($incG | ForEach-Object { Resolve-Group $_ }) -join ', '))
    if ($excU -or $excG) { Add-Line ("     Excl users : [{0}]  groups : [{1}]" -f (($excU | ForEach-Object { Resolve-U $_ }) -join ', '), (($excG | ForEach-Object { Resolve-Group $_ }) -join ', ')) }
    $incL = $p.Conditions.Locations.IncludeLocations; $excL = $p.Conditions.Locations.ExcludeLocations
    if ($incL -or $excL) { Add-Line ("     Locations : include=[{0}] exclude=[{1}]" -f (($incL | ForEach-Object { Resolve-Loc $_ }) -join '; '), (($excL | ForEach-Object { Resolve-Loc $_ }) -join '; ')) }
    Add-Line ("     Grant : operator={0} controls=[{1}]" -f $p.GrantControls.Operator, ($p.GrantControls.BuiltInControls -join ', '))
  }
} catch { Add-Line ("  [!] CA policy read failed: {0}" -f $_.Exception.Message) }

# ---- Named locations ----
Add-Line ""
Add-Line "------ NAMED LOCATIONS ------"
try {
  $nl = Get-MgIdentityConditionalAccessNamedLocation -All
  foreach ($l in $nl) {
    $detail = ''
    if ($l.AdditionalProperties.countriesAndRegions) { $detail = "countries: " + (($l.AdditionalProperties.countriesAndRegions) -join ', ') }
    elseif ($l.AdditionalProperties.ipRanges) { $detail = "IP ranges: " + (($l.AdditionalProperties.ipRanges | ForEach-Object { $_.cidrAddress }) -join ', ') }
    Add-Line ("  - {0}  ({1})" -f $l.DisplayName, $detail)
  }
} catch { Add-Line ("  [!] Named location read failed: {0}" -f $_.Exception.Message) }

# ---- Risk state ----
Add-Line ""
Add-Line "------ IDENTITY PROTECTION RISK (if licensed) ------"
if ($user) {
  try {
    $ru = Get-MgRiskyUser -Filter "id eq '$($user.Id)'" -ErrorAction Stop
    if ($ru) { Add-Line ("  RiskLevel={0}  RiskState={1}  LastUpdated={2}" -f $ru.RiskLevel, $ru.RiskState, $ru.RiskLastUpdatedDateTime) }
    else { Add-Line "  Not in the risky-users list (good)." }
  } catch { Add-Line ("  [!] Risky-user read failed (may need Entra ID P2): {0}" -f $_.Exception.Message) }
}

Add-Line ""
Add-Line "===================================================================="
Add-Line " DONE."
Add-Line ("  Report : {0}" -f $report)
if (Test-Path $csvPath) { Add-Line ("  CSV    : {0}" -f $csvPath) }
Add-Line "===================================================================="
$script:lines | Out-File -FilePath $report -Encoding utf8
Write-Host ""
Write-Host ("REPORT WRITTEN: {0}" -f $report)
