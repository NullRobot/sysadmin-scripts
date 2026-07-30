#Requires -Version 5.1
<#
.SYNOPSIS
    Definitive answer to "what password policy ACTUALLY applies?" - resultant policy per
    account, default domain policy, all PSOs, and every GPO that sets a password length.

.DESCRIPTION
    Password-policy questions ("why did this password get accepted / rejected?", audit
    findings about minimum length) are usually confused by three layers: the Default
    Domain Policy, fine-grained password policies (PSOs), and stray GPOs that LOOK like
    they set policy but are linked where password settings have no effect. Run on a DC
    (elevated) and this reports all of it, read-only:

      1. Resultant password policy PER ACCOUNT (Get-ADUserResultantPasswordPolicy;
         definitive: shows whether a PSO or the domain default wins for each user)
      2. Default Domain Password Policy
      3. Raw domain-object password attributes (cross-check against 2)
      4. Every fine-grained password policy (PSO) with precedence and AppliesTo
      5. EVERY GPO in the domain: whether it sets MinimumPasswordLength, and where it is
         linked (password settings only take effect from GPOs linked at the DOMAIN root
         and winning precedence; this exposes the decoys)
      6. Domain-root GPO link order (what is actually enforced at the domain)

.PARAMETER User
    Accounts to compute resultant policy for (step 1). Default: the built-in
    Administrator only; pass the accounts you care about.

.EXAMPLE
    .\Get-EffectivePasswordPolicy.ps1 -User jsmith,svc-backup,Administrator
#>
[CmdletBinding()]
param(
    [string[]]$User = @('Administrator')
)
$ErrorActionPreference = 'Continue'
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module GroupPolicy -ErrorAction SilentlyContinue

"===== RESULTANT PASSWORD POLICY PER ACCOUNT (definitive: what actually applies to each user) ====="
foreach ($u in $User) {
    try {
        $rp = Get-ADUserResultantPasswordPolicy -Identity $u -ErrorAction Stop
        if ($rp) { "{0,-16} -> PSO '{1}'  MinLen={2}  MaxAge={3}  Complexity={4}" -f $u, $rp.Name, $rp.MinPasswordLength, $rp.MaxPasswordAge, $rp.ComplexityEnabled }
        else     { "{0,-16} -> NO PSO; Default Domain Policy applies" -f $u }
    } catch { "{0,-16} -> lookup error: {1}" -f $u, $_.Exception.Message }
}

"`n===== DEFAULT DOMAIN PASSWORD POLICY ====="
Get-ADDefaultDomainPasswordPolicy | Select-Object MinPasswordLength,ComplexityEnabled,MaxPasswordAge,MinPasswordAge,PasswordHistoryCount,LockoutThreshold,ReversibleEncryptionEnabled | Format-List

"`n===== RAW DOMAIN OBJECT PASSWORD ATTRS (cross-check) ====="
$d = Get-ADDomain
Get-ADObject $d.DistinguishedName -Properties minPwdLength,maxPwdAge,pwdHistoryLength,pwdProperties | Select-Object minPwdLength,maxPwdAge,pwdHistoryLength,pwdProperties | Format-List

"`n===== ALL FINE-GRAINED PASSWORD POLICIES (PSOs) ====="
$psos = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
if ($psos) { foreach ($p in $psos) { "PSO '{0}' Precedence={1} MinLen={2} AppliesTo=[{3}]" -f $p.Name,$p.Precedence,$p.MinPasswordLength,(($p.AppliesTo) -join '; ') } } else { "NONE EXIST" }

"`n===== EVERY GPO: does it set MinimumPasswordLength, and where is it linked? ====="
foreach ($g in (Get-GPO -All | Sort-Object DisplayName)) {
    $xml = Get-GPOReport -Guid $g.Id -ReportType Xml
    $m = [regex]::Match($xml, 'MinimumPasswordLength</Name>\s*<SettingNumber>(\d+)')
    $links = ([regex]::Matches($xml, '<SOMPath>([^<]+)</SOMPath>') | ForEach-Object { $_.Groups[1].Value }) -join '; '
    if ($m.Success) { "*** SETS MinPwdLen={0} *** '{1}'  linkedTo=[{2}]" -f $m.Groups[1].Value, $g.DisplayName, $links }
    else            { "(no pwd-len)  '{0}'  linkedTo=[{1}]" -f $g.DisplayName, $links }
}

"`n===== DOMAIN-ROOT GPO LINKS (what's actually enforced at the domain) ====="
(Get-GPInheritance -Target (Get-ADDomain).DistinguishedName).GpoLinks | Select-Object DisplayName,Enabled,Enforced,Order | Format-Table -Auto

"`n===== DONE ====="
