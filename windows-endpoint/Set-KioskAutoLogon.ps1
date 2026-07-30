<#
.SYNOPSIS
    Configures (or repairs) Windows automatic logon for a kiosk / signage /
    shared-display machine, defeating the Windows 11 features that silently
    turn auto-logon back off.

.DESCRIPTION
    Auto-logon that "worked until the last reboot/update" is almost always one
    of three killers, all of which this script handles:
      1. DevicePasswordLessBuildVersion = 2 (Windows 11 passwordless mode)
         resets AutoAdminLogon to 0 on reboot -> set to 0
      2. AutoLogonCount counts DOWN each boot and kills auto-logon at 0
         -> removed
      3. LimitBlankPasswordUse = 1 rejects blank-password console logon
         -> set to 0 only when the account password is blank
    Then (re)writes the classic Winlogon values: AutoAdminLogon,
    DefaultUserName, DefaultDomainName, DefaultPassword. Verifies everything
    it wrote. Run as SYSTEM (RMM) or admin. Reboot to test.

    SECURITY: DefaultPassword is stored in CLEARTEXT in the registry -
    only use this on locked-down kiosk accounts with no real privileges.
    (Sysinternals Autologon encrypts it as an LSA secret if that matters.)

.PARAMETER UserName
    The auto-logon account (e.g. a local kiosk account).

.PARAMETER Password
    The account's password. Default: empty string (blank-password local
    account; the script then also relaxes LimitBlankPasswordUse).

.PARAMETER DomainName
    Logon domain. Default: the computer name (local account).

.EXAMPLE
    .\Set-KioskAutoLogon.ps1 -UserName KioskUser
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$UserName,
    [string]$Password = '',
    [string]$DomainName = $env:COMPUTERNAME
)

$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Write-Output "=== Configure Auto-Logon on $env:COMPUTERNAME for $DomainName\$UserName ==="

if (-not $PSCmdlet.ShouldProcess("$DomainName\$UserName", "Enable auto-logon (cleartext password in registry)")) { return }

# Step 1: Disable the Windows 11 Passwordless feature (resets AutoAdminLogon to 0 on reboot)
Set-ItemProperty -Path $winlogon -Name 'DevicePasswordLessBuildVersion' -Value 0 -Type DWord -Force
Write-Output "  DevicePasswordLessBuildVersion set to 0"

# Step 2: Blank-password accounts need LimitBlankPasswordUse=0 or console auto-logon fails
if ($Password -eq '') {
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Set-ItemProperty -Path $lsaPath -Name 'LimitBlankPasswordUse' -Value 0 -Type DWord -Force
    Write-Output "  LimitBlankPasswordUse set to 0 (blank-password account)"
}

# Step 3: Apply the auto-logon registry values
Set-ItemProperty -Path $winlogon -Name 'AutoAdminLogon'    -Value '1'         -Type String -Force
Set-ItemProperty -Path $winlogon -Name 'DefaultUserName'   -Value $UserName   -Type String -Force
Set-ItemProperty -Path $winlogon -Name 'DefaultDomainName' -Value $DomainName -Type String -Force
Set-ItemProperty -Path $winlogon -Name 'DefaultPassword'   -Value $Password   -Type String -Force
Write-Output "  Winlogon auto-logon values written"

# Step 4: Remove AutoLogonCount (counts down and disables auto-logon when it hits 0)
Remove-ItemProperty -Path $winlogon -Name 'AutoLogonCount' -ErrorAction SilentlyContinue
Write-Output "  AutoLogonCount removed"

# Verify
Write-Output ""
Write-Output "--- Verification ---"
foreach ($key in @('AutoAdminLogon','DefaultUserName','DefaultDomainName','DevicePasswordLessBuildVersion')) {
    $val = (Get-ItemProperty -Path $winlogon -Name $key -ErrorAction SilentlyContinue).$key
    if ($null -eq $val) {
        Write-Output "  $key : (not set) <-- PROBLEM"
    } else {
        Write-Output "  $key : '$val'"
    }
}
$acct = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
if ($acct) {
    Write-Output "  Local account: Enabled=$($acct.Enabled) PasswordRequired=$($acct.PasswordRequired)"
} else {
    Write-Output "  NOTE: '$UserName' is not a local account on this machine (domain account or typo?)"
}

Write-Output ""
Write-Output "=== Done. Reboot required to test auto-logon. ==="
