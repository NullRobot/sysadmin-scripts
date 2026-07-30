<#
.SYNOPSIS
    Add a domain user to the local Remote Desktop Users group on one or more remote servers.
.DESCRIPTION
    Grants RDP access without an interactive session on the target. For each server it opens an
    authenticated SMB session (the auth anchor the WinNT/ADSI call rides), reads the current
    Remote Desktop Users membership, adds the user if not already present, and re-reads to VERIFY.
    Idempotent - re-running on a server where the user is already a member makes no change.
    The admin credential is read from environment variables so no password literal sits in the
    script text (Group Policy script-block logging records the text, never the env value).
.PARAMETER ComputerName
    Target server host name(s).
.PARAMETER UserName
    The account to add (SamAccountName, no domain).
.PARAMETER Domain
    NetBIOS domain of the user (used in the WinNT path, e.g. 'CONTOSO').
.NOTES
    Set $env:ADMIN_USER (DOMAIN\admin) and $env:ADMIN_PW before running:
      ADMIN_USER=DOMAIN\admin ADMIN_PW=... pwsh -File Add-RemoteDesktopUser.ps1 -ComputerName srv1,srv2 -UserName jsmith -Domain CONTOSO
    Requires an account with local-admin rights on the targets. Never hardcode the password.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$ComputerName,
    [Parameter(Mandatory)][string]$UserName,
    [Parameter(Mandatory)][string]$Domain
)

$ErrorActionPreference = 'Continue'
if (-not $env:ADMIN_USER -or -not $env:ADMIN_PW) { throw "Set ADMIN_USER (DOMAIN\admin) and ADMIN_PW environment variables first." }
$cred = New-Object System.Management.Automation.PSCredential($env:ADMIN_USER, (ConvertTo-SecureString $env:ADMIN_PW -AsPlainText -Force))

for ($i = 0; $i -lt $ComputerName.Count; $i++) {
    $t = $ComputerName[$i]
    "=== $t ==="
    $drive = "RDU$i"
    try {
        New-PSDrive -Name $drive -PSProvider FileSystem -Root "\\$t\C$" -Credential $cred -ErrorAction Stop | Out-Null
        "auth anchor to $t OK"
    } catch { "auth anchor to ${t} FAILED: $($_.Exception.Message)"; continue }

    try {
        $grp    = [ADSI]"WinNT://$t/Remote Desktop Users,group"
        $before = @($grp.psbase.Invoke('Members') | ForEach-Object { ([ADSI]$_).InvokeGet('Name') })
        "before: $(if($before.Count){ $before -join ', ' } else { 'EMPTY' })"
        if ($before -contains $UserName) { "already a member, no change made" }
        else { $grp.psbase.Invoke('Add', @("WinNT://$Domain/$UserName,user")); "ADD issued for $Domain\$UserName" }

        $after = @(([ADSI]"WinNT://$t/Remote Desktop Users,group").psbase.Invoke('Members') | ForEach-Object { ([ADSI]$_).InvokeGet('Name') })
        "after:  $(if($after.Count){ $after -join ', ' } else { 'EMPTY' })"
        if ($after -contains $UserName) { "VERIFIED: $UserName is in Remote Desktop Users on $t" }
        else { "NOT VERIFIED: $UserName still absent on $t" }
    } catch {
        "group work FAILED on ${t}: $($_.Exception.Message)"
        if ($_.Exception.InnerException) { "  inner: $($_.Exception.InnerException.Message)" }
    } finally { Remove-PSDrive -Name $drive -Force -ErrorAction SilentlyContinue }
}
