<#
.SYNOPSIS
    Report who can RDP into one or more servers (group membership + user rights + policy).
.DESCRIPTION
    Read-only. Answers "why can/can't this person RDP in" by pulling the full picture per server:
      - Remote Desktop Users local group members
      - the SeRemoteInteractiveLogonRight and SeDenyRemoteInteractiveLogonRight user-rights (via
        secedit export - a Deny here silently overrides everything else)
      - fDenyTSConnections (is RDP even enabled on the box)
      - Local Administrators (admins can always RDP regardless of the RDU group)
    Runs the checks remotely via Invoke-Command with a supplied admin credential from env vars, so
    no password literal is in the script text. Changes nothing.
.PARAMETER ComputerName
    Target server host name(s).
.NOTES
    Set $env:ADMIN_USER (DOMAIN\admin) and $env:ADMIN_PW first. Requires WinRM to the targets.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$ComputerName
)

$ErrorActionPreference = 'Continue'
if (-not $env:ADMIN_USER -or -not $env:ADMIN_PW) { throw "Set ADMIN_USER (DOMAIN\admin) and ADMIN_PW environment variables first." }
$cred = New-Object System.Management.Automation.PSCredential($env:ADMIN_USER, (ConvertTo-SecureString $env:ADMIN_PW -AsPlainText -Force))

foreach ($t in $ComputerName) {
    "=== $t : Remote Desktop access ==="
    try {
        Invoke-Command -ComputerName $t -Credential $cred -ScriptBlock {
            $m = try { (Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction Stop).Name } catch { $null }
            "RDUsers members: $(if($m){ $m -join ', ' } else { 'EMPTY' })"
            $f = "$env:TEMP\ur_report.inf"
            secedit /export /cfg $f /areas USER_RIGHTS | Out-Null
            (Select-String -Path $f -Pattern 'SeRemoteInteractiveLogonRight|SeDenyRemoteInteractiveLogonRight').Line
            Remove-Item $f -Force -ErrorAction SilentlyContinue
            $ts = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue
            "fDenyTSConnections=$($ts.fDenyTSConnections)  (1 = RDP disabled)"
            $la = try { (Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop).Name -join ', ' } catch { 'n/a' }
            "Local Administrators (can always RDP): $la"
        } -ErrorAction Stop
    } catch { "  $t query failed: $($_.Exception.Message)" }
}
