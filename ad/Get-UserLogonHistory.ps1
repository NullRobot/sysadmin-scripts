<#
.SYNOPSIS
    Show recent logon sources for an AD account from a DC's Security log.
.DESCRIPTION
    Read-only. Answers "where has this account been logging on from" - useful for a shared/service
    account under investigation, a suspected compromise, or confirming who actually uses an account
    before you disable it. Prints the account's key attributes (enabled, last logon, SPNs = service
    indicator) then parses Security-log 4624 (logon) and 4768 (Kerberos TGT) events for the account,
    showing time, logon type, source IP, and source workstation. Run on a DC (ideally the one the
    account authenticates against).
.PARAMETER SamAccountName
    The account to trace.
.PARAMETER MaxEvents
    Max Security-log events to scan. Default 3000.
.NOTES
    Requires the ActiveDirectory module and rights to read the Security log. Events roll off, so
    this only covers what the log currently retains.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SamAccountName,
    [int]$MaxEvents = 3000
)

$ErrorActionPreference = 'Continue'
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

Write-Output "==================== $SamAccountName ===================="
try {
    $u = Get-ADUser -Identity $SamAccountName -Properties Enabled, whenCreated, LastLogonDate, PasswordLastSet, `
        Description, mail, servicePrincipalName, adminCount -ErrorAction Stop
    $u | Select-Object SamAccountName, Name, Enabled, whenCreated, LastLogonDate, PasswordLastSet, adminCount, Description | Format-List
    $spn = @($u.servicePrincipalName)
    Write-Output ("SPNs (service-account indicator): " + $(if ($spn.Count) { $spn -join '; ' } else { '(none)' }))
} catch { Write-Output "ERROR reading ${SamAccountName}: $($_.Exception.Message)" }

Write-Output "`n=== recent logon sources (4624 logon + 4768 Kerberos TGT, newest first) ==="
try {
    $xp = "*[System[(EventID=4624 or EventID=4768)] and EventData[Data[@Name='TargetUserName'][translate(text(),'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='$($SamAccountName.ToLower())']]]"
    $ev = Get-WinEvent -LogName Security -FilterXPath $xp -MaxEvents 60 -ErrorAction SilentlyContinue
    if (-not $ev) { Write-Output "No 4624/4768 events found (may have rolled out of the log)." }
    else {
        $ev | ForEach-Object {
            $x = [xml]$_.ToXml(); $data = @{}
            foreach ($n in $x.Event.EventData.Data) { $data[$n.Name] = $n.'#text' }
            [pscustomobject]@{
                Time        = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                Id          = $_.Id
                LogonType   = $data['LogonType']
                SrcIP       = $data['IpAddress']
                Workstation = $data['WorkstationName']
            }
        } | Format-Table -AutoSize | Out-String -Width 200
    }
} catch { Write-Output "ERROR querying Security log: $($_.Exception.Message)" }
