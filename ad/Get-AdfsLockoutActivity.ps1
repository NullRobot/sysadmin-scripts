<#
.SYNOPSIS
    Investigates an AD FS server's role in a user's account lockouts: account
    activity, AD FS Admin log events, local Security log auth failures, and
    the configured relying parties.

.DESCRIPTION
    When Find-AccountLockoutSource points at an AD FS server as the machine
    sending bad passwords to the DCs, the actual culprit (which app/device is
    replaying the stale credential) lives in AD FS's own logs. Run ON the
    AD FS server. Collects, for the target user:
      1. Get-AdfsAccountActivity - AD FS's own bad-password/lockout counters
         and the familiar/unfamiliar locations (Extranet Smart Lockout data)
      2. Available AD FS event logs and their record counts
      3. AD FS/Admin log entries mentioning the user (1203 = bad credential,
         411 = token validation failure, 342/364 = auth failures)
      4. Local Security log 4624/4625/4648 for the user (XPath-filtered,
         last 7 days) with logon type, process, workstation, and IP - this
         reveals whether the bad auth arrives via WAP/proxy or directly
      5. The relying party trust list (candidate apps replaying the cred)
    Read-only. Output as objects; optionally saves JSON.

.PARAMETER UserName
    The user under investigation. Give both formats if unsure
    (e.g. 'j.smith@contoso.com' for activity, 'J.Smith' for event matching).

.PARAMETER SamAccountName
    The short account name for Security-log matching. Default: the part of
    UserName before '@'.

.PARAMETER OutJson
    Optional path to write the full result as JSON.

.EXAMPLE
    .\Get-AdfsLockoutActivity.ps1 -UserName j.smith@contoso.com -OutJson C:\Temp\adfs-jsmith.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$UserName,
    [string]$SamAccountName,
    [string]$OutJson
)

if (-not $SamAccountName) { $SamAccountName = ($UserName -split '@')[0] }
$out = [ordered]@{ hostname = $env:COMPUTERNAME; user = $UserName }

# 1. ADFS Account Activity (Extranet Smart Lockout state)
try {
    Import-Module ADFS -ErrorAction Stop
    $out.account_activity = Get-ADFSAccountActivity -Identifier $UserName -ErrorAction Stop
} catch { $out.account_activity_err = $_.Exception.Message }

# 2. Available AD FS log names
try {
    $out.adfs_logs = Get-WinEvent -ListLog 'AD FS*' -ErrorAction SilentlyContinue |
        Select-Object LogName, RecordCount, IsEnabled
} catch {}

# 3. AD FS Admin log - recent events for the user
try {
    $namePattern = [regex]::Escape($SamAccountName)
    $admin = Get-WinEvent -LogName 'AD FS/Admin' -MaxEvents 500 -ErrorAction Stop |
        Where-Object { $_.Message -imatch $namePattern }
    $out.admin_events = $admin | ForEach-Object {
        [pscustomobject]@{
            Time  = $_.TimeCreated.ToUniversalTime().ToString('s') + 'Z'
            Id    = $_.Id
            Level = $_.LevelDisplayName
            Msg   = ($_.Message -replace "`r?`n", ' | ').Substring(0, [Math]::Min(400, $_.Message.Length))
        }
    }
} catch { $out.admin_err = $_.Exception.Message }

# 4. Local Security log - ADFS-mediated auth failures for the user (last 7 days)
try {
    $xpath = "*[System[(EventID=4624 or EventID=4625 or EventID=4648) and TimeCreated[timediff(@SystemTime) <= 604800000]] and EventData[Data[@Name='TargetUserName']='$SamAccountName']]"
    $sec = Get-WinEvent -LogName Security -FilterXPath $xpath -MaxEvents 200 -ErrorAction Stop
    $out.local_security = $sec | ForEach-Object {
        $x = [xml]$_.ToXml(); $d = @{}
        foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
        [pscustomobject]@{
            Time = $_.TimeCreated.ToUniversalTime().ToString('s') + 'Z'
            Id = $_.Id
            LogonType = $d['LogonType']; AuthPackage = $d['AuthenticationPackageName']
            LogonProcess = $d['LogonProcessName']; ProcessName = $d['ProcessName']
            Workstation = $d['WorkstationName']; IP = $d['IpAddress']
            Status = $d['Status']; SubStatus = $d['SubStatus']
        }
    }
} catch { $out.local_sec_err = $_.Exception.Message }

# 5. Relying party trusts - candidate applications replaying the credential
try {
    $out.relying_parties = Get-AdfsRelyingPartyTrust -ErrorAction Stop |
        Select-Object Name, Identifier, Enabled
} catch { $out.rp_err = $_.Exception.Message }

$result = [pscustomobject]$out
$result

if ($OutJson) {
    $result | ConvertTo-Json -Depth 10 | Set-Content $OutJson -Encoding UTF8
    Write-Host "Wrote $OutJson"
}
