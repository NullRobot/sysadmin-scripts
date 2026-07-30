#Requires -Version 5.1
<#
.SYNOPSIS
    Explains WHY a user's GPO-mapped drives are or are not working, from SYSTEM
    context on the endpoint (RMM-pushable), and can repoint desktop shortcuts that
    still target a retired file server.

.DESCRIPTION
    Built for file-server migrations and "my drives are gone" tickets. Read-only by
    default; remediation is opt-in:
        -FixShortcuts    rewrite desktop .lnk files pointing at -OldServer to -NewServer
        -ForceGpUpdate   gpupdate /force before the GPO check (does NOT rebuild the
                         user's logon token - group changes still need a re-logon)

    SYSTEM-context reality (the part naive scripts get wrong): SYSTEM is not the
    user, so it cannot see the user's live mapped drives or use $env:USERPROFILE.
    This script resolves the interactive user (Win32_ComputerSystem, falling back to
    explorer.exe's owner), reads their persistent mappings from HKU\<SID>\Network,
    and uses `gpresult /user` to see how Group Policy actually resolved for them.

    Checks, in order:
      A. Machine + interactive user context (SID, profile path)
      B. Connectivity: DNS + SMB 445 to the new server; whether the OLD server is
         still reachable (stale maps that still "work" mask a cutover)
      C. Group Policy result for the user: is the drive-map GPO Applied or DENIED
         (security filtering)? Is the user's CURRENT token in the filter group?
         The classic cause is the user missing from the GPO filter group; fixing
         that requires a DC change plus a fresh LOGON (gpupdate cannot rebuild a token).
      D. The user's persistent drive mappings from their hive, flagged old/new/other
      E. Desktop shortcuts (user + Public) still pointing at the old server
      F. One prioritized diagnosis with the exact next step

.PARAMETER GpoName
    Display name of the drive-map GPO to look for in gpresult.

.PARAMETER FilterGroup
    Security-filtering group the user must be in for the GPO to apply (optional but
    enables the most valuable check).

.PARAMETER NewServer
    FQDN of the NEW file server.

.PARAMETER OldServer
    Hostname of the OLD/retired file server.

.PARAMETER FixShortcuts
    Rewrite desktop shortcuts from the old server to the new one.

.PARAMETER ForceGpUpdate
    Run gpupdate /force before evaluating.

.EXAMPLE
    .\Diagnose-GpoDriveMaps.ps1 -GpoName 'Mapped Drives' -FilterGroup 'Drive Map Users' `
        -NewServer newfs.corp.example.com -OldServer OLDFS
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$GpoName,
    [string]$FilterGroup,
    [Parameter(Mandatory)][string]$NewServer,
    [Parameter(Mandatory)][string]$OldServer,
    [switch]$FixShortcuts,
    [switch]$ForceGpUpdate
)

$ErrorActionPreference = 'Continue'
$NewServerShort = ($NewServer -split '\.')[0]

# ---------- console helpers ----------
function Write-Pass    { param([string]$m) Write-Host "[ OK  ] $m" -ForegroundColor Green }
function Write-Fail    { param([string]$m) Write-Host "[FAIL ] $m" -ForegroundColor Red }
function Write-Info    { param([string]$m) Write-Host "[INFO ] $m" -ForegroundColor Cyan }
function Write-Review  { param([string]$m) Write-Host "[CHECK] $m" -ForegroundColor Yellow }
function Write-Section { param([string]$t) Write-Host ''; Write-Host ("===== $t =====") -ForegroundColor White }

$findings = New-Object System.Collections.Generic.List[string]
function Add-Finding { param([string]$f) $findings.Add($f) }

Write-Host ''
Write-Host "===============  DRIVE-MAP DIAGNOSTIC  (run as: $(whoami))  ===============" -ForegroundColor Cyan

# ====================  A. MACHINE + USER CONTEXT  ====================
Write-Section 'A. MACHINE AND USER'

$cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$machineName = $env:COMPUTERNAME
Write-Info "Machine: $machineName    Joined domain: $($cs.Domain)    DomainJoined: $([bool]$cs.PartOfDomain)"

# Logged-in user. SYSTEM is not the user, so resolve the interactive user explicitly.
$loggedUser = $null
if ($cs -and $cs.UserName) { $loggedUser = $cs.UserName }
if (-not $loggedUser) {
    # Fallback: owner of explorer.exe (the interactive shell).
    try {
        $exp = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop | Select-Object -First 1
        if ($exp) {
            $o = Invoke-CimMethod -InputObject $exp -MethodName GetOwner -ErrorAction Stop
            if ($o.User) { $loggedUser = "$($o.Domain)\$($o.User)" }
        }
    } catch { }
}

if (-not $loggedUser) {
    Write-Fail "No interactive user is logged in right now. Drive maps only build at user logon, so run this while the user is signed in."
    Add-Finding "No interactive user detected. Have the user log in, then re-run."
    $userSid = $null; $userProfile = $null
}
else {
    Write-Pass "Logged-in user: $loggedUser"
    if ($loggedUser -match '\\') { $userDomain, $userName = $loggedUser -split '\\', 2 } else { $userDomain = $machineName; $userName = $loggedUser }

    # SID + profile path (NEVER $env:USERPROFILE here; that is SYSTEM's profile).
    $userSid = $null; $userProfile = $null
    try { $userSid = (New-Object System.Security.Principal.NTAccount($userDomain, $userName)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { }
    $prof = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.SID -eq $userSid -or ($_.LocalPath -match "\\$([regex]::Escape($userName))$") } | Select-Object -First 1
    if ($prof) { $userProfile = $prof.LocalPath; if (-not $userSid) { $userSid = $prof.SID } }
    Write-Info "User SID: $userSid    Profile: $userProfile"
}

# ====================  B. CONNECTIVITY  ====================
Write-Section 'B. CONNECTIVITY'

try {
    $dns = Resolve-DnsName -Name $NewServer -ErrorAction Stop | Where-Object { $_.IPAddress } | Select-Object -First 1
    if ($dns) { Write-Pass "DNS: $NewServer resolves to $($dns.IPAddress)." }
    else { Write-Fail "DNS: $NewServer did not resolve."; Add-Finding "DNS for $NewServer is not resolving on this PC; drives cannot map by name." }
} catch { Write-Fail "DNS: could not resolve $NewServer ($($_.Exception.Message))."; Add-Finding "DNS for $NewServer failed; check the client's DNS settings." }

$smbNew = Test-NetConnection -ComputerName $NewServer -Port 445 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
if ($smbNew -and $smbNew.TcpTestSucceeded) { Write-Pass "SMB (445) to $NewServer is reachable from this PC." }
else { Write-Fail "SMB (445) to $NewServer is NOT reachable."; Add-Finding "This PC cannot reach $NewServer on 445 (network/VPN/firewall); drives cannot map." }

$smbOld = Test-NetConnection -ComputerName $OldServer -Port 445 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
if ($smbOld -and $smbOld.TcpTestSucceeded) { Write-Review "OLD server $OldServer is still reachable on 445. Stale maps to it will still 'work', which can mask the cutover." }
else { Write-Info "OLD server $OldServer is not reachable on 445 (expected once it is retired)." }

# ====================  C. GROUP POLICY (the main check)  ====================
Write-Section 'C. GROUP POLICY (the main check)'

if ($ForceGpUpdate) {
    Write-Info "Running gpupdate /force (refreshes policy but does NOT rebuild the logon token)..."
    & gpupdate.exe /force 2>&1 | Out-Null
}

$gpApplied = $null      # $true Applied, $false Denied/filtered, $null unknown
$inFilterGroup = $null
if ($loggedUser) {
    $gp = & gpresult.exe /user $loggedUser /scope:user /r 2>&1
    $gpText = ($gp | Out-String)
    if ($LASTEXITCODE -ne 0 -or $gpText -match 'does not have RSOP data|Logon Failure|INVALID') {
        Write-Review "gpresult could not read RSoP for $loggedUser (may not have logged on since last policy)."
        Add-Finding "Could not read the user's Group Policy result; have them log off and back on, then re-run."
    }
    else {
        # Track which section of gpresult we are in to classify Applied vs Denied.
        $section = ''
        $appliedGpos = New-Object System.Collections.Generic.List[string]
        $deniedGpos  = New-Object System.Collections.Generic.List[string]
        $secGroups   = New-Object System.Collections.Generic.List[string]
        foreach ($lnRaw in $gp) {
            $ln = "$lnRaw"
            if ($ln -match 'Applied Group Policy Objects')          { $section = 'applied'; continue }
            if ($ln -match 'not applied because they were filtered') { $section = 'denied';  continue }
            if ($ln -match 'part of the following security groups')  { $section = 'groups';  continue }
            if ($ln -match '^\s*-{3,}\s*$' -or [string]::IsNullOrWhiteSpace($ln)) { continue }
            $val = $ln.Trim()
            switch ($section) {
                'applied' { if ($val -notmatch ':\s') { $appliedGpos.Add($val) } }
                'denied'  { if ($val -notmatch 'Filtering|Reason') { $deniedGpos.Add($val) } }
                'groups'  { $secGroups.Add($val) }
            }
        }

        if ($appliedGpos | Where-Object { $_ -match [regex]::Escape($GpoName) }) {
            $gpApplied = $true
            Write-Pass "Drive-map GPO '$GpoName' is APPLIED for $loggedUser."
        }
        elseif ($deniedGpos | Where-Object { $_ -match [regex]::Escape($GpoName) }) {
            $gpApplied = $false
            Write-Fail "Drive-map GPO '$GpoName' was DENIED (filtered out) for $loggedUser. This is the classic security-group cause."
            Add-Finding "GPO '$GpoName' is filtered out (Denied) for this user. Almost always means they are not in the GPO's security filter group."
        }
        else {
            Write-Review "Drive-map GPO '$GpoName' did not appear in Applied OR Denied. The machine may not be receiving it at all (link/scope/loopback)."
            Add-Finding "Drive-map GPO not seen in the user's result at all; check the GPO link, security filter, and loopback processing."
        }

        if ($FilterGroup) {
            if ($secGroups | Where-Object { $_ -match [regex]::Escape($FilterGroup) }) {
                $inFilterGroup = $true
                Write-Pass "User IS in the filter group '$FilterGroup' (per gpresult)."
            }
            else {
                $inFilterGroup = $false
                Write-Fail "User is NOT in the filter group '$FilterGroup' in their CURRENT token."
                Write-Review "If they were just added, the membership only lands after a fresh LOG OFF / LOG ON. gpupdate alone will NOT fix it."
                Add-Finding "Add '$loggedUser' to '$FilterGroup' on a DC, then have the user LOG OFF and LOG ON."
            }
            if (-not ($secGroups | Where-Object { $_ -match '(?i)\bDomain Users\b' })) {
                Write-Review "The user's token does not even show 'Domain Users'. That points to a logon/token problem, not group membership."
            }
        }
    }
}
else {
    Write-Info "Skipped: no logged-in user to evaluate policy for."
}

# ====================  D. DRIVE MAPPINGS FROM THE USER HIVE  ====================
Write-Section 'D. CURRENT DRIVE MAPPINGS (from the user hive)'

if ($userSid) {
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
    }
    $hiveLoaded = Test-Path "HKU:\$userSid"
    $unloadAfter = $false
    if (-not $hiveLoaded -and $userProfile -and (Test-Path "$userProfile\NTUSER.DAT")) {
        & reg.exe load "HKU\$userSid" "$userProfile\NTUSER.DAT" 2>&1 | Out-Null
        $hiveLoaded = Test-Path "HKU:\$userSid"
        $unloadAfter = $hiveLoaded
    }

    if ($hiveLoaded) {
        $netKey = "HKU:\$userSid\Network"
        if (Test-Path $netKey) {
            $drives = Get-ChildItem $netKey -ErrorAction SilentlyContinue
            if ($drives) {
                foreach ($d in $drives) {
                    $letter = Split-Path $d.PSChildName -Leaf
                    $remote = (Get-ItemProperty -Path $d.PSPath -ErrorAction SilentlyContinue).RemotePath
                    if ($remote -match "(?i)$([regex]::Escape($OldServer))") {
                        Write-Fail "Drive ${letter}: still points at the OLD server -> $remote"
                        Add-Finding "Drive ${letter}: is still mapped to $OldServer in the user hive; a fresh logon should replace it once the GPO applies."
                    }
                    elseif ($remote -match "(?i)$([regex]::Escape($NewServerShort))") {
                        Write-Pass "Drive ${letter}: -> $remote"
                    }
                    else {
                        Write-Review "Drive ${letter}: -> $remote (neither old nor new server; review)"
                    }
                }
            }
            else { Write-Info "No persistent drives under the user's Network key (GPP maps are often non-persistent; can be normal)." }
        }
        else { Write-Info "User hive has no Network key (no persistent mapped drives recorded)." }
    }
    else {
        Write-Review "Could not read the user's registry hive."
    }

    if ($unloadAfter) { [gc]::Collect(); & reg.exe unload "HKU\$userSid" 2>&1 | Out-Null }
}
else {
    Write-Info "Skipped: no resolved user SID."
}

# ====================  E. DESKTOP SHORTCUTS  ====================
Write-Section 'E. DESKTOP SHORTCUTS'

$desktops = New-Object System.Collections.Generic.List[string]
if ($userProfile) { $desktops.Add((Join-Path $userProfile 'Desktop')) }
$desktops.Add((Join-Path $env:SystemDrive 'Users\Public\Desktop'))

$wsh = New-Object -ComObject WScript.Shell
$badLnks = New-Object System.Collections.Generic.List[object]
foreach ($dt in $desktops) {
    if (-not (Test-Path -LiteralPath $dt)) { continue }
    Get-ChildItem -LiteralPath $dt -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
        $sc = $wsh.CreateShortcut($_.FullName)
        if ($sc.TargetPath -match "(?i)\\\\$([regex]::Escape($OldServer))") {
            $badLnks.Add([pscustomobject]@{ File = $_.FullName; Target = $sc.TargetPath; WorkDir = $sc.WorkingDirectory })
        }
    }
}

if ($badLnks.Count -eq 0) {
    Write-Pass "No desktop shortcuts point at \\$OldServer."
}
else {
    Write-Review "$($badLnks.Count) desktop shortcut(s) still point at \\$OldServer."
    foreach ($b in $badLnks) { Write-Host ("        $($b.File)  ->  $($b.Target)") -ForegroundColor DarkGray }
    if ($FixShortcuts) {
        $fixed = 0
        $oldPattern = "(?i)\\\\$([regex]::Escape($OldServer))(\.[\w.-]+)?"
        foreach ($b in $badLnks) {
            try {
                $sc = $wsh.CreateShortcut($b.File)
                $sc.TargetPath = $sc.TargetPath -replace $oldPattern, "\\$NewServer"
                if ($sc.WorkingDirectory) { $sc.WorkingDirectory = $sc.WorkingDirectory -replace $oldPattern, "\\$NewServer" }
                $sc.Save()
                $fixed++
                Write-Pass "Rewrote: $($b.File)  ->  $($sc.TargetPath)"
            } catch { Write-Fail "Could not rewrite $($b.File): $($_.Exception.Message)" }
        }
        Add-Finding "Rewrote $fixed desktop shortcut(s) from $OldServer to $NewServer (assumes share names match between servers)."
    }
    else {
        Write-Info "Re-run with -FixShortcuts to rewrite these to the new server."
        Add-Finding "$($badLnks.Count) desktop shortcut(s) point at the old server; re-run with -FixShortcuts to repoint them."
    }
}

# ====================  F. DIAGNOSIS  ====================
Write-Section 'F. DIAGNOSIS AND NEXT STEP'

if ($gpApplied -eq $false -or $inFilterGroup -eq $false) {
    Write-Fail "MOST LIKELY CAUSE: this user is not passing the drive-map GPO's security filter."
    Write-Host  "        FIX: on a DC, confirm the user (or 'Domain Users') is in the GPO's filter group," -ForegroundColor Yellow
    Write-Host  "             then have the user LOG OFF and LOG ON. A fresh logon is required; gpupdate will not do it." -ForegroundColor Yellow
}
elseif ($gpApplied -eq $true) {
    Write-Pass "The drive-map GPO is applying for this user."
    Write-Host  "        If drives are still wrong, it is a stale cached mapping or a connectivity gap. Have the user LOG OFF and LOG ON" -ForegroundColor Yellow
    Write-Host  "        to rebuild the maps; if a drive still shows the old server afterward, delete that persistent mapping and re-logon." -ForegroundColor Yellow
}
else {
    Write-Review "Could not confirm the GPO result. Have the user log off and on, then re-run so gpresult has fresh data."
}

if ($findings.Count -gt 0) {
    Write-Host ''
    Write-Host "  Findings:" -ForegroundColor White
    $i = 1
    foreach ($f in $findings) { Write-Host ("    $i. $f"); $i++ }
}

Write-Host ''
Write-Host "===============  END  (machine: $machineName  user: $loggedUser)  ===============" -ForegroundColor Cyan
