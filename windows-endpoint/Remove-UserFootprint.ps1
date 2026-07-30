<#
.SYNOPSIS
    Audits (and optionally removes) every trace of a specific user account on a Windows
    device: profile, scheduled tasks, services, mapped-drive hive entries, stored
    credentials, and Wi-Fi 802.1X credential bindings.

.DESCRIPTION
    Built for the recurring "user changed their password and something on some machine
    keeps locking them out" and "user left, purge their cached footprint" scenarios.
    Run as SYSTEM (e.g. via an RMM quick job) on one device per run.

    -Mode Audit : read-only. Inventories everything and writes a text + JSON report.
                  Safe on any device, including the user's personal machine.
    -Mode Clean : audits first, then removes: the user's local profile (skipped if the
                  hive is loaded / session active unless -Force), scheduled tasks whose
                  principal is the user, services running as the user (stopped and set
                  Disabled, StartName untouched), and device-level cmdkey entries.

    What it inventories either way:
      1. User profile(s) matching the SAM name (Win32_UserProfile)
      2. Security log 4624/4625/4648 events referencing the user (last N days) with a
         per-process summary showing WHAT is invoking the user's credentials
      3. Wi-Fi profiles with 802.1X/EAP auth (cached domain creds are a classic
         lockout source after a password change)
      4. Scheduled tasks running as the user
      5. Services running as the user
      6. Interactive/disconnected sessions (query session)
      7. Persistent drive mappings from the user's registry hive (loads NTUSER.DAT
         temporarily if the hive isn't loaded)
      8. Device-level Credential Manager entries (cmdkey /list as SYSTEM)

.PARAMETER UserSam
    SAM account name of the target user (no domain prefix).

.PARAMETER Mode
    'Audit' (default, read-only) or 'Clean' (destructive - see DESCRIPTION).

.PARAMETER EventDays
    How many days of Security log to scan. Default 14.

.PARAMETER LogDir
    Where the .log/.json reports land. Default C:\Windows\Temp.

.PARAMETER Force
    In Clean mode, also delete the profile even if it is currently loaded
    (normally skipped so an active session isn't yanked out from under the user).

.EXAMPLE
    .\Remove-UserFootprint.ps1 -UserSam j.smith -Mode Audit

.EXAMPLE
    .\Remove-UserFootprint.ps1 -UserSam j.smith -Mode Clean
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$UserSam,

    [ValidateSet('Audit','Clean')]
    [string]$Mode = 'Audit',

    [int]$EventDays = 14,

    [string]$LogDir = 'C:\Windows\Temp',

    [switch]$Force
)

$ErrorActionPreference = 'Continue'
$userRegex = [regex]::Escape($UserSam)

$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$hostName = $env:COMPUTERNAME
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$logTxt  = Join-Path $LogDir "userfootprint-${UserSam}-${hostName}-${stamp}.log"
$logJson = Join-Path $LogDir "userfootprint-${UserSam}-${hostName}-${stamp}.json"

function Log {
    param($msg)
    $line = "[$((Get-Date).ToString('s'))] $msg"
    $line | Tee-Object -FilePath $logTxt -Append
}

Log "=== user footprint ${Mode} ==="
Log "Host: ${hostName}   User: ${UserSam}"

$report = [ordered]@{
    host      = $hostName
    mode      = $Mode
    user      = $UserSam
    timestamp = (Get-Date).ToUniversalTime().ToString('s') + 'Z'
    findings  = [ordered]@{}
    actions   = @()
}

# ---------- 1. User profile presence ----------
Log "--- 1. User profile ---"
$profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
    Where-Object { -not $_.Special -and $_.LocalPath -match "\\${userRegex}(\.|$)" }
if ($profiles) {
    $report.findings.profiles = @($profiles | ForEach-Object {
        [pscustomobject]@{
            LocalPath   = $_.LocalPath
            SID         = $_.SID
            Loaded      = $_.Loaded
            LastUseTime = $_.LastUseTime
        }
    })
    $profiles | ForEach-Object { Log "Profile: $($_.LocalPath)  SID=$($_.SID)  Loaded=$($_.Loaded)  LastUse=$($_.LastUseTime)" }
} else {
    Log "No profile found matching ${UserSam} on this device."
    $report.findings.profiles = @()
}

# ---------- 2. Security log 4624/4625/4648 referencing the user ----------
Log "--- 2. Local Security log (${EventDays}d) ---"
$since = (Get-Date).AddDays(-$EventDays)
$localEvents = @()
try {
    $raw = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4648; StartTime=$since} -ErrorAction Stop -MaxEvents 20000
    foreach ($e in $raw) {
        $x = [xml]$e.ToXml()
        $d = @{}
        foreach ($node in $x.Event.EventData.Data) { $d[$node.Name] = $node.'#text' }
        if (($d['TargetUserName'] -match $userRegex) -or ($d['SubjectUserName'] -match $userRegex) -or ($d['TargetOutboundUserName'] -match $userRegex)) {
            $localEvents += [pscustomobject]@{
                Time         = $e.TimeCreated.ToString('s')
                Id           = $e.Id
                TargetUser   = $d['TargetUserName']
                SubjectUser  = $d['SubjectUserName']
                OutboundUser = $d['TargetOutboundUserName']
                LogonType    = $d['LogonType']
                ProcessName  = $d['ProcessName']
                AuthPackage  = $d['AuthenticationPackageName']
                Workstation  = $d['WorkstationName']
                IpAddress    = $d['IpAddress']
                Status       = $d['Status']
                SubStatus    = $d['SubStatus']
            }
        }
    }
    Log "Found $($localEvents.Count) relevant Security events in ${EventDays} days."
} catch {
    Log "Security log probe error: $($_.Exception.Message)"
}
$report.findings.security_events = $localEvents
# Which processes are invoking the user's creds? Usually names the culprit outright.
$report.findings.processes_using_creds = @($localEvents |
    Where-Object { $_.ProcessName -and $_.ProcessName -ne '-' } |
    Group-Object ProcessName |
    ForEach-Object { [pscustomobject]@{ Process = $_.Name; Count = $_.Count } } |
    Sort-Object Count -Descending)
$report.findings.processes_using_creds | ForEach-Object { Log "  cred-using process: $($_.Process) x$($_.Count)" }

# ---------- 3. Wi-Fi profiles + 802.1X ----------
Log "--- 3. Wi-Fi profiles ---"
try {
    $profNames = (netsh wlan show profiles) | Select-String 'All User Profile\s*:\s*(.+)' | ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }
    $wifiData = @()
    foreach ($p in $profNames) {
        $detail = netsh wlan show profile name="$p" 2>&1 | Out-String
        $entry = [pscustomobject]@{
            Name     = $p
            AuthType = if ($detail -match 'Authentication\s+:\s*(.+)') { $matches[1].Trim() } else { '?' }
            EAPType  = if ($detail -match 'EAP type\s+:\s*(.+)') { $matches[1].Trim() } else { '' }
            Raw      = ($detail -split "`r?`n" | Where-Object { $_ -match 'Authentication|EAP|credential|User' } | Select-Object -First 10) -join ' | '
        }
        $wifiData += $entry
        Log "Wifi: $($entry.Name)  Auth=$($entry.AuthType)  EAP=$($entry.EAPType)"
    }
    $report.findings.wifi = $wifiData
} catch {
    Log "Wifi probe error: $($_.Exception.Message)"
}

# ---------- 4. Scheduled tasks running as the user ----------
Log "--- 4. Scheduled tasks ---"
$tasks = @()
try {
    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.Principal.UserId -match $userRegex })
    $report.findings.scheduled_tasks = @($tasks | ForEach-Object {
        [pscustomobject]@{ TaskName = $_.TaskName; Path = $_.TaskPath; State = $_.State; UserId = $_.Principal.UserId }
    })
    if ($tasks) { $tasks | ForEach-Object { Log "Task: $($_.TaskPath)$($_.TaskName)  as=$($_.Principal.UserId)  state=$($_.State)" } }
    else { Log "No scheduled tasks referencing the user." }
} catch { Log "Task probe error: $($_.Exception.Message)" }

# ---------- 5. Services running as the user ----------
Log "--- 5. Services ---"
$svcs = @()
try {
    $svcs = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.StartName -match $userRegex })
    $report.findings.services = @($svcs | Select-Object Name, DisplayName, StartName, State, StartMode)
    if ($svcs) { $svcs | ForEach-Object { Log "Service: $($_.Name)  runas=$($_.StartName)  state=$($_.State)" } }
    else { Log "No services referencing the user." }
} catch { Log "Service probe error: $($_.Exception.Message)" }

# ---------- 6. Sessions ----------
Log "--- 6. Sessions ---"
try {
    $sess = (query session 2>&1) -join "`n"
    $report.findings.sessions = $sess
    Log $sess
} catch { Log "Session probe error: $($_.Exception.Message)" }

# ---------- 7. Persistent drive mappings from the user's hive ----------
Log "--- 7. Mapped drives ---"
if (-not (Test-Path 'HKU:\')) { New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null }
$mappedDrives = @()
foreach ($p in $profiles) {
    $sid = $p.SID
    if (Test-Path "HKU:\${sid}") {
        $netKey = "HKU:\${sid}\Network"
        if (Test-Path $netKey) {
            Get-ChildItem $netKey | ForEach-Object {
                $props = Get-ItemProperty $_.PSPath
                $mappedDrives += [pscustomobject]@{ SID = $sid; DriveLetter = $_.PSChildName; RemotePath = $props.RemotePath; UserName = $props.UserName }
            }
        }
    } else {
        # Hive not loaded - mount it read, then unload
        $ntuserPath = Join-Path $p.LocalPath 'NTUSER.DAT'
        if (Test-Path $ntuserPath) {
            try {
                reg load "HKU\${sid}_tmp" "${ntuserPath}" | Out-Null
                $netKey = "HKU:\${sid}_tmp\Network"
                if (Test-Path $netKey) {
                    Get-ChildItem $netKey | ForEach-Object {
                        $props = Get-ItemProperty $_.PSPath
                        $mappedDrives += [pscustomobject]@{ SID = $sid; DriveLetter = $_.PSChildName; RemotePath = $props.RemotePath; UserName = $props.UserName }
                    }
                }
                [gc]::Collect(); [gc]::WaitForPendingFinalizers()
                reg unload "HKU\${sid}_tmp" | Out-Null
            } catch {
                Log "Could not load hive for ${sid}: $($_.Exception.Message)"
            }
        }
    }
}
$report.findings.mapped_drives = $mappedDrives
$mappedDrives | ForEach-Object { Log "Mapped: $($_.DriveLetter): -> $($_.RemotePath)  saved_as=$($_.UserName)" }

# ---------- 8. Device-level Credential Manager (SYSTEM context) ----------
Log "--- 8. cmdkey /list (SYSTEM context) ---"
try {
    $cm = (cmdkey /list) -join "`n"
    $report.findings.cmdkey_system = $cm
    Log $cm
} catch { Log "cmdkey probe error: $($_.Exception.Message)" }

# ============================================================
# CLEAN ACTIONS - only in Clean mode
# ============================================================
if ($Mode -eq 'Clean') {
    Log "=== CLEANING ==="

    # Profile delete (skip loaded profiles unless -Force)
    foreach ($p in $profiles) {
        if ($p.Loaded -and -not $Force) {
            Log "SKIPPED loaded profile $($p.LocalPath) (active session; use -Force to override)"
            $report.actions += "SKIPPED loaded profile $($p.LocalPath)"
            continue
        }
        try {
            $cim = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$($p.SID)'" -ErrorAction Stop
            Remove-CimInstance -InputObject $cim -ErrorAction Stop
            $report.actions += "Deleted profile $($p.LocalPath)"
            Log "Deleted profile $($p.LocalPath)"
        } catch {
            $report.actions += "FAILED to delete profile $($p.LocalPath): $($_.Exception.Message)"
            Log "FAILED to delete profile $($p.LocalPath): $($_.Exception.Message)"
        }
    }

    # Scheduled tasks running as the user
    foreach ($t in $tasks) {
        try {
            Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop
            $report.actions += "Removed scheduled task $($t.TaskPath)$($t.TaskName)"
            Log "Removed scheduled task $($t.TaskPath)$($t.TaskName)"
        } catch {
            $report.actions += "FAILED to remove scheduled task $($t.TaskName): $($_.Exception.Message)"
        }
    }

    # Services running as the user: stop + disable (leave StartName - no replacement to set)
    foreach ($s in $svcs) {
        try {
            Set-Service -Name $s.Name -StartupType Disabled -ErrorAction Stop
            Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
            $report.actions += "Disabled service $($s.Name) (was running as $($s.StartName))"
            Log "Disabled service $($s.Name)"
        } catch { Log "FAILED to disable service $($s.Name): $($_.Exception.Message)" }
    }

    # Device-level cmdkey entries (rebuild on next legitimate use)
    try {
        $cmLines = cmdkey /list | Select-String 'Target:'
        foreach ($l in $cmLines) {
            if ($l -match 'Target:\s*(.+?)\s*$') {
                $tgt = $matches[1]
                cmdkey /delete:"$tgt" | Out-Null
                $report.actions += "Removed cmdkey target $tgt"
            }
        }
    } catch { Log "cmdkey cleanup error: $($_.Exception.Message)" }

    Log "=== CLEAN COMPLETE ==="
} else {
    Log "=== Audit mode - no changes made ==="
}

$report | ConvertTo-Json -Depth 10 | Set-Content -Path $logJson -Encoding UTF8
Log "Wrote $logTxt"
Log "Wrote $logJson"
