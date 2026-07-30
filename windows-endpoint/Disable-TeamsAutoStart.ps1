<#
.SYNOPSIS
    Stops Microsoft Teams (classic AND new) from auto-starting for a given
    user - covers every autostart mechanism, runs as SYSTEM.

.DESCRIPTION
    Teams re-inserts itself into startup through five different doors; missing
    one means it's back at next logon. For the target profile this script:
      1. Removes Teams entries from the user's HKU ...\CurrentVersion\Run key
         (classic Teams / Squirrel updater)
      2. Removes Teams from the user's StartupApproved\Run key (new Teams MSIX)
      3. Deletes Teams shortcuts from the user's Startup folder
      4. Removes Teams entries from HKLM Run (machine-wide)
      5. Edits both Teams config files to turn off open-at-login and
         run-in-background: new Teams app_settings.json and classic
         desktop-config.json
      6. Kills any running Teams processes
    Designed for SYSTEM context (RMM): resolves the profile and SID itself
    and edits HKU directly, never HKCU. Useful for kiosks, conference-room
    PCs, shared machines, and "Teams keeps popping up" tickets.

.PARAMETER UserProfilePattern
    Wildcard fragment matching the target profile's LocalPath (e.g. 'jsmith').
    Default: the currently loaded non-special profile.

.EXAMPLE
    .\Disable-TeamsAutoStart.ps1 -UserProfilePattern kiosk
#>
[CmdletBinding()]
param(
    [string]$UserProfilePattern
)

$hostname = $env:COMPUTERNAME
Write-Output "=== Disable Teams Auto-Start on $hostname ==="

# Resolve the target profile + SID (SYSTEM-safe; never $env:USERPROFILE)
$profiles = Get-CimInstance Win32_UserProfile | Where-Object { !$_.Special }
if ($UserProfilePattern) {
    $userProfile = $profiles | Where-Object { $_.LocalPath -like "*$UserProfilePattern*" } | Select-Object -First 1
} else {
    $userProfile = $profiles | Where-Object { $_.Loaded } | Select-Object -First 1
}
if (-not $userProfile) {
    Write-Output "Target profile not found. Available profiles:"
    $profiles | ForEach-Object { Write-Output "  $($_.LocalPath)" }
    exit 1
}
$profilePath = $userProfile.LocalPath
$sid = $userProfile.SID
Write-Output "Target profile: $profilePath (SID: $sid)"
if (-not $userProfile.Loaded) {
    Write-Output "NOTE: profile hive not loaded; registry steps will be skipped unless the user is logged on."
}

# 1. Remove Teams from the user's Run key (HKU)
Write-Output "`nStep 1: HKU Run key..."
$runKey = "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Run"
if (Test-Path $runKey) {
    $teamsEntries = Get-ItemProperty -Path $runKey -ErrorAction SilentlyContinue |
        Get-Member -MemberType NoteProperty |
        Where-Object { $_.Name -match 'teams|com.squirrel' }
    foreach ($entry in $teamsEntries) {
        Remove-ItemProperty -Path $runKey -Name $entry.Name -Force -ErrorAction SilentlyContinue
        Write-Output "  Removed: $($entry.Name)"
    }
    if (-not $teamsEntries) { Write-Output "  No Teams entries found" }
} else {
    Write-Output "  Run key not found (hive not loaded?)"
}

# 2. New Teams (MSIX) StartupApproved
Write-Output "`nStep 2: StartupApproved (new Teams MSIX)..."
$startupApproved = "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
if (Test-Path $startupApproved) {
    $teamsStartup = Get-ItemProperty -Path $startupApproved -ErrorAction SilentlyContinue |
        Get-Member -MemberType NoteProperty |
        Where-Object { $_.Name -match 'teams' }
    foreach ($entry in $teamsStartup) {
        Remove-ItemProperty -Path $startupApproved -Name $entry.Name -Force -ErrorAction SilentlyContinue
        Write-Output "  Removed: $($entry.Name)"
    }
    if (-not $teamsStartup) { Write-Output "  No Teams entries" }
} else {
    Write-Output "  StartupApproved key not found"
}

# 3. Startup folder shortcuts
Write-Output "`nStep 3: Startup folder..."
$startupFolder = Join-Path $profilePath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path $startupFolder) {
    $teamsLinks = Get-ChildItem $startupFolder -Filter "*Teams*" -ErrorAction SilentlyContinue
    foreach ($link in $teamsLinks) {
        Remove-Item $link.FullName -Force -ErrorAction SilentlyContinue
        Write-Output "  Removed: $($link.Name)"
    }
    if (-not $teamsLinks) { Write-Output "  No Teams shortcuts" }
}

# 4. HKLM Run (all users)
Write-Output "`nStep 4: HKLM Run key..."
$hklmRun = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
$teamsHKLM = Get-ItemProperty -Path $hklmRun -ErrorAction SilentlyContinue |
    Get-Member -MemberType NoteProperty |
    Where-Object { $_.Name -match 'teams' }
foreach ($entry in $teamsHKLM) {
    Remove-ItemProperty -Path $hklmRun -Name $entry.Name -Force -ErrorAction SilentlyContinue
    Write-Output "  Removed from HKLM: $($entry.Name)"
}
if (-not $teamsHKLM) { Write-Output "  No Teams entries in HKLM Run" }

# 5. Teams' own config files
Write-Output "`nStep 5: Teams config files..."
$teamsConfig = Join-Path $profilePath "AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\app_settings.json"
if (Test-Path $teamsConfig) {
    try {
        $config = Get-Content $teamsConfig -Raw | ConvertFrom-Json
        $config | Add-Member -NotePropertyName 'open_app_in_background' -NotePropertyValue $false -Force
        $config | Add-Member -NotePropertyName 'auto_start_on_login' -NotePropertyValue $false -Force
        $config | ConvertTo-Json -Depth 10 | Set-Content $teamsConfig -Force
        Write-Output "  Updated new-Teams app_settings.json: auto_start=false, background=false"
    } catch {
        Write-Output "  Error updating new-Teams config: $($_.Exception.Message)"
    }
} else {
    Write-Output "  New Teams config not found"
}

$classicConfig = Join-Path $profilePath "AppData\Roaming\Microsoft\Teams\desktop-config.json"
if (Test-Path $classicConfig) {
    try {
        $config = Get-Content $classicConfig -Raw | ConvertFrom-Json
        if ($config.appPreferenceSettings) {
            $config.appPreferenceSettings | Add-Member -NotePropertyName 'openAtLogin' -NotePropertyValue $false -Force
            $config.appPreferenceSettings | Add-Member -NotePropertyName 'runningOnClose' -NotePropertyValue $false -Force
        }
        $config | ConvertTo-Json -Depth 10 | Set-Content $classicConfig -Force
        Write-Output "  Updated classic desktop-config.json: openAtLogin=false"
    } catch {
        Write-Output "  Error updating classic config: $($_.Exception.Message)"
    }
} else {
    Write-Output "  Classic Teams config not found"
}

# 6. Kill Teams if running
Write-Output "`nStep 6: Stopping Teams processes..."
Get-Process -Name ms-teams, Teams -ErrorAction SilentlyContinue | Stop-Process -Force
Write-Output "  Done"

Write-Output "`n=== Teams auto-start disabled on $hostname ==="
