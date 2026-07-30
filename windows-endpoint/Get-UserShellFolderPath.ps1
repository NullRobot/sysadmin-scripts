<#
.SYNOPSIS
    Resolves a user's REAL shell-folder path (Desktop, Documents, Downloads...) from
    SYSTEM context, correctly handling OneDrive Known Folder Move redirection.

.DESCRIPTION
    When RMM scripts run as SYSTEM, $env:USERPROFILE and [Environment]::GetFolderPath
    point at the SYSTEM profile, and blindly using <profile>\Desktop misses users whose
    Desktop was redirected into OneDrive by Known Folder Move. This helper:
      1. Locates the target user's profile (Win32_UserProfile; defaults to the
         currently loaded non-special profile, i.e. the logged-in user)
      2. Reads the requested folder from their hive's User Shell Folders key
         (expanding %USERPROFILE% against THEIR profile path, not SYSTEM's)
      3. Falls back to probing OneDrive* folders under the profile if the
         registry value is missing or the path doesn't exist on disk

    Outputs the resolved absolute path (or nothing + non-zero-ish warnings on
    failure). Use it before dropping files "on the user's desktop" as SYSTEM.

.PARAMETER FolderName
    Which shell folder to resolve. Default 'Desktop'. Must match a value name under
    User Shell Folders ('Desktop', 'Personal' for Documents, '{374DE290-...}' for
    Downloads, etc.).

.PARAMETER UserName
    Substring of the profile path to select a specific user. Default: the currently
    loaded (logged-in) non-special profile.

.EXAMPLE
    $desktop = .\Get-UserShellFolderPath.ps1
    Copy-Item C:\temp\shortcut.lnk -Destination $desktop

.EXAMPLE
    .\Get-UserShellFolderPath.ps1 -FolderName Personal -UserName jsmith
#>
[CmdletBinding()]
param(
    [string]$FolderName = 'Desktop',
    [string]$UserName
)

# --- 1. Find the target profile ---
$profiles = Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special }
if ($UserName) {
    $prof = $profiles | Where-Object { $_.LocalPath -like "*\*${UserName}*" } | Select-Object -First 1
} else {
    $prof = $profiles | Where-Object { $_.Loaded } | Select-Object -First 1
}
if (-not $prof) {
    Write-Warning "Could not find a matching user profile."
    return
}
$sid = $prof.SID
Write-Verbose "User SID: $sid  Profile: $($prof.LocalPath)"

# --- 2. Read the shell folder from their hive ---
$loadedTemp = $false
$hiveRoot = "Registry::HKEY_USERS\$sid"
if (-not (Test-Path $hiveRoot)) {
    # Hive not loaded (user logged off) - mount it temporarily
    $ntuser = Join-Path $prof.LocalPath 'NTUSER.DAT'
    if (Test-Path $ntuser) {
        reg load "HKU\${sid}_tmp" "$ntuser" | Out-Null
        $hiveRoot = "Registry::HKEY_USERS\${sid}_tmp"
        $loadedTemp = $true
    }
}

$resolved = $null
try {
    $shellKey = "$hiveRoot\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    $raw = (Get-ItemProperty -Path $shellKey -Name $FolderName -ErrorAction SilentlyContinue).$FolderName
    if ($raw) {
        # Expand %USERPROFILE% against THEIR profile - SYSTEM's env vars are wrong here
        $resolved = $raw -replace [regex]::Escape('%USERPROFILE%'), $prof.LocalPath
        $resolved = [Environment]::ExpandEnvironmentVariables($resolved)
    }
} finally {
    if ($loadedTemp) {
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        reg unload "HKU\${sid}_tmp" | Out-Null
    }
}

if (-not $resolved) {
    Write-Verbose "User Shell Folders\$FolderName not in hive - using profile-relative default"
    $fallbackLeaf = if ($FolderName -eq 'Personal') { 'Documents' } else { $FolderName }
    $resolved = Join-Path $prof.LocalPath $fallbackLeaf
}

# --- 3. If the path doesn't exist, probe OneDrive KFM locations ---
if (-not (Test-Path $resolved)) {
    Write-Verbose "$resolved does not exist on disk; probing OneDrive folders"
    $leaf = Split-Path $resolved -Leaf
    Get-ChildItem -Path $prof.LocalPath -Directory -Filter 'OneDrive*' -ErrorAction SilentlyContinue | ForEach-Object {
        $candidate = Join-Path $_.FullName $leaf
        if (Test-Path $candidate) { $resolved = $candidate }
    }
}

if (Test-Path $resolved) {
    $resolved
} else {
    Write-Warning "Could not resolve an existing '$FolderName' path for $($prof.LocalPath)."
}
