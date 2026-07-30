<#
.SYNOPSIS
    Fixes a broken Entra ID Primary Refresh Token (PRT) on a Windows device
    without touching the user: sets the CloudAP RunRecovery flag and clears
    the WAM token broker cache, so a simple lock/unlock re-establishes SSO.

.DESCRIPTION
    Symptom: endless "Sign in to Microsoft 365" / credential popups in
    Outlook, Teams, and OneDrive on a hybrid- or Entra-joined machine;
    dsregcmd /status (run AS THE USER, not SYSTEM) shows AzureAdPrt : NO.

    Designed to run as SYSTEM (RMM). It:
      1. Sets the CloudAP LoadParameters RunRecovery=1 registry flag, which
         tells the AAD plugin to run device recovery at the user's next
         lock/unlock or sign-in (the silent equivalent of
         'dsregcmd /forcerecovery', which cannot run as SYSTEM)
      2. Clears the user's AAD.BrokerPlugin TokenBroker Accounts cache so
         every app re-requests tokens instead of replaying dead ones
      3. Optionally drops a helper .bat on the user's desktop that runs
         'dsregcmd /forcerecovery' interactively, as a fallback
    After running: have the user lock (Win+L) and unlock. A sign-in prompt
    appears once; after they sign in the PRT is rebuilt.

.PARAMETER UserProfileName
    Folder name of the affected user under C:\Users. Default: the currently
    loaded non-special profile.

.PARAMETER PlaceDesktopFallback
    Also write the interactive Fix_Login_Popup.bat to the user's desktop.

.EXAMPLE
    .\Repair-EntraPrtRecovery.ps1 -PlaceDesktopFallback
#>
[CmdletBinding()]
param(
    [string]$UserProfileName,
    [switch]$PlaceDesktopFallback
)

# Resolve the target user's profile path (SYSTEM context: never use $env:USERPROFILE)
if ($UserProfileName) {
    $profilePath = "C:\Users\$UserProfileName"
} else {
    $profilePath = (Get-CimInstance Win32_UserProfile | Where-Object { $_.Loaded -and !$_.Special } | Select-Object -First 1).LocalPath
}
if (-not $profilePath -or -not (Test-Path $profilePath)) {
    Write-Host "ERROR: could not resolve target user profile. Pass -UserProfileName." -ForegroundColor Red
    exit 1
}
Write-Host "Target profile: $profilePath"

# Step 1: Set the CloudAP RunRecovery registry flag
# {B16898C6-A148-4967-9171-64D755DA8520} is the well-known CloudAP AzureAD package GUID
$regPath = "HKLM:\Software\Microsoft\IdentityStore\LoadParameters\{B16898C6-A148-4967-9171-64D755DA8520}"
if (-not (Test-Path $regPath)) {
    Write-Host "CloudAP registry path not found, creating it"
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "RunRecovery" -Value 1 -Type DWord -ErrorAction Stop
Write-Host "OK: RunRecovery flag set to 1"

# Step 2: Clear the WAM Token Broker cache (forces re-auth for all apps)
$brokerCache = Join-Path $profilePath "AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts"
if (Test-Path $brokerCache) {
    $files = Get-ChildItem $brokerCache -File
    Write-Host "Clearing $($files.Count) cached token files..."
    Remove-Item "$brokerCache\*" -Force -ErrorAction SilentlyContinue
    Write-Host "OK: Token broker cache cleared"
} else {
    Write-Host "INFO: Token broker cache path not found (may differ on this build)"
}

# Step 3: Optional interactive fallback on the user's desktop
if ($PlaceDesktopFallback) {
    $batContent = @'
@echo off
echo This will fix your sign-in popups. A sign-in window will open.
echo Please sign in with your work email and password.
echo.
pause
dsregcmd /forcerecovery
echo.
echo Done! Please lock your PC (Windows key + L) then unlock it.
pause
'@
    $desktopPath = Join-Path $profilePath "Desktop"
    $batContent | Out-File (Join-Path $desktopPath "Fix_Login_Popup.bat") -Encoding ASCII
    Write-Host "OK: fallback batch file placed on the user's desktop"
}

# Verify
Write-Host "`n--- VERIFICATION ---"
$val = Get-ItemProperty -Path $regPath -Name "RunRecovery" -ErrorAction SilentlyContinue
Write-Host "RunRecovery flag: $($val.RunRecovery)"
Write-Host "`nNEXT: have the user lock (Win+L) then unlock. A sign-in dialog should appear once;"
Write-Host "after signing in, verify with 'dsregcmd /status' IN THE USER'S CONTEXT that AzureAdPrt : YES."
