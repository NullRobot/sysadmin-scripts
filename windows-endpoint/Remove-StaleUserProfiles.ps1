<#
.SYNOPSIS
    Deletes local Windows user profiles that have not been modified in a configurable number of days.

.DESCRIPTION
    Enumerates subfolders under a user profiles directory (default C:\Users), compares each
    folder's LastWriteTime against a threshold, and removes the matching Win32_UserProfile via
    CIM/WMI for any profile older than the threshold. All actions are logged to a CSV-style log
    file next to the script (or to a path you specify).

    Intended for cleaning up stale local profiles on shared or kiosk-style Windows endpoints
    (e.g. via RMM/scheduled task run as SYSTEM). Removing a profile deletes the user's local
    registry hive and local profile folder - it does NOT touch redirected/roaming data such as
    OneDrive, Documents, or network home shares, but any purely local files in that profile will
    be lost.

.PARAMETER UsersDirectory
    Path to the parent directory containing user profile folders. Defaults to C:\Users.

.PARAMETER ThresholdDays
    Minimum age (based on folder LastWriteTime) in days before a profile is eligible for
    deletion. Defaults to 30.

.PARAMETER LogPath
    Path to the log file. Defaults to profile_deletion_log.txt in the script's own directory.

.PARAMETER WhatIf
    Standard PowerShell ShouldProcess support. Run with -WhatIf first to see which profiles
    would be deleted without actually deleting anything.

.EXAMPLE
    .\Remove-StaleUserProfiles.ps1 -WhatIf
    Shows which profiles older than 30 days would be removed, without deleting anything.

.EXAMPLE
    .\Remove-StaleUserProfiles.ps1 -ThresholdDays 45 -LogPath D:\Logs\profile_cleanup.csv
    Deletes profiles untouched for 45+ days and logs to a custom path.

.NOTES
    Run this with an account that has rights to enumerate and remove CIM user profile instances
    (local admin, or SYSTEM via RMM/scheduled task). Always test with -WhatIf on a non-production
    machine first. This script does not exclude any built-in or service accounts, so review the
    -WhatIf output before running for real in an environment with non-standard local accounts.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$UsersDirectory = "C:\Users",
    [int]$ThresholdDays = 30,
    [string]$LogPath
)

# Default log file path to the script's own directory if not specified
if (-not $LogPath) {
    $scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
    $LogPath = Join-Path -Path $scriptDirectory -ChildPath "profile_deletion_log.txt"
}

# Get the current date once so all comparisons in this run are consistent
$currentDate = Get-Date

# Initialize the log file with headers
"Timestamp,UserProfile,Result" | Out-File -FilePath $LogPath -Encoding utf8

# Writes a line to both the log file and the console
function Write-Log {
    param (
        [string]$message
    )
    $message | Out-File -FilePath $LogPath -Append -Encoding utf8
    Write-Host $message
}

Write-Log "$(Get-Date) - Script execution started"

# Loop through each user's folder under the profiles directory
foreach ($userFolder in Get-ChildItem -Path $UsersDirectory -Directory) {
    $lastWriteTime = $userFolder.LastWriteTime
    $folderName = $userFolder.Name
    $profilePath = $userFolder.FullName
    $timeDifference = ($currentDate - $lastWriteTime).Days

    Write-Log "$(Get-Date) - Checking folder: $profilePath, LastWriteTime: $lastWriteTime, Days Old: $timeDifference"

    if ($timeDifference -ge $ThresholdDays) {
        try {
            # Use CIM to get the Win32_UserProfile instance matching this folder, so we remove
            # the profile properly (registry hive + profile list entry), not just the folder.
            $userProfile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { $_.LocalPath -eq $profilePath }
            if ($userProfile) {
                $sid = $userProfile.SID
                Write-Log "$(Get-Date) - Found SID: $sid for profile: $profilePath"

                if ($PSCmdlet.ShouldProcess($profilePath, "Remove user profile")) {
                    $userProfile | Remove-CimInstance -ErrorAction Stop
                    $logMessage = "$(Get-Date),$profilePath,Deletion succeeded"
                    Write-Log $logMessage
                } else {
                    Write-Log "$(Get-Date),$profilePath,Skipped (WhatIf)"
                }
            } else {
                $logMessage = "$(Get-Date),$profilePath,No matching profile found"
                Write-Log $logMessage
            }
        } catch {
            $logMessage = "$(Get-Date),$profilePath,Deletion failed: $_"
            Write-Log $logMessage
        }
    } else {
        $logMessage = "$(Get-Date),$profilePath,Profile is not $ThresholdDays days old"
        Write-Log $logMessage
    }
}

Write-Log "$(Get-Date) - Script execution completed"
