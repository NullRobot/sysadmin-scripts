<#
.SYNOPSIS
    Runs a command in the LOGGED-ON USER's context from a SYSTEM session
    (RMM) via a throwaway scheduled task, and returns the output.

.DESCRIPTION
    The fundamental RMM gotcha: scripts run as SYSTEM, but many diagnostics
    only mean anything in the user's context - dsregcmd /status (PRT state),
    net use (mapped drives), cmdkey /list (stored credentials), klist,
    whoami /groups, per-user env vars. This helper:
      1. Registers a temporary scheduled task with the interactive user as
         principal (LogonType Interactive - the user must be logged on)
      2. Runs the command with output redirected to a temp file
      3. Waits, reads the output back, cleans up the task and the temp file
    Returns the command's stdout as strings. The command runs with the
    user's token and limited privileges (RunLevel Limited).

.PARAMETER Command
    The command line to run (passed to cmd.exe /c). Quote as needed.

.PARAMETER UserName
    The logged-on user to run as. Default: auto-detected from the loaded
    non-special profile.

.PARAMETER TimeoutSeconds
    How long to wait for output before giving up. Default 15.

.EXAMPLE
    .\Invoke-AsLoggedOnUser.ps1 -Command 'dsregcmd /status'

.EXAMPLE
    .\Invoke-AsLoggedOnUser.ps1 -Command 'net use' -UserName jsmith
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Command,
    [string]$UserName,
    [int]$TimeoutSeconds = 15
)

# Auto-detect the logged-on user if not given (SYSTEM-safe)
if (-not $UserName) {
    $userProfile = Get-CimInstance Win32_UserProfile | Where-Object { $_.Loaded -and !$_.Special } | Select-Object -First 1
    if (-not $userProfile) { throw "No logged-on user profile found; pass -UserName." }
    $UserName = Split-Path $userProfile.LocalPath -Leaf
}

$taskName = "UserCtx_$([guid]::NewGuid().ToString('N').Substring(0,8))"
$outFile = "C:\Windows\Temp\$taskName.out"

try {
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c $Command > `"$outFile`" 2>&1"
    $principal = New-ScheduledTaskPrincipal -UserId $UserName -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName

    # Wait for the output file to appear and the task to finish
    $elapsed = 0
    do {
        Start-Sleep -Seconds 1
        $elapsed++
        $state = (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue).State
    } while ($state -eq 'Running' -and $elapsed -lt $TimeoutSeconds)
    Start-Sleep -Seconds 1  # let the redirect flush

    if (Test-Path $outFile) {
        Get-Content $outFile
    } else {
        Write-Warning "No output produced. Is '$UserName' actually logged on interactively?"
    }
}
finally {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $outFile -Force -ErrorAction SilentlyContinue
}
