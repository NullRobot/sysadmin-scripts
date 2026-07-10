<#
.SYNOPSIS
    Discovers active local PowerShell remoting sessions on this machine.

.DESCRIPTION
    Scans running powershell.exe processes for command lines that include
    a -ConnectionUri argument (i.e. New-PSSession / Enter-PSSession style
    remoting sessions, such as those opened through an RMM tool's remote
    PowerShell/Agent Browser feature). For each match it extracts the
    window title (if set), connection URI, port, and username (if a
    PSCredential username is present on the command line), and returns
    the results as a compact JSON array.

    This is a read-only discovery script. It does not open, close, or
    modify any session; it only inspects existing process command lines.

.PARAMETER ProcessName
    Name of the process to scan for remoting command lines. Defaults to
    'powershell.exe'. Set to 'pwsh.exe' to scan PowerShell 7 sessions
    instead, or run the script twice to cover both.

.EXAMPLE
    PS> .\Discover-AgentBrowserSessions.ps1
    Returns a JSON array of any active remoting sessions found among
    running powershell.exe processes.

.EXAMPLE
    PS> .\Discover-AgentBrowserSessions.ps1 -ProcessName pwsh.exe
    Same, but scans PowerShell 7 (pwsh.exe) processes instead.

.NOTES
    Requires local access to query Win32_Process command lines
    (standard user rights are normally sufficient; some environments
    restrict CommandLine visibility to admins).
    Usage: powershell.exe -ExecutionPolicy Bypass -File Discover-AgentBrowserSessions.ps1
#>

[CmdletBinding()]
param(
    [string]$ProcessName = 'powershell.exe'
)

$sessions = @()

Get-CimInstance Win32_Process -Filter "Name='$ProcessName'" -ErrorAction SilentlyContinue | ForEach-Object {
    $cmd = $_.CommandLine
    if ($cmd -and $cmd -match '-ConnectionUri') {
        $hostname = $null; $uri = $null; $user = $null; $port = $null

        if ($cmd -match "WindowTitle\s*=\s*'([^']+)'") { $hostname = $Matches[1] }
        if ($cmd -match "ConnectionUri\s+'([^']+)'") {
            $uri = $Matches[1]
            if ($uri -match ':(\d+)') { $port = [int]$Matches[1] }
        }
        if ($cmd -match "PSCredential\s*\(\s*\(?'([^']+)'") { $user = $Matches[1] }

        if ($uri) {
            $sessions += [PSCustomObject]@{
                Hostname = $hostname
                Uri      = $uri
                Port     = $port
                Username = $user
                PID      = $_.ProcessId
            }
        }
    }
}

$sessions | ConvertTo-Json -Compress
