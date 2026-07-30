<#
.SYNOPSIS
    Read-only workstation diagnostic for logon / drive-map / folder-redirection / connectivity issues.
.DESCRIPTION
    Run as SYSTEM (Datto RMM) or admin. The broad first pass when a user reports missing desktop
    icons, drives not mapping, redirected folders pointing at the wrong place, or "can't reach the
    server." For each loaded user profile it reports the shell-folder targets (Desktop/Documents/AppData),
    persistent mapped drives, and network printer connections. Then it tests connectivity to a file
    server (DNS + ping + TCP 445 + current SMB sessions), and pulls the relevant event logs since a
    cutoff: Folder Redirection, SMB client, Group Policy, DNS client, System errors/criticals, and
    Netlogon/no-DC events. Finishes with Offline Files service state and any NIC set to power off.
    Changes nothing.
.PARAMETER FileServer
    Server name to test connectivity against (the one the user's drives/redirection point at).
.PARAMETER Days
    Event-log look-back window. Default 8.
.NOTES
    Remember commands run as SYSTEM: user paths come from the profile, not $env:USERPROFILE.
#>
[CmdletBinding()]
param(
    [string]$FileServer,
    [int]$Days = 8
)

$ErrorActionPreference = 'Continue'
$since = (Get-Date).AddDays(-$Days)

$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
Write-Output "=== $env:COMPUTERNAME | $($os.Caption) $($os.Version) | Domain: $($cs.Domain) ==="

Write-Output "`n=== LOGGED-IN USER PROFILES (loaded, non-special) ==="
$null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue
foreach ($p in (Get-CimInstance Win32_UserProfile | Where-Object { $_.Loaded -and -not $_.Special })) {
    $sid = $p.SID
    Write-Output "Profile: $($p.LocalPath)  SID: $sid"
    try {
        $usf = Get-ItemProperty "HKU:\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -ErrorAction Stop
        Write-Output "  Desktop  = $($usf.Desktop)"
        Write-Output "  Personal = $($usf.Personal)"
        Write-Output "  AppData  = $($usf.AppData)"
    } catch { Write-Output "  (cannot read shell folders: $($_.Exception.Message))" }
    Write-Output "  Mapped drives:"
    Get-ChildItem "HKU:\$sid\Network" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "    $($_.PSChildName): -> $((Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).RemotePath)"
    }
    Write-Output "  Network printers:"
    Get-ChildItem "HKU:\$sid\Printers\Connections" -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "    $($_.PSChildName -replace ',','\')" }
}

if ($FileServer) {
    Write-Output "`n=== SERVER CONNECTIVITY: $FileServer ==="
    try { Write-Output "DNS: $(([System.Net.Dns]::GetHostAddresses($FileServer) | ForEach-Object { $_.IPAddressToString }) -join ', ')" }
    catch { Write-Output "DNS FAILED: $($_.Exception.Message)" }
    $tnc = Test-NetConnection -ComputerName $FileServer -Port 445 -WarningAction SilentlyContinue
    Write-Output "Ping: $($tnc.PingSucceeded) | TCP 445: $($tnc.TcpTestSucceeded)"
    Write-Output "Current SMB connections:"
    Get-SmbConnection -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "  \\$($_.ServerName)\$($_.ShareName) as $($_.UserName) (dialect $($_.Dialect))" }
}

Write-Output "`n=== EVENT LOGS since $($since.ToString('MM/dd')) ==="
$logs = @(
    @{ n='FolderRedirection';       log='Microsoft-Windows-Folder Redirection/Operational'; lvl=@(1,2,3) },
    @{ n='SMBClient-Connectivity';  log='Microsoft-Windows-SmbClient/Connectivity';        lvl=@(1,2,3) },
    @{ n='GroupPolicy';             log='Microsoft-Windows-GroupPolicy/Operational';       lvl=@(1,2)   },
    @{ n='DNS-Client';              log='Microsoft-Windows-DNS-Client/Operational';        lvl=@(1,2,3) }
)
foreach ($l in $logs) {
    Write-Output "--- $($l.n) ---"
    try {
        Get-WinEvent -FilterHashtable @{LogName=$l.log; Level=$l.lvl; StartTime=$since} -MaxEvents 30 -ErrorAction Stop |
            ForEach-Object { "{0:MM/dd HH:mm} [{1}] {2}" -f $_.TimeCreated, $_.Id, (($_.Message -split "`r?`n")[0]) }
    } catch { Write-Output "  (none / log absent)" }
}
Write-Output "--- System errors/criticals (top sources) ---"
try {
    Get-WinEvent -FilterHashtable @{LogName='System'; Level=@(1,2); StartTime=$since} -ErrorAction Stop |
        Group-Object ProviderName, Id | Sort-Object Count -Descending | Select-Object -First 15 |
        ForEach-Object { "{0,4}x  {1}" -f $_.Count, $_.Name }
} catch { Write-Output "  (none)" }
Write-Output "--- Netlogon / no-DC / unexpected shutdown ---"
try {
    Get-WinEvent -FilterHashtable @{LogName='System'; Id=@(5719,5783,6008,41); StartTime=$since} -ErrorAction Stop |
        ForEach-Object { "{0:MM/dd HH:mm} [{1}] {2}" -f $_.TimeCreated, $_.Id, (($_.Message -split "`r?`n")[0]) }
} catch { Write-Output "  (none)" }

Write-Output "`n=== OFFLINE FILES / NIC POWER ==="
$csc = Get-Service CscService -ErrorAction SilentlyContinue
Write-Output "CscService (Offline Files): $($csc.Status) / $($csc.StartType)"
Get-NetAdapterPowerManagement -ErrorAction SilentlyContinue | Where-Object { $_.AllowComputerToTurnOffDevice -eq 'Enabled' } |
    ForEach-Object { Write-Output "WARN: '$($_.Name)' allows Windows to power off the NIC" }
Write-Output "`n=== DONE ==="
