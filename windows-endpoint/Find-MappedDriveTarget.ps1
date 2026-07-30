<#
.SYNOPSIS
    Resolve the UNC target of a user's mapped drive on a workstation, from every source.
.DESCRIPTION
    Read-only. Run as SYSTEM (Datto RMM) or admin. "What does the user's P: drive actually point at"
    when they aren't sure and it isn't showing while you're in SYSTEM context. Checks three places:
      1. Mapped drives in every currently-loaded user hive (HKU\<SID>\Network).
      2. If the target user isn't logged in, temporarily loads their NTUSER.DAT and reads the same key.
      3. GPP Drives.xml in SYSVOL (covers GPO-mapped drives, which never appear in the user hive).
    Prints every drive-letter -> UNC it finds, tagged by source. Changes nothing (unloads the hive it loads).
.PARAMETER UserName
    The user whose mapped drives you want (used to locate their profile / filter output).
.PARAMETER Domain
    FQDN of the domain, for the SYSVOL GPP sweep. Defaults to the machine's domain.
.NOTES
    The machine account can read SYSVOL, so the GPP portion works even as SYSTEM.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$UserName,
    [string]$Domain = $env:USERDNSDOMAIN
)

$ErrorActionPreference = 'Continue'
$out = @()

# 1. Loaded user hives
Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '_Classes$' } | ForEach-Object {
    $sid = $_.PSChildName
    try { $u = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { $u = $sid }
    $netKey = "Registry::HKEY_USERS\$sid\Network"
    if (Test-Path $netKey) {
        Get-ChildItem $netKey | ForEach-Object {
            $rp = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).RemotePath
            $out += "[loaded] $u  $($_.PSChildName): -> $rp"
        }
    }
}

# 2. Offline hive load if the user isn't logged in
if (-not ($out -match [regex]::Escape($UserName))) {
    $prof = Get-CimInstance Win32_UserProfile | Where-Object { $_.LocalPath -like "*$UserName*" }
    if ($prof) {
        $dat = Join-Path $prof.LocalPath 'NTUSER.DAT'
        reg load "HKU\EscTmp" "$dat" 2>&1 | Out-Null
        if (Test-Path 'Registry::HKEY_USERS\EscTmp\Network') {
            Get-ChildItem 'Registry::HKEY_USERS\EscTmp\Network' | ForEach-Object {
                $rp = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).RemotePath
                $out += "[hive] $UserName  $($_.PSChildName): -> $rp"
            }
        } else { $out += "$UserName hive: no HKU Network key (may be GPO-mapped without reconnect)" }
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        reg unload "HKU\EscTmp" 2>&1 | Out-Null
    } else { $out += "no $UserName profile on this machine" }
}

# 3. GPP drive maps from SYSVOL
Get-ChildItem "\\$Domain\SYSVOL\$Domain\Policies\*\User\Preferences\Drives\Drives.xml" -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $x = [xml](Get-Content $_.FullName -ErrorAction Stop)
        $x.Drives.Drive | ForEach-Object { $out += "[GPP] $($_.Properties.letter): -> $($_.Properties.path)  (GPO $($_.name))" }
    } catch {}
}

if (-not $out) { $out = @('no mapped-drive entries found anywhere') }
$out
