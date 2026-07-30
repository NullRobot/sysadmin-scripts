<#
.SYNOPSIS
    Programmatically attaches a PowerShell computer startup script to an existing GPO,
    without touching the GPMC UI.

.DESCRIPTION
    Deploying settings via GPP Scheduled Tasks XML is brittle (malformed XML fails
    silently). The rock-solid alternative is the Startup Scripts CSE: the script runs at
    every boot as SYSTEM, and whatever it configures (e.g. Register-ScheduledTask) is
    self-healing because the next boot re-applies it.

    This script does everything a GPMC "add startup script" click does:
      1. Writes the .ps1 into the GPO's SYSVOL folder (Machine\Scripts\Startup)
      2. Writes/updates scripts.ini (Unicode, Hidden attribute) listing the script
      3. Merges the Scripts CSE GUID pair into gPCMachineExtensionNames on the GPO's
         AD object (preserving any CSEs already registered) and bumps versionNumber
      4. Bumps the GPT.INI version so clients notice the change

    Run on a domain controller (or any box with the GroupPolicy + ActiveDirectory
    modules and SYSVOL write access) as a domain admin.

    NOTE: PowerShell startup scripts registered via scripts.ini run through the
    legacy Scripts CSE; the file listed in scripts.ini is executed with
    powershell.exe by the CSE when it has a .ps1 extension on modern Windows.
    Test on one machine (gpupdate /force + reboot) before scoping wide.

.PARAMETER GpoName
    Display name of the EXISTING GPO to attach the script to.

.PARAMETER ScriptFile
    Local path of the .ps1 to deploy as the startup script.

.PARAMETER Domain
    DNS name of the domain. Default: current machine's domain.

.EXAMPLE
    .\Add-GpoStartupScript.ps1 -GpoName 'Workstation Cleanup' -ScriptFile C:\temp\bootstrap.ps1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$GpoName,
    [Parameter(Mandatory)][string]$ScriptFile,
    [string]$Domain = $env:USERDNSDOMAIN
)

$ErrorActionPreference = 'Stop'
Import-Module GroupPolicy -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path $ScriptFile)) { throw "Script file not found: $ScriptFile" }
$scriptName = Split-Path $ScriptFile -Leaf

$gpo = Get-GPO -Name $GpoName -ErrorAction Stop
$gpoGuid = $gpo.Id.ToString().ToUpper()
Write-Host "GPO '$GpoName' = {$gpoGuid}"

$gpoSysvol     = "\\${Domain}\SYSVOL\${Domain}\Policies\{${gpoGuid}}"
$machineScripts = "${gpoSysvol}\Machine\Scripts"
$startupDir    = "${machineScripts}\Startup"
$scriptDest    = Join-Path $startupDir $scriptName
$scriptsIni    = Join-Path $machineScripts 'scripts.ini'

# --- 1. Stage the script in SYSVOL ---
New-Item -ItemType Directory -Path $startupDir -Force | Out-Null
Copy-Item -Path $ScriptFile -Destination $scriptDest -Force
Write-Host "Staged $scriptDest"

# --- 2. Write/merge scripts.ini ---
$existingEntries = @()
if (Test-Path $scriptsIni) {
    $iniRaw = Get-Content $scriptsIni -Raw
    # Collect existing CmdLine entries in the [Startup] section so we append, not clobber
    $existingEntries = [regex]::Matches($iniRaw, '(?m)^\d+CmdLine=(.+)$') | ForEach-Object { $_.Groups[1].Value.Trim() }
}
if ($existingEntries -notcontains $scriptName) {
    $allEntries = @($existingEntries) + $scriptName
} else {
    $allEntries = @($existingEntries)
    Write-Host "scripts.ini already lists $scriptName"
}
$lines = @('[Startup]')
for ($i = 0; $i -lt $allEntries.Count; $i++) {
    $lines += "${i}CmdLine=$($allEntries[$i])"
    $lines += "${i}Parameters="
}
# scripts.ini must be Unicode and carries the Hidden attribute
if (Test-Path $scriptsIni) { (Get-Item $scriptsIni -Force).Attributes = 'Normal' }
($lines -join "`r`n") | Set-Content -Path $scriptsIni -Encoding Unicode
(Get-Item $scriptsIni -Force).Attributes = 'Hidden'
Write-Host "Wrote scripts.ini with $($allEntries.Count) startup entr$(if ($allEntries.Count -eq 1) {'y'} else {'ies'})"

# --- 3. Merge Scripts CSE GUIDs into gPCMachineExtensionNames + bump versionNumber ---
# Scripts CSE:          {42B5FAAE-6536-11d2-AE5A-0000F87571E3}
# Scripts tool snap-in: {40B6664F-4972-11D1-A7CA-0000F87571E3}
$csePair = '[{42B5FAAE-6536-11d2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
$domainDn = (Get-ADDomain -Server $Domain).DistinguishedName
$gpoDn = "CN={${gpoGuid}},CN=Policies,CN=System,${domainDn}"
$gpoAdObject = Get-ADObject -Identity $gpoDn -Properties gPCMachineExtensionNames, versionNumber

$extNames = $gpoAdObject.gPCMachineExtensionNames
if ($extNames -notmatch '42B5FAAE-6536-11d2-AE5A-0000F87571E3') {
    # Merge, keeping the bracketed pairs sorted by first GUID as Windows expects
    $pairs = @()
    if ($extNames) { $pairs = [regex]::Matches($extNames, '\[[^\]]+\]') | ForEach-Object { $_.Value } }
    $pairs += $csePair
    $newExt = ($pairs | Sort-Object) -join ''
} else {
    $newExt = $extNames
    Write-Host "Scripts CSE already registered on the GPO"
}
# Machine-side change: bump the LOWER 16 bits of versionNumber
Set-ADObject -Identity $gpoDn -Replace @{
    gPCMachineExtensionNames = $newExt
    versionNumber            = ($gpoAdObject.versionNumber + 1)
}
Write-Host "Updated gPCMachineExtensionNames and bumped versionNumber to $($gpoAdObject.versionNumber + 1)"

# --- 4. Bump GPT.INI so clients pull the new version ---
$gptIni = Join-Path $gpoSysvol 'GPT.INI'
if (Test-Path $gptIni) {
    $iniText = Get-Content $gptIni -Raw
    if ($iniText -match 'Version=(\d+)') {
        $newVer = [int]$Matches[1] + 1
        $iniText = $iniText -replace 'Version=\d+', "Version=$newVer"
        $iniText | Set-Content -Path $gptIni -Encoding ASCII
        Write-Host "Bumped GPT.INI version to $newVer"
    }
} else {
    Write-Warning "GPT.INI not found at $gptIni - clients may not detect the change until AD/SYSVOL versions align"
}

Write-Host ""
Write-Host "Done. Verify on one target machine:"
Write-Host "  gpupdate /force, then reboot (startup scripts only fire at boot)"
Write-Host "  gpresult /h report.html  -> confirm the script shows under Computer > Policies > Scripts"
