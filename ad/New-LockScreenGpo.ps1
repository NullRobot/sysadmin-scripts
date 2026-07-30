<#
.SYNOPSIS
    Builds a complete fleet-wide branded lock screen GPO from scratch: stages the
    image on SYSVOL, sets the policy values, creates the GPP Files preference that
    copies the image locally, registers the CSEs, bumps the version, links the OUs.

.DESCRIPTION
    Windows Pro cannot use LockScreenImage from an UNC path reliably, so the working
    pattern is two-part: a GPP Files preference copies the image from SYSVOL to a
    fixed local path on every machine, and the Personalization policy points at that
    local path. This script builds the whole thing programmatically:

      A. Copies -ImagePath into <SYSVOL>\<domain>\GPOFiles\Wallpaper\
      B. Creates (or reuses) the GPO
      C. Sets the registry policies: LockScreenImage, NoChangingLockScreen,
         LockScreenOverlaysDisabled, DisableAcrylicBackgroundOnLogon (keeps help
         text sharp on the sign-in screen), DisableWindowsSpotlightOnLockScreen,
         DisableThirdPartySuggestions
      D. Writes the GPP Files.xml preference (action=Replace, bypassErrors)
      E. MERGES the Files CSE GUID pair into gPCMachineExtensionNames without
         clobbering the Registry CSE that Set-GPRegistryValue already added
      F. Bumps the COMPUTER half (upper 16 bits) of the GPO version in both
         GPT.INI and the AD versionNumber attribute
      G. Links the GPO to each -TargetOU
      H. Prints a full verification report

    Run on a DC as a domain admin (GroupPolicy + ActiveDirectory modules).
    Existing signed-in sessions keep the old lock screen until LogonUI restarts
    (sign-out or reboot); the policy applies cleanly at next boot.

.PARAMETER GpoName
    Display name for the GPO (created if missing).

.PARAMETER ImagePath
    Path to the source PNG/JPG (local to the DC or UNC).

.PARAMETER TargetOU
    One or more OU distinguished names to link the GPO to.

.PARAMETER LocalImagePath
    Where the image lands on each endpoint. Default C:\ProgramData\OrgBranding\LockScreen.png.

.EXAMPLE
    .\New-LockScreenGpo.ps1 -GpoName 'Org Lock Screen' -ImagePath C:\Temp\lockscreen.png `
        -TargetOU 'OU=Workstations,DC=corp,DC=example,DC=com'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$GpoName,
    [Parameter(Mandatory)][string]$ImagePath,
    [Parameter(Mandatory)][string[]]$TargetOU,
    [string]$LocalImagePath = 'C:\ProgramData\OrgBranding\LockScreen.png'
)

$ErrorActionPreference = 'Stop'
Import-Module GroupPolicy -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

$domain = (Get-ADDomain).DNSRoot
$domainDn = (Get-ADDomain).DistinguishedName
$imgName = Split-Path $ImagePath -Leaf

# --- Step A: stage image on SYSVOL ---
Write-Host "===== Staging image on SYSVOL ====="
$sysvolDir = "\\$domain\SYSVOL\$domain\GPOFiles\Wallpaper"
if (-not (Test-Path $sysvolDir)) { New-Item -ItemType Directory -Path $sysvolDir -Force | Out-Null }
$sysvolImg = Join-Path $sysvolDir $imgName
Copy-Item -Path $ImagePath -Destination $sysvolImg -Force
Get-Item $sysvolImg | Format-Table Name, Length, LastWriteTime -AutoSize

# --- Step B: create/get GPO ---
Write-Host "===== Creating GPO '$GpoName' ====="
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if ($gpo) { Write-Host "  GPO already exists: $($gpo.Id)" }
else {
    $gpo = New-GPO -Name $GpoName -Comment 'Branded lock screen: GPP Files copies image locally, Personalization policy points at it.'
    Write-Host "  Created: $($gpo.Id)"
}

# --- Step C: registry policies ---
Write-Host "===== Setting registry policy values ====="
$regSets = @(
    @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Value='LockScreenImage';                    Type='String'; Data=$LocalImagePath }
    @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Value='NoChangingLockScreen';               Type='DWord';  Data=1 }
    @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Value='LockScreenOverlaysDisabled';         Type='DWord';  Data=1 }
    @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\System';          Value='DisableAcrylicBackgroundOnLogon';    Type='DWord';  Data=1 }
    @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent';    Value='DisableWindowsSpotlightOnLockScreen';Type='DWord';  Data=1 }
    @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent';    Value='DisableThirdPartySuggestions';       Type='DWord';  Data=1 }
)
foreach ($r in $regSets) {
    Set-GPRegistryValue -Name $GpoName -Key $r.Key -ValueName $r.Value -Type $r.Type -Value $r.Data | Out-Null
    Write-Host ("  set {0}\{1} = {2} ({3})" -f $r.Key, $r.Value, $r.Data, $r.Type)
}

# --- Step D: GPP Files preference (copies SYSVOL image to the local path) ---
Write-Host "===== Creating GPP Files preference ====="
$gpoFolder = "\\$domain\SYSVOL\$domain\Policies\{$($gpo.Id)}"
$machinePrefDir = Join-Path $gpoFolder 'Machine\Preferences\Files'
if (-not (Test-Path $machinePrefDir)) { New-Item -ItemType Directory -Path $machinePrefDir -Force | Out-Null }
$filesXmlPath = Join-Path $machinePrefDir 'Files.xml'
$localLeaf = Split-Path $LocalImagePath -Leaf
$uid = "{$([guid]::NewGuid().ToString().ToUpper())}"
$now = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
$filesXml = @"
<?xml version="1.0" encoding="UTF-8"?>
<Files clsid="{215B2E53-57CE-475c-80FE-9EEC14635851}">
    <File clsid="{50BE44C8-567A-4ed1-B1D0-9234FE1F38AF}" name="$localLeaf" status="$localLeaf" image="2" changed="$now" uid="$uid" bypassErrors="1">
        <Properties action="R" fromPath="$sysvolImg" targetPath="$LocalImagePath" readOnly="0" archive="1" hidden="0" suppress="1" executable="0" />
    </File>
</Files>
"@
Set-Content -Path $filesXmlPath -Value $filesXml -Encoding UTF8 -Force
Write-Host "  Wrote $filesXmlPath"

# --- Step E: merge Files CSE into gPCMachineExtensionNames (preserve existing CSEs) ---
Write-Host "===== Registering Files CSE on GPO ====="
$filesCSE  = '{7150F9BF-48AD-4da4-A49C-29EF4A8369BA}'   # Files preference CSE
$filesTool = '{3BAE7E51-E3F4-41D0-853D-9BB9FD47605F}'   # GPMC tool extension
$gpoAd = Get-ADObject -Identity "CN={$($gpo.Id)},CN=Policies,CN=System,$domainDn" -Properties gPCMachineExtensionNames
$current = $gpoAd.gPCMachineExtensionNames
Write-Host "  current: $current"

# Parse the [{cse}{tool}...][{cse}...] format into blocks, add ours, rebuild sorted
$blocks = @{}
if ($current) {
    foreach ($m in [regex]::Matches($current, '\[(\{[^\]]+)\]')) {
        $guids = [regex]::Matches($m.Groups[1].Value, '\{[A-F0-9\-]+\}') | ForEach-Object { $_.Value }
        if ($guids.Count -gt 0) {
            $cse = $guids[0]
            if (-not $blocks.ContainsKey($cse)) { $blocks[$cse] = New-Object System.Collections.Generic.HashSet[string] }
            if ($guids.Count -gt 1) { foreach ($t in $guids[1..($guids.Count - 1)]) { $blocks[$cse].Add($t) | Out-Null } }
        }
    }
}
if (-not $blocks.ContainsKey($filesCSE)) { $blocks[$filesCSE] = New-Object System.Collections.Generic.HashSet[string] }
$blocks[$filesCSE].Add($filesTool) | Out-Null
$newValue = (($blocks.Keys | Sort-Object) | ForEach-Object { "[$_$((($blocks[$_] | Sort-Object) -join ''))]" }) -join ''
Write-Host "  new:     $newValue"
Set-ADObject -Identity $gpoAd.DistinguishedName -Replace @{ gPCMachineExtensionNames = $newValue }

# --- Step F: bump the COMPUTER half of the GPO version ---
Write-Host "===== Bumping GPO version ====="
$gptIni = Join-Path $gpoFolder 'GPT.INI'
$iniContent = Get-Content $gptIni
$verLine = $iniContent | Where-Object { $_ -match '^Version=' }
if ($verLine -match '^Version=(\d+)') {
    $oldVer = [int]$Matches[1]
    # Computer version is the upper 16 bits, User the lower 16
    $userVer = $oldVer -band 0xFFFF
    $compVer = ($oldVer -shr 16) + 1
    $newVer = ($compVer -shl 16) -bor $userVer
    Set-Content -Path $gptIni -Value ($iniContent -replace '^Version=.*', "Version=$newVer") -Force
    Set-ADObject -Identity $gpoAd.DistinguishedName -Replace @{ versionNumber = $newVer }
    Write-Host "  bumped Version $oldVer -> $newVer (GPT.INI + AD)"
}

# --- Step G: link to OUs ---
Write-Host "===== Linking GPO to OUs ====="
foreach ($ou in $TargetOU) {
    try {
        $link = Get-GPInheritance -Target $ou | Select-Object -ExpandProperty GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }
        if ($link) { Write-Host "  Already linked: $ou" }
        else {
            New-GPLink -Name $GpoName -Target $ou -LinkEnabled Yes -Enforced No | Out-Null
            Write-Host "  Linked to: $ou"
        }
    } catch {
        Write-Host "  ERROR linking to $ou : $($_.Exception.Message)"
    }
}

# --- Step H: verification report ---
Write-Host "`n===== Final verification report ====="
$gpoFinal = Get-GPO -Name $GpoName
Write-Host "GPO: $($gpoFinal.DisplayName)  Id=$($gpoFinal.Id)  Status=$($gpoFinal.GpoStatus)  CompVer=$($gpoFinal.Computer.DSVersion)/$($gpoFinal.Computer.SysvolVersion)"
foreach ($r in $regSets) {
    try {
        $v = Get-GPRegistryValue -Name $GpoName -Key $r.Key -ValueName $r.Value -ErrorAction Stop
        "  OK    $($r.Key)\$($r.Value) = $($v.Value)"
    } catch { "  MISS  $($r.Key)\$($r.Value)" }
}
foreach ($ou in $TargetOU) {
    $link = Get-GPInheritance -Target $ou | Select-Object -ExpandProperty GpoLinks | Where-Object { $_.DisplayName -eq $GpoName }
    if ($link) { "  OK    linked $ou (Enabled=$($link.Enabled))" } else { "  MISS  link $ou" }
}
Write-Host "`nTest on one machine: gpupdate /force, sign out, lock screen should show the image."
