<#
.SYNOPSIS
    Figures out WHAT is blocking access to (or deletion of) a file when normal
    tools just say "Access is denied".

.DESCRIPTION
    Works through every layer that can silently block file operations:
      1. Loaded minifilter drivers (fltmc) - EDR/AV file protection lives here
      2. NTFS ACL on the file and its parent directory (icacls)
      3. Alternate Data Streams on the file (forensic markers, Zone.Identifier)
      4. Reparse-point state on the parent directory
      5. AppLocker effective policy + a Test-AppLockerPolicy check for the file
      6. WDAC / code-integrity policies (CITool, Win11 22H2+)
      7. Microsoft Defender state, threat history mentioning the path, and any
         third-party AV registered in SecurityCenter2
      8. Optionally (-TryDelete) attempts a direct .NET delete and reports the
         exact exception type, which usually names the layer responsible

    Read-only except for the opt-in -TryDelete. Run as SYSTEM or admin.

.PARAMETER Path
    The file being blocked.

.PARAMETER TryDelete
    Attempt [System.IO.File]::Delete() at the end and report the raw exception.

.EXAMPLE
    .\Get-FileBlockerDiagnostics.ps1 -Path 'C:\Program Files (x86)\App\stuck.dll'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Path,

    [switch]$TryDelete
)

$ErrorActionPreference = 'Continue'
$dir = Split-Path $Path -Parent

Write-Output "==== Target ===="
Write-Output "  File:   $Path  (exists: $(Test-Path -LiteralPath $Path))"
Write-Output "  Parent: $dir"
Write-Output ""

Write-Output "==== 1. Loaded minifilter drivers (EDR/AV file protection lives here) ===="
& fltmc.exe filters 2>&1 | Out-String
Write-Output ""

Write-Output "==== 2. ACL on the file ===="
if (Test-Path -LiteralPath $Path) { & icacls.exe $Path 2>&1 | Out-String } else { Write-Output "  (file gone)" }
Write-Output ""
Write-Output "==== 2b. ACL on the parent directory ===="
& icacls.exe $dir 2>&1 | Out-String
Write-Output ""

Write-Output "==== 3. Alternate Data Streams on the file ===="
$streams = Get-Item -LiteralPath $Path -Stream * -ErrorAction SilentlyContinue
$streams | Select-Object Stream, Length | Format-Table -AutoSize
$nonDefault = $streams | Where-Object { $_.Stream -ne ':$DATA' }
if ($nonDefault) { Write-Output "  >>> Non-default streams present (possible AV/EDR forensic markers)" }
Write-Output ""

Write-Output "==== 4. Reparse point check on the parent directory ===="
$rp = & fsutil.exe reparsepoint query $dir 2>&1
Write-Output "  $rp"
Write-Output ""

Write-Output "==== 5. AppLocker effective policy ===="
try {
    $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
    if ($policy) {
        $xml = $policy.ToXml()
        if ($xml.Length -gt 200) {
            Write-Output "  AppLocker is ACTIVE. Policy length: $($xml.Length) chars"
            $policy.RuleCollections | ForEach-Object {
                Write-Output "    $($_.RuleCollectionType): EnforcementMode=$($_.EnforcementMode), $($_.Count) rules"
            }
            Write-Output ""
            Write-Output "  Test: is the target file allowed for SYSTEM?"
            $test = Test-AppLockerPolicy -Path $Path -PolicyObject $policy -User 'NT AUTHORITY\SYSTEM' -ErrorAction SilentlyContinue
            $test | Format-List PolicyDecision, MatchingRule, FilePath
        } else {
            Write-Output "  AppLocker policy is empty (not enforcing)"
        }
    } else {
        Write-Output "  No AppLocker policy"
    }
} catch {
    Write-Output "  AppLocker check error: $($_.Exception.Message)"
}
Write-Output ""

Write-Output "==== 6. WDAC / code integrity policies (CITool, Win11 22H2+) ===="
try {
    $ci = & CITool.exe -lp 2>&1
    Write-Output ($ci | Out-String)
} catch {
    Write-Output "  CITool.exe not available: $($_.Exception.Message)"
}
Write-Output ""

Write-Output "==== 7. Microsoft Defender status ===="
try {
    Get-MpComputerStatus -ErrorAction Stop |
        Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled,
                      BehaviorMonitorEnabled, OnAccessProtectionEnabled, AMRunningMode, AMProductVersion |
        Format-List
} catch {
    Write-Output "  Defender cmdlets unavailable: $($_.Exception.Message)"
}

Write-Output "==== 7b. Defender threat history mentioning the path ===="
try {
    $needle = Split-Path (Split-Path $Path -Parent) -Leaf
    $threats = Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.Resources -like "*${needle}*" }
    if ($threats) {
        $threats | Select-Object DetectionID, ThreatID, ProcessName, Resources, ActionSuccess | Format-List
    } else {
        Write-Output "  No related threat detections in Defender"
    }
} catch {
    Write-Output "  Could not read threat history: $($_.Exception.Message)"
}
Write-Output ""

Write-Output "==== 7c. Registered AV products (SecurityCenter2) ===="
Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntivirusProduct -ErrorAction SilentlyContinue |
    Select-Object displayName, productState, pathToSignedReportingExe |
    Format-List

if ($TryDelete) {
    Write-Output "==== 8. Direct .NET delete attempt (exception names the blocking layer) ===="
    try {
        [System.IO.File]::SetAttributes($Path, [System.IO.FileAttributes]::Normal)
        [System.IO.File]::Delete($Path)
        Write-Output "  DELETED via .NET: $Path"
    } catch {
        Write-Output "  .NET delete failed: $($_.Exception.GetType().Name) - $($_.Exception.Message)"
        if ($_.Exception.InnerException) {
            Write-Output "  Inner: $($_.Exception.InnerException.Message)"
        }
        Write-Output "  Next steps: rename the file instead of deleting (bypasses delete ACL),"
        Write-Output "  or queue it via PendingFileRenameOperations (see Add-PendingFileDeleteOnBoot.ps1)."
    }
}
