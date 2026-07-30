#Requires -Version 5.1
<#
.SYNOPSIS
    Disables CLIENT-SIDE RDP printer redirection on one workstation - the fix for
    mstsc.exe 0xc0000005 crashes caused by a local printer driver's UI DLL.

.DESCRIPTION
    Known failure mode: mstsc.exe crashes (Event 1000, exception 0xc0000005, often
    faulting in ntdll) when connecting to an RDS host or printing from a RemoteApp.
    The WER loaded-module list is full of LOCAL print-driver UI/config DLLs (PS5UI.DLL,
    ADUIGP.DLL, PrintConfig.dll, prntvpt.dll, mxdwdrv.dll, or a vendor UI DLL). Cause:
    at connect-time enumeration mstsc LoadLibrary's each redirected local printer's
    native UI DLL into itself; a bad one corrupts mstsc's heap. With ZERO local
    printers redirected that code path never runs, so the crash cannot fire.

    This sets DisablePrinterRedirection=1 in BOTH client keys:
      HKLM\Software\Microsoft\Terminal Server Client   (modern mstsc - load-bearing;
        MS-documented for disabling redirection on a specific local device)
      HKLM\Software\Microsoft\Terminal Server          (legacy ActiveX path)

    Redirection is "most restrictive wins", so this client-side denial overrides a
    signed .rdp's redirectprinters:i:1 WITHOUT editing the file (no signature break),
    and touches nothing server-side, so other users are unaffected. No reboot needed;
    the user must fully log off / relaunch the connection (not just reconnect).

    Also drops a breadcrumb value explaining WHY, because the MS troubleshooting
    article tells techs to delete this value to "restore missing redirected printers",
    which would re-arm the crash.

    VERIFY after relaunch: in the user's remote session, Get-Printer should show ZERO
    'Remote Desktop Easy Print' printers. Give the user a server-side queue for their
    physical printer first if they need to print.

    Run as SYSTEM/admin (writes HKLM). Idempotent. -Revert undoes it.

.PARAMETER Revert
    Re-enable client printer redirection (sets both values to 0, removes breadcrumb).

.PARAMETER BreadcrumbNote
    Text stored next to the value explaining why it is set. Customize with your
    ticket number / contact.

.EXAMPLE
    .\Disable-RdpClientPrinterRedirection.ps1 -BreadcrumbNote 'Ticket 12345 - stops mstsc crash; do not delete. Contact IT.'
#>
[CmdletBinding()]
param(
  [switch]$Revert,
  [string]$BreadcrumbNote = 'INTENTIONAL - stops mstsc 0xc0000005 crash from local printer-driver UI DLL load during redirection enumeration. Do NOT delete to "fix" missing redirected printers; give the user a server-side queue instead.'
)

$ErrorActionPreference = 'Stop'

# "Terminal Server Client" is the modern mstsc client key (the load-bearing one).
# "Terminal Server" is the legacy ActiveX-control key. Set BOTH so no path re-enables it.
$targets = @(
  'HKLM:\Software\Microsoft\Terminal Server Client',
  'HKLM:\Software\Microsoft\Terminal Server'
)

$desired = if ($Revert) { 0 } else { 1 }

foreach ($key in $targets) {
  if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
  New-ItemProperty -Path $key -Name 'DisablePrinterRedirection' -Value $desired -PropertyType DWord -Force | Out-Null
  $val = (Get-ItemProperty -Path $key -Name 'DisablePrinterRedirection').DisablePrinterRedirection
  Write-Output ("{0}\DisablePrinterRedirection = {1}" -f $key, $val)
}

$noteKey = 'HKLM:\Software\Microsoft\Terminal Server Client'
if ($Revert) {
  Remove-ItemProperty -Path $noteKey -Name 'DisablePrinterRedirection_Reason' -ErrorAction SilentlyContinue
  Write-Output "REVERTED: client printer redirection re-enabled on this machine. Next RDP/RemoteApp launch will redirect local printers again (the crash trigger returns if the bad driver is still installed)."
} else {
  New-ItemProperty -Path $noteKey -Name 'DisablePrinterRedirection_Reason' -Value $BreadcrumbNote -PropertyType String -Force | Out-Null
  Write-Output "DONE: client printer redirection disabled on $env:COMPUTERNAME."
  Write-Output "ACTION: have the user CLOSE every RDP/RemoteApp window (full logoff, not just disconnect) and relaunch so the new connection reads the value."
  Write-Output "VERIFY: in their next remote session, Get-Printer must show ZERO 'Remote Desktop Easy Print' printers."
}
