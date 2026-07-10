# sysadmin-scripts

A collection of practical PowerShell and shell scripts for Windows, Active Directory,
Microsoft 365, Azure, and endpoint administration, drawn from real day-to-day IT work and
cleaned up to be reusable. Every script is parameterized (no hardcoded environments), carries
usage documentation, and is safe to drop into your own setup after a quick read of its header.

Nothing here is tied to a specific organization. Review and test any script in a non-production
environment before running it against live systems.

## Scripts

### Active Directory & GPO

| Script | What it does |
|---|---|
| [`Check-AD-Health.ps1`](ad/Check-AD-Health.ps1) | Runs a quick Active Directory health sweep: DC reachability/LDAP/SYSVOL/NETLOGON, FSMO role holders, replication errors, inactive/disabled accounts, and DNS test. |
| [`Find-SlowGPOs.ps1`](ad/Find-SlowGPOs.ps1) | Scans all GPOs in a domain and flags settings known to cause slow logon/boot (sync scripts, software install, folder redirection, WMI filters, roaming profiles, etc.), then exports a scored CSV report. |

### Exchange Online & Microsoft 365

| Script | What it does |
|---|---|
| [`Find-SuspiciousInboxRules.ps1`](exchange-m365/Find-SuspiciousInboxRules.ps1) | Read-only Exchange Online scan that flags inbox rules and forwarding commonly used to hide mail during a business email compromise. |
| [`Get-MailboxRetentionAndSizeReport.ps1`](exchange-m365/Get-MailboxRetentionAndSizeReport.ps1) | Reports Exchange Online mailbox retention/MFA (Managed Folder Assistant) settings, primary and archive mailbox sizes, and ELC diagnostic log properties for a given user. |
| [`Revoke-UserSignInSessions.ps1`](exchange-m365/Revoke-UserSignInSessions.ps1) | Revokes all active Microsoft 365 sign-in sessions/refresh tokens for a compromised user account via Microsoft Graph, for incident containment after a password/MFA reset. |
| [`diagnose-m365-group-reply-failure.ps1`](exchange-m365/diagnose-m365-group-reply-failure.ps1) | Diagnoses why a user can't reply-all/reply to a Microsoft 365 Group in Outlook/OWA by checking group type, membership/owners, inbox rules, retention/MRM, and Send As / Send on Behalf permissions. |

### Azure

| Script | What it does |
|---|---|
| [`test-subscription-arm-access.ps1`](azure/test-subscription-arm-access.ps1) | Tests whether the current cached Az context can directly read a given Azure subscription via ARM, useful for diagnosing CSP/Lighthouse/guest-tenant access issues. |

### Windows Endpoint

| Script | What it does |
|---|---|
| [`Add-CookieExceptionForDomain.ps1`](windows-endpoint/Add-CookieExceptionForDomain.ps1) | Adds a browser policy cookie exception (Chrome/Edge) for a given domain so a site's session survives "clear cookies on exit" GPO settings. |
| [`Get-ArelliaAgentDiagnostics.ps1`](windows-endpoint/Get-ArelliaAgentDiagnostics.ps1) | Pulls and summarizes the Ivanti/Arellia EPM agent event log to help diagnose sync or certificate/TLS failures. |
| [`Get-DelineaEpmAgentState.ps1`](windows-endpoint/Get-DelineaEpmAgentState.ps1) | Read-only diagnostic that dumps Delinea/Thycotic EPM agent service state, registry config, install dirs, and recent log errors to a file for troubleshooting elevation/connectivity issues. |
| [`Get-DiskHealthReport.ps1`](windows-endpoint/Get-DiskHealthReport.ps1) | Read-only Windows disk/SMART/reliability and boot-event health report, with optional filtering for a named application's services after a suspected disk-related outage. |
| [`Get-PostRebootDiagnostics.ps1`](windows-endpoint/Get-PostRebootDiagnostics.ps1) | Read-only post-reboot diagnostic sweep: SCM service failures, NIC/DHCP events, RMM agent health, application errors, and boot-completion time within a given time window. |
| [`Install-LegacyPSModuleFromNupkg.ps1`](windows-endpoint/Install-LegacyPSModuleFromNupkg.ps1) | Manually downloads and unpacks legacy PowerShell Gallery modules (AzureAD, MSOnline) as .nupkg archives when Install-Module isn't available or fails. |
| [`Remove-StaleUserProfiles.ps1`](windows-endpoint/Remove-StaleUserProfiles.ps1) | Deletes local Windows user profiles that haven't been written to in N days (default 30), with CSV-style logging and -WhatIf support. |
| [`Remove-StaticDnsServerEntry.ps1`](windows-endpoint/Remove-StaticDnsServerEntry.ps1) | Finds and removes a specific rogue DNS server (default 8.8.8.8) from a NIC's static config, or reports if it's coming from DHCP instead. |
| [`audit-cygwin-environment.sh`](windows-endpoint/audit-cygwin-environment.sh) | Audits a Cygwin installation on Windows (version, packages, dotfiles, SSH config, cron, tools, mounts, home tree, Python, git repos, X11) and writes reports to a local output directory ahead of a PC migration. |

### Server Hardware

| Script | What it does |
|---|---|
| [`Get-PercRaidHealth.ps1`](server-hardware/Get-PercRaidHealth.ps1) | Downloads Dell's PERCCLI utility and pulls controller, physical drive, and virtual drive health from a PERC RAID controller (read-only). |

### Datto RMM

| Script | What it does |
|---|---|
| [`Discover-AgentBrowserSessions.ps1`](datto-rmm/Discover-AgentBrowserSessions.ps1) | Discovers active local PowerShell remoting (WinRM) sessions on the current machine by scanning running powershell.exe processes for -ConnectionUri, returning hostname/URI/port/username as JSON. |

### macOS

| Script | What it does |
|---|---|
| [`brew-autoupdate.sh`](macos/brew-autoupdate.sh) | Runs brew update and brew upgrade with timestamped log output, meant to be run periodically (e.g. via cron/launchd). |
| [`icloud-stuck-sync-diagnose.sh`](macos/icloud-stuck-sync-diagnose.sh) | Diagnoses and clears a stuck macOS iCloud Drive sync, then reports disk space usage and cleanup options. |
| [`macos-safe-erase-usb.sh`](macos/macos-safe-erase-usb.sh) | Safely erase/format a USB flash drive as exFAT/MBR on macOS with hard guardrails against wiping the internal disk or any large external drive. |

### Misc

| Script | What it does |
|---|---|
| [`Install-M365AdminModules.ps1`](misc/Install-M365AdminModules.ps1) | Installs (or skips if already present) a set of PowerShell modules needed for M365/SharePoint/Partner Center admin work, using the modern PSResourceGet cmdlets when available and falling back to the legacy PowerShellGet/PSGallery path otherwise. |
| [`batch-convert-png-to-jpg.sh`](misc/batch-convert-png-to-jpg.sh) | Recursively finds PNG files and converts them to JPG (quality 25 by default) using ImageMagick, deleting the originals. |

## Usage

Most PowerShell scripts include comment-based help:

```powershell
Get-Help ./ad/Check-AD-Health.ps1 -Full
```

Run with the parameters shown in each script's `.EXAMPLE` block. Scripts that make changes support
`-WhatIf` or prompt for confirmation where practical.

## Disclaimer

Provided as-is, no warranty. Test before running against production. Use at your own risk.

## License

[MIT](LICENSE)
