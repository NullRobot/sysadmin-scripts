# sysadmin-scripts

A working library of 97 PowerShell and shell scripts for Windows, Active Directory, Microsoft 365,
Azure, and endpoint administration. These come out of real day-to-day systems administration work and
have been generalized for reuse: every script is parameterized (no hardcoded environments or hostnames),
carries comment-based help, and defaults to read-only or `-WhatIf` where it touches anything.

Maintained by **Cameron Voss** ([@NullRobot](https://github.com/NullRobot)).

Nothing here is tied to any specific organization or customer. Read a script's header, then test it in a
non-production environment before running it against live systems.

## Scripts

### Active Directory & Group Policy

| Script | What it does |
|---|---|
| [`Add-GpoStartupScript.ps1`](ad/Add-GpoStartupScript.ps1) | Programmatically attaches a PowerShell computer startup script to an existing GPO (SYSVOL staging, scripts.ini, CSE merge into gPCMachineExtensionNames, version bump) without GPMC. |
| [`Check-AD-Health.ps1`](ad/Check-AD-Health.ps1) | Quick overall health check against an Active Directory domain (DC diag, replication, SYSVOL, DNS). |
| [`Disable-ReversiblePasswordEncryption.ps1`](ad/Disable-ReversiblePasswordEncryption.ps1) | Clear the domain reversible-encryption bit (pwdProperties 0x10) while leaving complexity intact, with verify. |
| [`Find-AccountLockoutSource.ps1`](ad/Find-AccountLockoutSource.ps1) | Hunts the source of AD account lockouts on a DC: 4776/4771/4625/4740 failure mining with a per-user ranked source summary. |
| [`Find-GpoPathReferences.ps1`](ad/Find-GpoPathReferences.ps1) | Scans all GPO reports for references to a server/share/path string before a file-server migration or decommission. |
| [`Find-GppDriveMapReference.ps1`](ad/Find-GppDriveMapReference.ps1) | Find GPP drive maps and SYSVOL/NETLOGON scripts that reference a dead server/share/UNC string across a domain. |
| [`Find-SlowGPOs.ps1`](ad/Find-SlowGPOs.ps1) | Scans all GPOs in a domain and flags settings known to cause slow logon, boot, or shutdown. |
| [`Find-SmbNamedPipeRecon.ps1`](ad/Find-SmbNamedPipeRecon.ps1) | Detect BloodHound/SharpHound-style AD recon via lsarpc/samr/srvsvc named-pipe triplets in Security 5145. |
| [`Get-AccountLockoutEvents.ps1`](ad/Get-AccountLockoutEvents.ps1) | Trace an account's lockout activity on a DC (4740/4776/4771) to find the source machine spraying a stale password. |
| [`Get-AdfsLockoutActivity.ps1`](ad/Get-AdfsLockoutActivity.ps1) | Investigates an AD FS server's role in a user's lockouts: account activity, AD FS Admin log, local Security log auth failures, relying parties. |
| [`Get-ADPrivilegedAccountAudit.ps1`](ad/Get-ADPrivilegedAccountAudit.ps1) | Read-only audit of privileged group membership, password policy/PSOs, krbtgt age, and DC service accounts. |
| [`Get-ADSecurityPostureReport.ps1`](ad/Get-ADSecurityPostureReport.ps1) | Read-only AD security recon: privileged group membership, stale/suspect accounts, EOL OS inventory, security GPOs, krbtgt age, DCs, trusts; for post-pentest and IR triage. |
| [`Get-DfsrSysvolHealth.ps1`](ad/Get-DfsrSysvolHealth.ps1) | Read-only DFSR SYSVOL health: replication state, StopReplicationOnAutoRecovery, SYSVOL/NETLOGON shares, recent events, VSS pressure, optional GPT.INI version compare across DCs. |
| [`Get-EffectivePasswordPolicy.ps1`](ad/Get-EffectivePasswordPolicy.ps1) | Definitive password-policy report: resultant policy per account, default domain policy, all PSOs, and every GPO that sets MinPwdLength + where it's linked. |
| [`Get-GpoScopeReport.ps1`](ad/Get-GpoScopeReport.ps1) | Read-only reality check on a GPO: does it apply, to whom (security filtering), version DS/SYSVOL sync, and the computer count under each linked OU. |
| [`Get-GppDriveMappings.ps1`](ad/Get-GppDriveMappings.ps1) | Dumps a GPP drive-map GPO's Drives.xml (letter, action, target, remove-policy, item-level targeting); -All walks every Drives.xml in SYSVOL. |
| [`Get-PrivilegedGroupAudit.ps1`](ad/Get-PrivilegedGroupAudit.ps1) | Recursive AD privileged-group membership audit (enabled state, last logon, created, description) plus named-account detail and built-in Administrator status. |
| [`Get-RecentGpoChanges.ps1`](ad/Get-RecentGpoChanges.ps1) | List GPOs modified in the last N days with their links, security filtering, and client-side extensions. |
| [`Get-UserLogonHistory.ps1`](ad/Get-UserLogonHistory.ps1) | Show recent logon sources (4624/4768: time, type, source IP, workstation) for an AD account from a DC. |
| [`Invoke-AdFleetParallel.ps1`](ad/Invoke-AdFleetParallel.ps1) | Runs an arbitrary worker scriptblock against every computer in given OUs in parallel via a runspace pool (PS 5.1): AD targeting, activity window, ping precheck, progress, summary, CSV. |
| [`New-GpoStartupScriptDeployment.ps1`](ad/New-GpoStartupScriptDeployment.ps1) | Fully scripted GPO software deployment via machine startup script: creates/links the GPO, registers scripts.ini, bumps gpt.ini + AD versions. |
| [`New-LockScreenGpo.ps1`](ad/New-LockScreenGpo.ps1) | Builds a complete branded lock-screen GPO end to end: SYSVOL image staging, six registry policies, GPP Files.xml, CSE merge, computer-version bump, OU links, verification report. |
| [`Remove-DisabledUsersFromPrivilegedGroups.ps1`](ad/Remove-DisabledUsersFromPrivilegedGroups.ps1) | Strip disabled user accounts out of privileged AD groups with runtime Enabled checks and verify (-WhatIf). |
| [`Repair-DcSecureChannel.ps1`](ad/Repair-DcSecureChannel.ps1) | Repairs a broken DC secure channel by stopping the local KDC to force use of a healthy peer, purging tickets, then netdom resetpwd (no demote). |
| [`Repair-DfsrVssShadowConflict.ps1`](ad/Repair-DfsrVssShadowConflict.ps1) | Recovers a DFSR service wedged by stuck VSS shadow copies: stop DFSR, escalating shadow deletion (diskshadow persistent/volatile, WMI), restart, pollad, verify (destructive to Previous Versions, gated). |
| [`Repoint-GppDriveMapServer.ps1`](ad/Repoint-GppDriveMapServer.ps1) | File-server migration cutover for a GPP drive-map GPO: rewrites drive paths old->new server with backup, correct AD+gpt.ini version bump, and abort-on-mismatch guards. |
| [`Reset-KrbtgtPassword.ps1`](ad/Reset-KrbtgtPassword.ps1) | Rotate krbtgt with a max-ticket-age window safety check and post-rotation health checks (-CheckOnly/-Force). |
| [`Retire-Gpo.ps1`](ad/Retire-Gpo.ps1) | Safely retires a GPO: always backs up + writes HTML settings record first, then unlinks and/or deletes only when asked; prints restore command. |
| [`Set-BulkChangePasswordAtLogon.ps1`](ad/Set-BulkChangePasswordAtLogon.ps1) | Force "change password at next logon" on a list of accounts, skipping SPN/disabled/PNE accounts, with verify (-WhatIf). |
| [`Set-DomainTimeSource.ps1`](ad/Set-DomainTimeSource.ps1) | Point the PDC emulator at an external NTP peer list and verify it synced (fixes domain-wide Kerberos-breaking time drift). |
| [`Update-GpoUncPaths.ps1`](ad/Update-GpoUncPaths.ps1) | Rewrites UNC paths inside GPOs (Preferences XML + Registry.pol values) old-server to new, with correct gpt.ini/AD version bumps and verification. |

### Windows Endpoint

| Script | What it does |
|---|---|
| [`Add-CookieExceptionForDomain.ps1`](windows-endpoint/Add-CookieExceptionForDomain.ps1) | Adds a "cookies allowed on exit" policy exception for a domain in Chrome and Edge. |
| [`Add-PendingFileDeleteOnBoot.ps1`](windows-endpoint/Add-PendingFileDeleteOnBoot.ps1) | Queues locked/stubborn files and directory trees for early-boot deletion via PendingFileRenameOperations, deepest-first, preserving existing pending ops. |
| [`Add-RemoteDesktopUser.ps1`](windows-endpoint/Add-RemoteDesktopUser.ps1) | Add a domain user to Remote Desktop Users on remote servers via ADSI, idempotent with verify (creds via env var). |
| [`audit-cygwin-environment.sh`](windows-endpoint/audit-cygwin-environment.sh) | Snapshots a Cygwin installation's configuration for audit/rebuild. |
| [`Clear-DiskSpaceSafe.ps1`](windows-endpoint/Clear-DiskSpaceSafe.ps1) | Reversible C: space reclaim: MSI logs, recycle bin, WU cache, old Temp, optional in-place log truncation (-WhatIf). |
| [`Diagnose-GpoDriveMaps.ps1`](windows-endpoint/Diagnose-GpoDriveMaps.ps1) | Explains from SYSTEM context why a user's GPO drive maps aren't working (gpresult Applied vs Denied, filter-group token check, hive mappings, connectivity) and can repoint old-server desktop shortcuts. |
| [`Disable-RdpClientPrinterRedirection.ps1`](windows-endpoint/Disable-RdpClientPrinterRedirection.ps1) | Disables client-side RDP printer redirection (both TS registry keys) to stop mstsc 0xc0000005 crashes from a local printer-driver UI DLL; breadcrumb + revert. |
| [`Disable-TeamsAutoStart.ps1`](windows-endpoint/Disable-TeamsAutoStart.ps1) | Stops classic AND new Teams auto-start for a target user from SYSTEM: Run keys, StartupApproved, Startup folder, HKLM, both config JSONs. |
| [`Find-MappedDriveTarget.ps1`](windows-endpoint/Find-MappedDriveTarget.ps1) | Resolve a user's mapped-drive UNC from loaded hives, offline NTUSER.DAT, and SYSVOL GPP (works as SYSTEM). |
| [`Find-OrphanedInstallerPackages.ps1`](windows-endpoint/Find-OrphanedInstallerPackages.ps1) | Reports (and optionally deletes) orphaned MSI/MSP in C:\Windows\Installer left by a failed-install/self-repair loop; registry-reference-based, size-family targeting. |
| [`Find-StaleCredentialConsumers.ps1`](windows-endpoint/Find-StaleCredentialConsumers.ps1) | Finds what could hold a stale password on a machine: services/tasks running as user accounts, minutes-scale recurring tasks, connections, recent 4624s. |
| [`Find-WorkstationLockoutCause.ps1`](windows-endpoint/Find-WorkstationLockoutCause.ps1) | Find what on a workstation is locking out an account: stale creds, tasks, services, mapped drives, cred vault. |
| [`Get-ArelliaAgentDiagnostics.ps1`](windows-endpoint/Get-ArelliaAgentDiagnostics.ps1) | Collects and summarizes Arellia/Ivanti EPM agent event-log entries. |
| [`Get-DelineaEpmAgentState.ps1`](windows-endpoint/Get-DelineaEpmAgentState.ps1) | Read-only diagnostic dump of Delinea/Thycotic EPM (Privilege Manager) agent state. |
| [`Get-DiskHealthReport.ps1`](windows-endpoint/Get-DiskHealthReport.ps1) | Read-only disk, SMART/storage-reliability, and boot/shutdown health report. |
| [`Get-DiskSpaceUsage.ps1`](windows-endpoint/Get-DiskSpaceUsage.ps1) | Junction-aware disk-usage triage: top folders, usual suspects, WinSxS, profiles, VSS, and largest files. |
| [`Get-FileBlockerDiagnostics.ps1`](windows-endpoint/Get-FileBlockerDiagnostics.ps1) | Identifies what is blocking a file operation: minifilter drivers, ACLs, ADS, reparse points, AppLocker/WDAC, Defender/AV state, with opt-in .NET delete probe. |
| [`Get-HyperVHostDiagnostics.ps1`](windows-endpoint/Get-HyperVHostDiagnostics.ps1) | Read-only Hyper-V host inventory: VMs, checkpoint counts, disk chains, and largest VHD/AVHDX/ISO files. |
| [`Get-PostRebootDiagnostics.ps1`](windows-endpoint/Get-PostRebootDiagnostics.ps1) | Read-only sweep of Event Logs and network state around a reboot or maintenance window. |
| [`Get-RdpAccessReport.ps1`](windows-endpoint/Get-RdpAccessReport.ps1) | Report who can RDP into servers: RDU group, SeRemoteInteractiveLogonRight/Deny, fDenyTSConnections, local admins. |
| [`Get-ServerPerformanceSnapshot.ps1`](windows-endpoint/Get-ServerPerformanceSnapshot.ps1) | Read-only server perf snapshot: RAM/commit pressure, top processes by mem/CPU, sessions, monitoring/EDR agents. |
| [`Get-UserShellFolderPath.ps1`](windows-endpoint/Get-UserShellFolderPath.ps1) | Resolves a user's real Desktop/Documents/etc. path from SYSTEM context via their registry hive, handling OneDrive Known Folder Move redirection. |
| [`Get-WorkstationLogonDiagnostics.ps1`](windows-endpoint/Get-WorkstationLogonDiagnostics.ps1) | Read-only workstation diag for logon/drive-map/folder-redirection/SMB/DNS issues (per-profile shell folders, connectivity, event logs). |
| [`Install-AppCrashLogger.ps1`](windows-endpoint/Install-AppCrashLogger.ps1) | Installs an event-triggered forensic crash logger for one process: records fault signature + WER loaded-module evidence per Event 1000, with classify-regex tagging. |
| [`Install-LegacyPSModuleFromNupkg.ps1`](windows-endpoint/Install-LegacyPSModuleFromNupkg.ps1) | Manually installs legacy PowerShell Gallery modules from their .nupkg directly. |
| [`Invoke-IntuneMdmSync.ps1`](windows-endpoint/Invoke-IntuneMdmSync.ps1) | Forces an immediate Intune/MDM sync from SYSTEM via the EnterpriseMgmt scheduled tasks, restarts IME, reports last successful sync. |
| [`Invoke-SafeDiskCleanup.ps1`](windows-endpoint/Invoke-SafeDiskCleanup.ps1) | Emergency C: space reclaim of known-safe caches (WU cache, temps, upgrade leftovers, DISM component cleanup) with freed-GB report. |
| [`Remove-StaleUserProfiles.ps1`](windows-endpoint/Remove-StaleUserProfiles.ps1) | Deletes local Windows user profiles unmodified in N days (destructive, has -WhatIf). |
| [`Remove-StaticDnsServerEntry.ps1`](windows-endpoint/Remove-StaticDnsServerEntry.ps1) | Locates and removes a specific static DNS server address from a network adapter. |
| [`Remove-UserFootprint.ps1`](windows-endpoint/Remove-UserFootprint.ps1) | Audits (and optionally removes) a specific user's footprint on a device: profile, tasks, services, cmdkey creds, Wi-Fi 802.1X bindings, hive drive maps; finds what process is invoking stale creds. |
| [`Repair-EntraPrtRecovery.ps1`](windows-endpoint/Repair-EntraPrtRecovery.ps1) | Fixes a broken Entra PRT from SYSTEM: sets the CloudAP RunRecovery flag, clears the WAM token broker cache, optional desktop fallback .bat. |
| [`Reset-LocalGroupPolicy.ps1`](windows-endpoint/Reset-LocalGroupPolicy.ps1) | Removes rogue local Group Policy (Registry.pol) with backup so domain/Intune policy wins again; optional policy-registry-key clearing + gpupdate. |
| [`Set-KioskAutoLogon.ps1`](windows-endpoint/Set-KioskAutoLogon.ps1) | Configures/repairs kiosk auto-logon and defeats the Win11 killers (DevicePasswordLessBuildVersion, AutoLogonCount, LimitBlankPasswordUse). |
| [`Set-SchannelTlsHardening.ps1`](windows-endpoint/Set-SchannelTlsHardening.ps1) | Disables TLS 1.0/1.1 + RC4/DES/3DES, enables TLS 1.2, sets GCM-only cipher order on one or many machines (SRA remediation). |

### Exchange Online & Microsoft 365

| Script | What it does |
|---|---|
| [`diagnose-m365-group-reply-failure.ps1`](exchange-m365/diagnose-m365-group-reply-failure.ps1) | Diagnoses the common causes of "can't reply to a Microsoft 365 Group" failures in Outlook/OWA. |
| [`Find-MissingMailbox.ps1`](exchange-m365/Find-MissingMailbox.ps1) | Finds what happened to a "disappeared" mailbox: active/soft-deleted/inactive/converted checks plus audit-log who-deleted-it and license-change events. |
| [`Find-SuspiciousInboxRules.ps1`](exchange-m365/Find-SuspiciousInboxRules.ps1) | Scans every mailbox in a tenant for malicious inbox-rule patterns (forwarding, delete-on-arrival, RSS-folder hiding). |
| [`Get-EntraSignInDiagnostics.ps1`](exchange-m365/Get-EntraSignInDiagnostics.ps1) | Read-only Entra ID user diagnostic: auth method/sync, N-day sign-in analysis (foreign-success flagging, error-code grouping+CSV), Conditional Access, named locations, risk state. |
| [`Get-MailboxRetentionAndSizeReport.ps1`](exchange-m365/Get-MailboxRetentionAndSizeReport.ps1) | Reports mailbox retention/MFA settings, sizes, and ELC diagnostics for a user. |
| [`Get-TenantEmailAuthReport.ps1`](exchange-m365/Get-TenantEmailAuthReport.ps1) | EXO email-auth discovery: accepted domains, direct-send posture, DKIM state, and the exact selector CNAMEs to publish in DNS, plus subject-prepend/disclaimer transport rules. |
| [`Repair-MailboxJunkSelfBlock.ps1`](exchange-m365/Repair-MailboxJunkSelfBlock.ps1) | Fixes "all mail goes to Junk": removes self/own-domain entries from Blocked Senders and optionally resets the server-side Junk Email Rule. |
| [`Revoke-UserSignInSessions.ps1`](exchange-m365/Revoke-UserSignInSessions.ps1) | Revokes all active sign-in sessions (refresh tokens) for a Microsoft 365 / Entra ID user. |
| [`Sync-SharePointFileToLocal.ps1`](exchange-m365/Sync-SharePointFileToLocal.ps1) | Unattended sync of the newest matching file from a SharePoint library folder to a fixed local path via Graph app-only REST (PS 5.1, no modules; secret via env var; atomic replace with rotation). |
| [`Test-DirectSendSpoofExposure.ps1`](exchange-m365/Test-DirectSendSpoofExposure.ps1) | Diagnose Direct Send spoof exposure (RejectDirectSend/DKIM/inbox rules + domain mail grouped by source IP) before blocking. |

### Azure & Entra ID

| Script | What it does |
|---|---|
| [`Disable-AaddsRc4Encryption.ps1`](azure/Disable-AaddsRc4Encryption.ps1) | Disables RC4 Kerberos (and enables armoring) on an Entra Domain Services managed domain, preserving all other domainSecuritySettings; verifies and lists health alerts (AADDS123). |
| [`Get-AzureFilesAuthReport.ps1`](azure/Get-AzureFilesAuthReport.ps1) | Audits why an Azure Files share is or isn't mountable: identity-based auth mode, shared-key state, network rules, key rotation age, share inventory, per-mode next-step guidance. |
| [`Get-EntraSecurityAudit.ps1`](azure/Get-EntraSecurityAudit.ps1) | Entra ID security posture audit: Security Defaults, Conditional Access policies, per-user MFA registration (flags password-only), password policy, licensing. |
| [`test-subscription-arm-access.ps1`](azure/test-subscription-arm-access.ps1) | Tests whether the cached Az PowerShell context has direct ARM access to a subscription. |

### Network & DNS

| Script | What it does |
|---|---|
| [`Find-UnmanagedHosts.ps1`](network/Find-UnmanagedHosts.ps1) | Auto-detect the local /24, sweep SMB/445, and flag hosts that are NOT domain-managed (legacy/shadow-IT). |
| [`Get-NpsAuthFailures.ps1`](network/Get-NpsAuthFailures.ps1) | On an NPS/RADIUS server, identifies the device behind a user's failing WiFi/VPN auths: MAC, AP/NAS, reason codes from 6273/6274 + 4625 + IAS logs. |
| [`monitor-public-dns-https.sh`](network/monitor-public-dns-https.sh) | Passive long-running monitor of a public site's DNS (multiple resolvers) and HTTPS (per-IP via --resolve), logging only failures and slow responses. |
| [`Remove-StaleDnsApexRecords.ps1`](network/Remove-StaleDnsApexRecords.ps1) | Removes DC-self-registered "same as parent" apex A records from an AD DNS zone and sets DnsAvoidRegisterRecords=LdapIpAddress so Netlogon stops re-adding them; verifies with repeated resolves. |
| [`Test-TlsProtocolSupport.ps1`](network/Test-TlsProtocolSupport.ps1) | Proves which TLS versions (1.0/1.1/1.2) targets actually accept via real pinned handshakes; auditor-ready pass/partial/fail table. |

### File Shares & Migration

| Script | What it does |
|---|---|
| [`Repair-NestedDuplicateFolders.ps1`](file-shares/Repair-NestedDuplicateFolders.ps1) | Finds and flattens "doubled folder" (...\NAME\NAME\...) structures that push paths past MAX_PATH; robocopy-enumerated, same-volume renames, dry-run/collapse/merge with rollback. |
| [`Repoint-ShareShortcutTargets.ps1`](file-shares/Repoint-ShareShortcutTargets.ps1) | Repoints .lnk shortcuts saved inside a share from an old file server to a new one after a migration (dry-run, verifies new target exists). |

### Server Hardware & Virtualization

| Script | What it does |
|---|---|
| [`Get-iDracRedfishInfo.ps1`](server-hardware/Get-iDracRedfishInfo.ps1) | Probe a Dell iDRAC (ports, TLS cert, Redfish) and read model/power-state/serial/BIOS (creds via env var). |
| [`Get-PercRaidHealth.ps1`](server-hardware/Get-PercRaidHealth.ps1) | Downloads Dell PERCCLI and reports PERC RAID controller / physical / virtual drive health. |
| [`Repair-OfflineBcd.ps1`](server-hardware/Repair-OfflineBcd.ps1) | Offline BCD repair for a non-booting VM: online its attached boot+OS disks on a helper, bcdboot the store, offline again; size-guarded disk selection. |
| [`Test-VhdChainIntegrity.ps1`](server-hardware/Test-VhdChainIntegrity.ps1) | Traces a Hyper-V VM's VHD/AVHDX differencing chain from active disk to base, flagging broken parents and orphaned snapshot files. |

### RMM

| Script | What it does |
|---|---|
| [`Discover-AgentBrowserSessions.ps1`](datto-rmm/Discover-AgentBrowserSessions.ps1) | Discovers active local WinRM/PSRemoting proxy sessions (Agent Browser CagService ports) on this machine. |

### macOS

| Script | What it does |
|---|---|
| [`brew-autoupdate.sh`](macos/brew-autoupdate.sh) | Updates Homebrew's package index and upgrades all installed formulae/casks. |
| [`icloud-stuck-sync-diagnose.sh`](macos/icloud-stuck-sync-diagnose.sh) | Diagnoses a stuck macOS iCloud Drive sync; reports local disk and sync-daemon state. |
| [`macos-safe-erase-usb.sh`](macos/macos-safe-erase-usb.sh) | Safely erase and format a small USB flash drive as exFAT/MBR on macOS with device-guard checks. |

### Shared Helpers

| Script | What it does |
|---|---|
| [`Invoke-AsLoggedOnUser.ps1`](lib/Invoke-AsLoggedOnUser.ps1) | Runs a command in the logged-on user's context from SYSTEM via a throwaway scheduled task and returns the output (dsregcmd, net use, cmdkey, etc.). |

### Misc

| Script | What it does |
|---|---|
| [`batch-convert-png-to-jpg.sh`](misc/batch-convert-png-to-jpg.sh) | Recursively converts all .png files under the current directory to .jpg. |
| [`Install-M365AdminModules.ps1`](misc/Install-M365AdminModules.ps1) | Installs the standard set of PowerShell modules for Microsoft 365 / SharePoint / Exchange admin work. |

## Usage

Most PowerShell scripts carry comment-based help:

```powershell
Get-Help ./ad/Check-AD-Health.ps1 -Full
```

Run with the parameters shown in each script's `.EXAMPLE` block. Scripts that change something support
`-WhatIf` or confirm before acting. A few scripts that need credentials read them from environment
variables rather than parameters, so nothing sensitive lands in your shell history; each one documents
which variables it expects.

## Disclaimer

Provided as-is, with no warranty. Test before running against production. Use at your own risk.

## License

[MIT](LICENSE)
