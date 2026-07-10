# sysadmin-scripts

A collection of practical PowerShell and shell scripts for Windows, Microsoft 365, Azure, and
network administration, pulled from real day-to-day IT work and cleaned up to be reusable.

Every script is parameterized (no hardcoded environments), documented with usage examples, and
safe to drop into your own environment. Read the header of each before running it.

> Work in progress. Scripts are being added and documented.

## Categories

| Folder | What's in it |
|---|---|
| `ad/` | Active Directory, GPO, and user-lifecycle tasks |
| `exchange-m365/` | Exchange Online, mail-flow, inbox-rule/BEC scanning, MFA |
| `azure/` | Azure quota, cost, and subscription/tenant lookups |
| `windows-endpoint/` | Workstation and endpoint fixes |
| `server-hardware/` | RAID/disk health and post-reboot diagnostics |
| `network/` | DNS, RADIUS/NPS, and cert diagnostics |
| `file-shares/` | NTFS permission auditing and share migration |
| `datto-rmm/` | Datto RMM remote-session helpers |
| `macos/` | A few macOS maintenance utilities |

## Usage

Most PowerShell scripts include comment-based help:

```powershell
Get-Help ./ad/Check-ADHealth.ps1 -Full
```

Run with the parameters shown in each script's `.EXAMPLE` block. Scripts that make changes prompt
for confirmation or support `-WhatIf` where practical.

## Disclaimer

These are provided as-is. Review and test any script in a non-production environment before running
it against live systems. No warranty; use at your own risk.

## License

MIT
