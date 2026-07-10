#Requires -Version 5.1
<#
.SYNOPSIS
    Installs a standard set of PowerShell modules used for Microsoft 365 / SharePoint /
    Partner Center administration, for the current user only.

.DESCRIPTION
    Checks each module in the list and installs it for the current user if it isn't
    already available. Prefers the modern PSResourceGet cmdlets (Install-PSResource)
    when present on the system, and falls back to the legacy PowerShellGet
    (Install-Module) path on systems that don't have PSResourceGet yet.

    Trusts the PSGallery repository so installs run non-interactively (no per-module
    "untrusted repository" prompt). Errors on individual modules are caught and
    reported so one failed install doesn't stop the rest from installing.

.PARAMETER Modules
    List of module names to install. Defaults to a common M365 admin module set:
    PnP.PowerShell, PartnerCenter, and Microsoft.Online.SharePoint.PowerShell.

.EXAMPLE
    .\Install-M365AdminModules.ps1

    Installs the default module set for the current user.

.EXAMPLE
    .\Install-M365AdminModules.ps1 -Modules 'ExchangeOnlineManagement','Microsoft.Graph'

    Installs a custom list of modules instead of the default set.

.NOTES
    Run this in a normal (non-admin) PowerShell session; -Scope CurrentUser does not
    require elevation. Safe to re-run; already-installed modules are skipped.
#>

[CmdletBinding()]
param(
    [string[]]$Modules = @('PnP.PowerShell', 'PartnerCenter', 'Microsoft.Online.SharePoint.PowerShell')
)

$ErrorActionPreference = 'Continue'

if (Get-Command Install-PSResource -ErrorAction SilentlyContinue) {
    # Modern PSResourceGet path (PowerShell 7.4+ / Microsoft.PowerShell.PSResourceGet)
    try { Set-PSResourceRepository -Name PSGallery -Trusted -ErrorAction SilentlyContinue } catch {}

    foreach ($m in $Modules) {
        if (Get-Module -ListAvailable -Name $m) { Write-Host "SKIP $m"; continue }
        try {
            Install-PSResource -Name $m -Repository PSGallery -Scope CurrentUser -TrustRepository -ErrorAction Stop
            Write-Host "OK(rg) $m"
        }
        catch {
            Write-Host "ERR(rg) $m : $($_.Exception.Message)"
        }
    }
}
else {
    # Legacy PowerShellGet path
    if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
        Register-PSRepository -Name PSGallery -SourceLocation 'https://www.powershellgallery.com/api/v2' -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    }

    foreach ($m in $Modules) {
        if (Get-Module -ListAvailable -Name $m) { Write-Host "SKIP $m"; continue }
        try {
            Install-Module $m -Repository PSGallery -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Host "OK $m"
        }
        catch {
            Write-Host "ERR $m : $($_.Exception.Message)"
        }
    }
}

Write-Host "Module install pass complete."
