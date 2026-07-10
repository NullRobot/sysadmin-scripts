<#
.SYNOPSIS
    Adds a "cookies allowed on exit" policy exception for a specific domain in Chrome and Edge.

.DESCRIPTION
    Some organizational GPOs force browsers to clear all cookies/site data on exit
    (Chrome: ClearBrowsingDataOnExitList / CookiesClearOnExitList, Edge equivalents).
    This breaks persistent-login web apps (password managers, SSO portals, etc.) that
    rely on a cookie surviving between browser sessions.

    This script sets the CookiesAllowedForUrls policy for both Chrome and Edge via the
    registry, which whitelists the specified domain so its cookies are exempt from the
    clear-on-exit policy. Run elevated (local admin) on the target machine, since it
    writes to HKEY_LOCAL_MACHINE.

.PARAMETER Domain
    The domain pattern to exempt, in Chrome/Edge policy URL-pattern format.
    Example: "https://[*.]example.com"

.PARAMETER EntryIndex
    The numbered value name under CookiesAllowedForUrls to use. Each exempted domain
    needs its own sequential index (1, 2, 3, ...). Defaults to 1. If other exceptions
    already exist on the machine, check the existing registry key first and pick the
    next free number so you don't overwrite one.

.EXAMPLE
    .\Add-CookieExceptionForDomain.ps1 -Domain "https://[*.]example.com"

.EXAMPLE
    .\Add-CookieExceptionForDomain.ps1 -Domain "https://[*.]example.com" -EntryIndex 2

.NOTES
    Requires local admin rights (writes to HKLM).
    Applies to both Chrome and Edge policy hives; remove either block if you only
    need to target one browser.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]${Domain},

    [Parameter(Mandatory = $false)]
    [int]${EntryIndex} = 1
)

$ErrorActionPreference = 'Stop'

$chromePath = "HKLM:\SOFTWARE\Policies\Google\Chrome\CookiesAllowedForUrls"
$edgePath   = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\CookiesAllowedForUrls"

try {
    # Chrome exception
    New-Item -Path ${chromePath} -Force | Out-Null
    New-ItemProperty -Path ${chromePath} -Name "${EntryIndex}" -Value ${Domain} -PropertyType String -Force | Out-Null
    Write-Host "Chrome: added cookie exception for ${Domain} at index ${EntryIndex}"

    # Edge exception
    New-Item -Path ${edgePath} -Force | Out-Null
    New-ItemProperty -Path ${edgePath} -Name "${EntryIndex}" -Value ${Domain} -PropertyType String -Force | Out-Null
    Write-Host "Edge: added cookie exception for ${Domain} at index ${EntryIndex}"
}
catch {
    Write-Error "Failed to write registry policy: $($_.Exception.Message)"
    throw
}

<#
Manual/GUI equivalent (Group Policy Editor path), if you'd rather push this via GPO
instead of a local registry edit:

  Computer Configuration
  -> Policies
     -> Administrative Templates
        -> Microsoft Edge (or Google > Google Chrome)
           -> Privacy and services (Edge) / Content Settings > Cookies (Chrome)
              -> "Configure which cookies are allowed to be set on exit" /
                 "Cookies allowed for URLs"

  Add the domain pattern (e.g. "https://[*.]example.com") to the list.
#>
