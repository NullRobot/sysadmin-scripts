<#
.SYNOPSIS
    Manually installs legacy PowerShell Gallery modules by downloading their .nupkg package directly.

.DESCRIPTION
    Some legacy modules (e.g. AzureAD, MSOnline) can be awkward to install with Install-Module in
    locked-down environments (outdated PowerShellGet, no PSGallery trust configured, corporate proxy,
    or a machine where the user lacks rights to install into the system module path). This script
    works around that by downloading the module's .nupkg directly from the PowerShell Gallery API,
    unzipping it into the target module directory, and stripping the NuGet packaging cruft
    (_rels, package, [Content_Types].xml, *.nuspec) so PowerShell loads it as a normal module.

    Skips any module that is already present at the destination.

.PARAMETER Modules
    One or more module names to install. Defaults to 'AzureAD' and 'MSOnline'.

.PARAMETER Destination
    Path to the module directory to install into. Defaults to the current user's
    WindowsPowerShell\Modules folder under Documents.

.PARAMETER TempPath
    Directory used for the temporary downloaded .zip before extraction. Defaults to $env:TEMP.

.EXAMPLE
    .\Install-LegacyPSModuleFromNupkg.ps1

    Installs AzureAD and MSOnline into the current user's module path.

.EXAMPLE
    .\Install-LegacyPSModuleFromNupkg.ps1 -Modules 'AzureAD' -Destination 'C:\Modules'

    Installs only AzureAD into a custom module directory.

.NOTES
    Requires outbound HTTPS access to www.powershellgallery.com.
    Run in an elevated/appropriate context if the destination path requires write permissions
    you don't otherwise have.
#>
[CmdletBinding()]
param(
    [string[]]$Modules = @('AzureAD', 'MSOnline'),
    [string]$Destination = (Join-Path $env:USERPROFILE 'Documents\WindowsPowerShell\Modules'),
    [string]$TempPath = $env:TEMP
)

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072

New-Item -ItemType Directory -Path $Destination -Force | Out-Null

foreach ($m in $Modules) {
    $md = Join-Path $Destination $m
    if (Test-Path (Join-Path $md "$m.psd1")) { Write-Host "SKIP $m (present)"; continue }
    try {
        $tmp = Join-Path $TempPath "$m-dl.zip"
        Invoke-WebRequest "https://www.powershellgallery.com/api/v2/package/$m" -OutFile $tmp -UseBasicParsing -ErrorAction Stop
        if (Test-Path $md) { Remove-Item $md -Recurse -Force -ErrorAction SilentlyContinue }
        Expand-Archive -Path $tmp -DestinationPath $md -Force
        # Remove NuGet packaging metadata so the module loads cleanly as a plain PowerShell module
        Remove-Item (Join-Path $md '`[Content_Types`].xml') -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $md '_rels') -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $md 'package') -Recurse -Force -ErrorAction SilentlyContinue
        Get-ChildItem $md -Filter *.nuspec | Remove-Item -Force -ErrorAction SilentlyContinue
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        if (Test-Path (Join-Path $md "$m.psd1")) { Write-Host "OK $m" } else { Write-Host "PARTIAL $m (psd1 not at root)" }
    } catch {
        Write-Host "ERR $m : $($_.Exception.Message)"
    }
}
Write-Host "DONE-NUPKG"
