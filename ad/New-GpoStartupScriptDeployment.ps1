<#
.SYNOPSIS
    Creates a GPO that runs a deployment script at computer startup - fully
    scripted, including the scripts.ini registration and the version bumps
    GPMC would normally do for you.

.DESCRIPTION
    The reliable way to push an installer (VPN client, agent, runtime) to
    domain machines without SCCM/Intune: a machine startup script running as
    SYSTEM. Doing it by hand in GPMC is clicky; doing it by script requires
    three non-obvious steps this handles correctly:
      1. Creates the GPO and links it to the target OU
      2. Copies your deployment script into the GPO's own SYSVOL
         Machine\Scripts\Startup folder and registers it in
         Machine\Scripts\scripts.ini (the part GPMC hides from you)
      3. Bumps the version number in BOTH gpt.ini and the AD object
         (+1 = machine-side change) - without matching bumps clients
         ignore the GPO's new contents
    The deployment script itself should be idempotent (check installed
    version, exit fast if current) since it runs at every boot.
    Run on a DC as domain admin. Verify in GPMC afterward.

.PARAMETER GpoName
    Display name for the new GPO.

.PARAMETER TargetOU
    Distinguished name of the OU to link (e.g. "OU=Workstations,DC=corp,DC=local").

.PARAMETER ScriptPath
    UNC path of the deployment script to copy in (e.g. a .bat/.cmd/.ps1 on
    NETLOGON). It is COPIED into the GPO's SYSVOL folder.

.PARAMETER Comment
    Optional GPO comment.

.EXAMPLE
    .\New-GpoStartupScriptDeployment.ps1 -GpoName "Deploy VPN Client" `
        -TargetOU "OU=PCs,DC=corp,DC=local" `
        -ScriptPath "\\corp.local\NETLOGON\vpn\deploy_vpn.bat"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$GpoName,
    [Parameter(Mandatory)]
    [string]$TargetOU,
    [Parameter(Mandatory)]
    [string]$ScriptPath,
    [string]$Comment = "Deploys software via machine startup script"
)

Import-Module GroupPolicy -ErrorAction Stop
Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path $ScriptPath)) { throw "Script not found: $ScriptPath" }
$domain = (Get-ADDomain).DNSRoot
$domainDN = (Get-ADDomain).DistinguishedName
$scriptFile = Split-Path $ScriptPath -Leaf

if (-not $PSCmdlet.ShouldProcess("$domain", "Create GPO '$GpoName' linked to $TargetOU running $scriptFile at startup")) { return }

# 1. Create the GPO and link it
$gpo = New-GPO -Name $GpoName -Comment $Comment
New-GPLink -Guid $gpo.Id -Target $TargetOU -LinkEnabled Yes | Out-Null

# 2. Stage the startup script inside the GPO's SYSVOL folder
$gpoPath = "\\$domain\SYSVOL\$domain\Policies\{$($gpo.Id)}"
$scriptsDir = "$gpoPath\Machine\Scripts\Startup"
New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null
Copy-Item $ScriptPath "$scriptsDir\$scriptFile"

# Register it in scripts.ini (what the Startup Scripts UI actually writes)
@"
[Startup]
0CmdLine=$scriptFile
0Parameters=
"@ | Set-Content "$gpoPath\Machine\Scripts\scripts.ini" -Encoding ASCII

# 3. Bump the GPO version so clients pick up the change.
# Machine-side change = +1 in the low 16 bits. gpt.ini and the AD object
# versionNumber must match or clients flag the GPO as inconsistent.
$gptIniPath = "$gpoPath\gpt.ini"
$gptContent = Get-Content $gptIniPath -Raw
$newVersion = 1
if ($gptContent -match 'Version=(\d+)') {
    $newVersion = [int]$Matches[1] + 1
    $gptContent = $gptContent -replace "Version=\d+", "Version=$newVersion"
    Set-Content $gptIniPath $gptContent -Encoding ASCII -NoNewline
}

$gpoDN = "CN={$($gpo.Id)},CN=Policies,CN=System,$domainDN"
$adObj = [ADSI]"LDAP://$gpoDN"
$adObj.Properties["versionNumber"].Value = $newVersion
$adObj.CommitChanges()

Write-Output "GPO created: $($gpo.DisplayName)"
Write-Output "GPO ID: {$($gpo.Id)}"
Write-Output "Linked to: $TargetOU"
Write-Output "Startup script: $scriptsDir\$scriptFile"
Write-Output ""
Write-Output "Verify in GPMC: the GPO should show the startup script under"
Write-Output "Computer Configuration > Policies > Windows Settings > Scripts > Startup."
Write-Output "Clients apply it at next boot (startup scripts do not run at gpupdate)."
