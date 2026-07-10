#Requires -Modules GroupPolicy

<#
.SYNOPSIS
    Scans all Group Policy Objects in a domain and flags settings known to cause slow logon, boot, or shutdown times.

.DESCRIPTION
    Pulls every GPO in the target domain, retrieves its XML report, and checks it against a set of known
    performance anti-patterns: synchronous startup/shutdown scripts, legacy software installation policies,
    folder redirection (especially AppData), excessive drive/printer mappings via GP Preferences, roaming
    profiles, synchronous GP processing, disabled slow-link detection, loopback processing, expensive WMI
    filters (including the classic Win32_Product trap), large numbers of scheduled tasks, risky registry
    tweaks (DNS negative cache, prefetch, search indexing), heavy audit policies, AppLocker/SRP rule counts,
    forced-reboot Windows Update policies, large firewall rule sets, CPU throttling via power policy,
    critical services disabled by old "optimization" guides, WPAD/proxy auto-detect, oversized GPOs, and
    GPOs referencing many UNC paths.

    Findings are weighted by severity (Critical/High/Medium/Low), summarized on screen with the worst
    offenders highlighted first, and exported to a timestamped CSV in the current directory.

.PARAMETER Domain
    FQDN of the Active Directory domain to scan, e.g. contoso.com. If omitted, the script tries
    Get-ADDomain first and falls back to $env:USERDNSDOMAIN.

.EXAMPLE
    .\Find-SlowGPOs.ps1

    Auto-detects the current domain and scans all GPOs in it.

.EXAMPLE
    .\Find-SlowGPOs.ps1 -Domain contoso.com

    Scans all GPOs in the specified domain (useful when running from a machine joined to a
    different domain, or in a multi-domain forest).

.OUTPUTS
    Console summary plus a CSV report: GPO-Performance-Report_<timestamp>.csv in the current directory.

.NOTES
    Run from any domain-joined machine with RSAT (Group Policy Management + Active Directory modules)
    installed, using an account with read access to Group Policy Objects.
    Requires the GroupPolicy PowerShell module (and ActiveDirectory module for the domain-root link
    count and WMI filter query lookup; both checks fail gracefully if that module isn't loaded).
#>

param(
    [string]$Domain  # leave blank to auto-detect, or pass -Domain "contoso.com"
)

# --- figure out what domain we're working with ---
if (-not $Domain) {
    try {
        $Domain = (Get-ADDomain -ErrorAction Stop).DNSRoot
    }
    catch {
        # Get-ADDomain can fail depending on module/permissions, fall back to the env var
        $Domain = $env:USERDNSDOMAIN
    }
    if (-not $Domain) {
        Write-Host "Couldn't figure out the domain. Pass it in with -Domain" -ForegroundColor Red
        return
    }
}
Write-Host "`nTarget domain: $Domain" -ForegroundColor Cyan
Write-Host "Pulling GPOs... this might take a minute depending on how many there are`n"

# grab em all
try {
    $allGPOs = Get-GPO -All -Domain $Domain -ErrorAction Stop
}
catch {
    Write-Host "Failed to pull GPOs. Make sure RSAT is installed and you can reach the domain." -ForegroundColor Red
    Write-Host $_.Exception.Message
    return
}

if ($allGPOs.Count -eq 0) {
    Write-Host "No GPOs found. That's... weird." -ForegroundColor Yellow
    return
}

Write-Host "Found $($allGPOs.Count) GPOs. Analyzing each one...`n"

# this is where we collect all our findings
$results = [System.Collections.ArrayList]::new()

# severity weights - higher = worse for performance
$weights = @{
    'Critical' = 4
    'High'     = 3
    'Medium'   = 2
    'Low'      = 1
}

# helper to add a finding without repeating the object construction everywhere
function Add-Finding {
    param($GPOName, $GPOId, $Category, $Severity, $Detail, $Recommendation)
    [void]$results.Add([PSCustomObject]@{
        GPO            = $GPOName
        GPOID          = $GPOId
        Category       = $Category
        Severity       = $Severity
        Weight         = $weights[$Severity]
        Detail         = $Detail
        Recommendation = $Recommendation
    })
}

$counter = 0
foreach ($gpo in $allGPOs) {
    $counter++
    $pct = [math]::Round(($counter / $allGPOs.Count) * 100)
    Write-Progress -Activity "Analyzing GPOs" -Status "$($gpo.DisplayName) ($pct%)" -PercentComplete $pct

    # get the XML report - this is where all the actual settings live
    try {
        [xml]$report = Get-GPOReport -Guid $gpo.Id -ReportType XML -Domain $Domain -ErrorAction Stop
    }
    catch {
        # some GPOs are just broken, skip em
        Add-Finding $gpo.DisplayName $gpo.Id "Error" "Low" "Could not read GPO report: $($_.Exception.Message)" "Check if GPO is corrupted or inaccessible"
        continue
    }

    $gpoName = $gpo.DisplayName
    $gpoId   = $gpo.Id

    # namespace manager for xpath queries - GPO XML uses this ns
    $ns = New-Object System.Xml.XmlNamespaceManager($report.NameTable)
    $ns.AddNamespace("q", "http://www.microsoft.com/GroupPolicy/Settings")
    $ns.AddNamespace("q1", "http://www.microsoft.com/GroupPolicy/Settings/Scripts")
    $ns.AddNamespace("q2", "http://www.microsoft.com/GroupPolicy/Settings/Windows/Registry")
    $ns.AddNamespace("q3", "http://www.microsoft.com/GroupPolicy/Settings/DriveMaps")
    $ns.AddNamespace("q4", "http://www.microsoft.com/GroupPolicy/Settings/Printers")
    $ns.AddNamespace("q5", "http://www.microsoft.com/GroupPolicy/Settings/ScheduledTasks")
    $ns.AddNamespace("q6", "http://www.microsoft.com/GroupPolicy/Settings/Security")
    $ns.AddNamespace("q7", "http://www.microsoft.com/GroupPolicy/Settings/SoftwareInstallation")
    $ns.AddNamespace("q8", "http://www.microsoft.com/GroupPolicy/Settings/FolderRedirection")
    $ns.AddNamespace("q9", "http://www.microsoft.com/GroupPolicy/Settings/Firewall")

    $xmlStr = $report.OuterXml

    # ============================================================
    #  CHECK: linked but entirely disabled GPO
    # ============================================================
    # these still get processed during GP evaluation even though they do nothing.
    # not a huge deal but it adds up if there's dozens of them
    if ($gpo.GpoStatus -eq 'AllSettingsDisabled') {
        Add-Finding $gpoName $gpoId "Disabled GPO" "Low" `
            "GPO has all settings disabled but still exists and may be linked" `
            "Delete the GPO if it's not needed, or unlink it from all OUs"
    }
    # partially disabled - less of a perf thing, more of a 'this is confusing' thing
    elseif ($gpo.GpoStatus -eq 'UserSettingsDisabled' -or $gpo.GpoStatus -eq 'ComputerSettingsDisabled') {
        # only flag if the disabled side actually has settings (otherwise its fine)
        $compNode = $report.SelectSingleNode("//q:Computer/q:ExtensionData", $ns)
        $userNode = $report.SelectSingleNode("//q:User/q:ExtensionData", $ns)
        if ($gpo.GpoStatus -eq 'UserSettingsDisabled' -and $userNode) {
            Add-Finding $gpoName $gpoId "Partial Disable" "Low" `
                "User side disabled but contains user settings" `
                "Review if user settings are intentionally disabled or just forgotten"
        }
        if ($gpo.GpoStatus -eq 'ComputerSettingsDisabled' -and $compNode) {
            Add-Finding $gpoName $gpoId "Partial Disable" "Low" `
                "Computer side disabled but contains computer settings" `
                "Review if computer settings are intentionally disabled or just forgotten"
        }
    }

    # ============================================================
    #  CHECK: startup & shutdown scripts
    # ============================================================
    # these run synchronously by default and block the boot/shutdown process
    $scriptNodes = $report.SelectNodes("//q1:Script", $ns)
    if ($scriptNodes.Count -gt 0) {
        $startupScripts  = @($scriptNodes | Where-Object { $_.Type -match 'Startup|Logon' })
        $shutdownScripts = @($scriptNodes | Where-Object { $_.Type -match 'Shutdown|Logoff' })

        if ($startupScripts.Count -gt 0) {
            $scriptList = ($startupScripts | ForEach-Object {
                $cmd = if ($_.Command) { $_.Command } else { $_.InnerText }
                $cmd
            }) -join '; '
            $sev = if ($startupScripts.Count -ge 3) { 'High' } else { 'Medium' }
            Add-Finding $gpoName $gpoId "Startup/Logon Scripts" $sev `
                "$($startupScripts.Count) startup/logon script(s): $scriptList" `
                "Move logic to scheduled tasks or Intune scripts. Startup scripts block the login screen."
        }
        if ($shutdownScripts.Count -gt 0) {
            $sev = if ($shutdownScripts.Count -ge 3) { 'High' } else { 'Low' }
            Add-Finding $gpoName $gpoId "Shutdown/Logoff Scripts" $sev `
                "$($shutdownScripts.Count) shutdown/logoff script(s)" `
                "Shutdown scripts delay the shutdown process. Consider if they're still needed."
        }
    }

    # ============================================================
    #  CHECK: software installation policies
    # ============================================================
    # MSI deployment via GP is legacy and slow - blocks logon until it finishes
    $swNodes = $report.SelectNodes("//q7:*", $ns)
    # also try raw match since the namespace can vary
    if ($swNodes.Count -eq 0 -and $xmlStr -match 'SoftwareInstallation') {
        # found it but xpath missed, flag it generically
        if ($xmlStr -match 'MsiApplication|ApplicationName') {
            Add-Finding $gpoName $gpoId "Software Installation" "Critical" `
                "GPO deploys software via Group Policy Software Installation" `
                "GP software deployment is synchronous and blocks logon. Use SCCM, Intune, PDQ, or an RMM tool instead."
        }
    }
    elseif ($swNodes.Count -gt 0) {
        Add-Finding $gpoName $gpoId "Software Installation" "Critical" `
            "GPO contains software installation settings ($($swNodes.Count) nodes)" `
            "GP software deployment is synchronous and blocks logon. Use a real deployment tool."
    }

    # ============================================================
    #  CHECK: folder redirection
    # ============================================================
    # redirecting Desktop/Documents/etc to a network share = every file operation goes over the network
    $frNodes = $report.SelectNodes("//q8:*", $ns)
    $frMatch = $xmlStr -match 'FolderRedirection'
    if ($frNodes.Count -gt 0 -or $frMatch) {
        # try to figure out which folders
        $folders = @()
        if ($xmlStr -match 'Desktop')    { $folders += 'Desktop' }
        if ($xmlStr -match 'Documents' -or $xmlStr -match 'My Documents') { $folders += 'Documents' }
        if ($xmlStr -match 'AppData')    { $folders += 'AppData' }
        if ($xmlStr -match 'Pictures')   { $folders += 'Pictures' }
        if ($xmlStr -match 'Downloads')  { $folders += 'Downloads' }
        if ($xmlStr -match 'Start Menu') { $folders += 'Start Menu' }

        $folderStr = if ($folders.Count -gt 0) { $folders -join ', ' } else { '(could not determine which folders)' }
        # AppData redirection is the worst offender
        $sev = if ($folders -contains 'AppData') { 'Critical' } else { 'High' }
        Add-Finding $gpoName $gpoId "Folder Redirection" $sev `
            "Redirects folders to network: $folderStr" `
            "Folder redirection over the network causes lag, especially AppData. Consider OneDrive Known Folder Move instead."
    }

    # ============================================================
    #  CHECK: drive mappings (GP Preferences)
    # ============================================================
    $driveNodes = $report.SelectNodes("//q3:*", $ns)
    $driveCount = 0
    if ($xmlStr -match 'DriveMapSettings') {
        # count how many drives
        $driveCount = ([regex]::Matches($xmlStr, 'DriveMapSettings|Drive name')).Count
        if ($driveCount -eq 0) { $driveCount = ([regex]::Matches($xmlStr, '<Drive ')).Count }
    }
    if ($driveCount -gt 5) {
        Add-Finding $gpoName $gpoId "Drive Mappings" "Medium" `
            "Maps $driveCount+ drives via GP Preferences" `
            "Lots of drive mappings slow logon, especially if any target servers are offline. Consider logon scripts with timeout handling or direct shortcuts."
    }
    elseif ($driveCount -gt 0 -and $xmlStr -match 'Reconnect') {
        # reconnect = persistent mappings, these retry on boot even if server is down
        Add-Finding $gpoName $gpoId "Drive Mappings" "Low" `
            "$driveCount drive mapping(s) with reconnect enabled" `
            "Persistent drive maps retry connections at logon. If a file server is slow or down, this stalls login."
    }

    # ============================================================
    #  CHECK: printer mappings
    # ============================================================
    $printerCount = ([regex]::Matches($xmlStr, '<(Shared)?Printer |PrinterConnection|PortPrinter')).Count
    if ($printerCount -gt 10) {
        Add-Finding $gpoName $gpoId "Printer Mappings" "High" `
            "$printerCount printer mappings in one GPO" `
            "Excessive printer mappings slow logon significantly. Use item-level targeting or split by location/department."
    }
    elseif ($printerCount -gt 3) {
        Add-Finding $gpoName $gpoId "Printer Mappings" "Medium" `
            "$printerCount printer mappings" `
            "Each printer mapping adds logon time. Use item-level targeting so users only get printers they need."
    }

    # ============================================================
    #  CHECK: roaming profiles
    # ============================================================
    if ($xmlStr -match 'RoamingProfile|\\\\.*\\profiles?\$|ProfilePath') {
        $sev = 'High'
        # if they set a profile size limit at least they tried
        if ($xmlStr -match 'ProfileSize|LimitSize') { $sev = 'Medium' }
        Add-Finding $gpoName $gpoId "Roaming Profiles" $sev `
            "Configures roaming user profiles" `
            "Roaming profiles sync at logon/logoff. Large profiles = very slow logins. Migrate to FSLogix or OneDrive KFM."
    }

    # ============================================================
    #  CHECK: synchronous processing settings
    # ============================================================
    # when GP runs synchronously, the user has to wait for ALL policies to apply before they get a desktop
    if ($xmlStr -match 'RunSynchronous|AlwaysWaitForNetwork|SyncForegroundPolicy|NoBackgroundPolicy') {
        $details = @()
        if ($xmlStr -match 'AlwaysWaitForNetwork')   { $details += 'Always wait for network at logon' }
        if ($xmlStr -match 'SyncForegroundPolicy')    { $details += 'Synchronous foreground processing' }
        if ($xmlStr -match 'NoBackgroundPolicy')      { $details += 'Background refresh disabled' }
        if ($xmlStr -match 'RunSynchronous')          { $details += 'Synchronous run configured' }

        Add-Finding $gpoName $gpoId "Synchronous Processing" "High" `
            ($details -join '; ') `
            "Synchronous GP processing blocks logon until all policies apply. This is the #1 cause of slow logins from GPOs."
    }

    # ============================================================
    #  CHECK: slow link detection disabled or misconfigured
    # ============================================================
    # slow link detection lets GP skip some policies on slow connections (VPN, etc)
    # disabling it means full GP processing even on garbage connections
    if ($xmlStr -match 'GroupPolicyMinTransferRate' -or $xmlStr -match 'SlowLinkDetect') {
        if ($xmlStr -match 'value.*["\s]0["\s<]' -and $xmlStr -match 'SlowLink') {
            Add-Finding $gpoName $gpoId "Slow Link Detection" "High" `
                "Slow link detection is disabled (transfer rate = 0)" `
                "Without slow link detection, GP applies all policies even over VPN/slow connections. Re-enable or set a reasonable threshold."
        }
        elseif ($xmlStr -match 'GroupPolicyMinTransferRate') {
            Add-Finding $gpoName $gpoId "Slow Link Detection" "Low" `
                "Slow link threshold is customized" `
                "Verify the slow link threshold is appropriate. Default is 500 Kbps."
        }
    }

    # ============================================================
    #  CHECK: loopback processing
    # ============================================================
    # replace mode is the heavy one - processes user policies twice
    if ($xmlStr -match 'LoopbackMode|UserPolicyMode') {
        $mode = if ($xmlStr -match 'Replace|mode.*2') { 'Replace' } else { 'Merge' }
        $sev = if ($mode -eq 'Replace') { 'Medium' } else { 'Low' }
        Add-Finding $gpoName $gpoId "Loopback Processing" $sev `
            "Loopback processing enabled ($mode mode)" `
            "Loopback processing means user policies get applied twice (once normally, once for the computer's OU). This adds login time."
    }

    # ============================================================
    #  CHECK: WMI filters
    # ============================================================
    # WMI queries run on EVERY client that processes the GPO even if the filter excludes them
    if ($gpo.WmiFilter) {
        $wmiName = $gpo.WmiFilter.Name
        # try to get the actual query
        $wmiQuery = ""
        try {
            $wmiQuery = $gpo.WmiFilter.Query
            if (-not $wmiQuery) {
                # pull from AD directly
                $wmiObj = Get-ADObject -Filter "Name -eq '$($gpo.WmiFilter.Name)'" -SearchBase "CN=SOM,CN=WMIPolicy,CN=System,$((Get-ADDomain -Server $Domain).DistinguishedName)" -Properties msWMI-Parm2 -ErrorAction SilentlyContinue
                if ($wmiObj) { $wmiQuery = $wmiObj.'msWMI-Parm2' }
            }
        }
        catch {
            # whatever, we know there's a WMI filter at least
        }

        $sev = 'Medium'
        $detail = "WMI filter attached: $wmiName"
        # flag the really bad WMI queries
        if ($wmiQuery -match 'Win32_Product') {
            $sev = 'Critical'
            $detail += " - USES Win32_Product (triggers MSI reconfiguration on every evaluation!)"
        }
        elseif ($wmiQuery -match 'SELECT.*FROM.*WHERE') {
            $detail += " - Query: $($wmiQuery.Substring(0, [Math]::Min($wmiQuery.Length, 150)))"
        }
        Add-Finding $gpoName $gpoId "WMI Filter" $sev `
            $detail `
            "WMI filters run on every GP refresh cycle on every machine. Win32_Product is especially bad. Consider security group filtering instead."
    }

    # ============================================================
    #  CHECK: scheduled tasks via GP Preferences
    # ============================================================
    $taskCount = ([regex]::Matches($xmlStr, 'ScheduledTasks|<Task |<TaskV2 ')).Count
    if ($taskCount -gt 5) {
        Add-Finding $gpoName $gpoId "Scheduled Tasks" "Medium" `
            "$taskCount scheduled task definitions" `
            "Large numbers of scheduled tasks deployed via GPO add processing time. Consider deploying via RMM instead."
    }

    # ============================================================
    #  CHECK: registry settings - look for known bad ones
    # ============================================================

    # DNS negative cache - setting this to 0 = constant DNS lookups for failed queries
    if ($xmlStr -match 'NegativeCacheTime.*value.*["\s]0["\s<]' -or $xmlStr -match 'MaxNegativeCacheTtl.*0') {
        Add-Finding $gpoName $gpoId "DNS Config" "Medium" `
            "DNS negative cache disabled (TTL=0)" `
            "Without negative caching, every failed DNS lookup retries immediately. This can hammer the DNS server and slow name resolution."
    }

    # disabling prefetch/superfetch
    if ($xmlStr -match 'EnablePrefetcher.*0|EnableSuperfetch.*0|SysMain.*4') {
        Add-Finding $gpoName $gpoId "Prefetch/Superfetch" "Medium" `
            "Prefetch or Superfetch is disabled via GPO" `
            "Disabling Superfetch on SSDs is fine but on HDDs it significantly slows app launch times. Verify this is intentional."
    }

    # windows search indexer disabled
    if ($xmlStr -match 'PreventIndexingOutlook|DisableSearching|WSearch.*4|AllowSearching.*0') {
        Add-Finding $gpoName $gpoId "Search Indexer" "Low" `
            "Windows Search indexing is restricted or disabled" `
            "Disabling search indexing saves some background CPU but makes searches very slow. Usually not worth it on modern hardware."
    }

    # visual effects forced to best appearance (all animations on)
    if ($xmlStr -match 'VisualFXSetting.*1' -or ($xmlStr -match 'UserPreferencesMask' -and $xmlStr -match '158,30')) {
        Add-Finding $gpoName $gpoId "Visual Effects" "Low" `
            "Visual effects forced to 'Best Appearance'" `
            "Forcing all visual effects on wastes GPU/CPU on older machines. Let users/admins choose or set to 'Best Performance'."
    }

    # ============================================================
    #  CHECK: heavy audit policies
    # ============================================================
    $auditCount = ([regex]::Matches($xmlStr, 'AuditSetting|EventAudit|IncludeValue.*Success|IncludeValue.*Failure')).Count
    if ($auditCount -gt 20) {
        Add-Finding $gpoName $gpoId "Audit Policy" "Medium" `
            "$auditCount audit settings configured" `
            "Heavy audit policies generate lots of events and can impact I/O, especially on busy servers. Review which audits are actually needed."
    }

    # ============================================================
    #  CHECK: AppLocker / SRP
    # ============================================================
    if ($xmlStr -match 'AppLockerPolicy|RuleCollection') {
        $ruleCount = ([regex]::Matches($xmlStr, '<FilePathRule|<FileHashRule|<FilePublisherRule')).Count
        $sev = if ($ruleCount -gt 50) { 'High' } elseif ($ruleCount -gt 20) { 'Medium' } else { 'Low' }
        Add-Finding $gpoName $gpoId "AppLocker" $sev `
            "AppLocker policy with $ruleCount rules" `
            "AppLocker rules are evaluated on every process launch. Hash rules are the slowest (re-hashes the file each time). Use publisher rules where possible."
    }
    if ($xmlStr -match 'SoftwareRestrictionPolicies|CodeIdentifiers') {
        Add-Finding $gpoName $gpoId "Software Restriction Policy" "Medium" `
            "Legacy Software Restriction Policies configured" `
            "SRP is deprecated and slower than AppLocker. Consider migrating to AppLocker or WDAC."
    }

    # ============================================================
    #  CHECK: windows update policies
    # ============================================================
    if ($xmlStr -match 'WindowsUpdate|WUServer|AUOptions') {
        $details = @()
        if ($xmlStr -match 'NoAutoUpdate.*0')       { $details += 'Auto-update enabled' }
        if ($xmlStr -match 'AUOptions.*4')           { $details += 'Auto-download and schedule install' }
        if ($xmlStr -match 'AlwaysAutoRebootAtScheduledTime') { $details += 'Forced auto-reboot' }
        if ($xmlStr -match 'ScheduledInstallDay')    { $details += 'Scheduled install day configured' }
        if ($xmlStr -match 'AutoInstallMinorUpdates') { $details += 'Minor updates auto-install' }

        # only flag if it's doing forced reboots or downloading during work hours
        if ($xmlStr -match 'AlwaysAutoRebootAtScheduledTime|ScheduledInstallTime') {
            Add-Finding $gpoName $gpoId "Windows Update" "Medium" `
                "Windows Update policy with forced reboot: $($details -join '; ')" `
                "Forced restarts during business hours disrupt users. Check scheduled install time is outside work hours."
        }
    }

    # ============================================================
    #  CHECK: firewall rules (tons of them = slow processing)
    # ============================================================
    $fwRuleCount = ([regex]::Matches($xmlStr, '<Rule |<FirewallRule|InboundFirewallRules|OutboundFirewallRules')).Count
    if ($fwRuleCount -gt 50) {
        Add-Finding $gpoName $gpoId "Firewall Rules" "Medium" `
            "$fwRuleCount firewall rules deployed via GPO" `
            "Large numbers of firewall rules slow down GP processing and can impact network performance. Consider consolidating rules."
    }

    # ============================================================
    #  CHECK: power management policies
    # ============================================================
    if ($xmlStr -match 'PowerSettings|MaxThrottle|MinThrottle|ProcessorPerfBoostMode') {
        if ($xmlStr -match 'MaxThrottle|ProcFreqMax.*[1-7]\d\b') {
            Add-Finding $gpoName $gpoId "Power Management" "High" `
                "CPU performance is being throttled via power policy" `
                "GPO is limiting CPU frequency. This directly slows down the machine. Review power plan settings."
        }
        if ($xmlStr -match 'VideoDim|MonitorTimeout|StandbyTimeout') {
            Add-Finding $gpoName $gpoId "Power Management" "Low" `
                "Sleep/display timeout configured via GPO" `
                "Not a performance issue per se but aggressive sleep timers can be annoying. Just flagging it."
        }
    }

    # ============================================================
    #  CHECK: services being disabled that shouldn't be
    # ============================================================
    # disabling services for "optimization" often causes more problems than it solves
    $svcDisablePatterns = @(
        'Themes.*4',           # themes service = visual glitches, slow rendering
        'Dhcp.*4',             # DHCP client = no automatic IP
        'Dnscache.*4',         # DNS cache = constant DNS lookups
        'EventLog.*4',         # event log service
        'FontCache.*4',        # font cache = slow app rendering
        'LSM.*4',              # local session manager
        'Schedule.*4',         # task scheduler = breaks many built-in features
        'BITS.*4',             # BITS = windows update stops working
        'wuauserv.*4',         # windows update service
        'AppIDSvc.*4'          # AppLocker depends on this
    )
    $badServices = @()
    foreach ($pattern in $svcDisablePatterns) {
        if ($xmlStr -match $pattern) {
            $svcName = ($pattern -split '\.\*')[0]
            $badServices += $svcName
        }
    }
    if ($badServices.Count -gt 0) {
        $sev = if ($badServices -contains 'Dnscache' -or $badServices -contains 'Schedule' -or $badServices -contains 'EventLog') { 'Critical' } else { 'High' }
        Add-Finding $gpoName $gpoId "Disabled Services" $sev `
            "Critical services being disabled: $($badServices -join ', ')" `
            "Disabling these services causes more problems than it solves. This is probably left over from an old 'optimization' guide."
    }

    # ============================================================
    #  CHECK: IE maintenance / legacy stuff
    # ============================================================
    if ($xmlStr -match 'InternetExplorer|IESettings|ProxySettings.*AutoDetect') {
        if ($xmlStr -match 'AutoDetect.*1|WPAD') {
            Add-Finding $gpoName $gpoId "Proxy/WPAD" "Medium" `
                "WPAD/Auto-detect proxy is enabled" `
                "WPAD auto-detection adds 5-20 seconds to browser startup and many network operations. Disable if you're not using a proxy."
        }
    }

    # ============================================================
    #  CHECK: GPO size / complexity (rough estimate)
    # ============================================================
    $xmlSize = $xmlStr.Length
    if ($xmlSize -gt 500000) {
        Add-Finding $gpoName $gpoId "GPO Size" "High" `
            "Very large GPO (XML report is $([math]::Round($xmlSize/1KB)) KB)" `
            "Large GPOs take longer to download and process. Consider splitting into smaller, targeted GPOs."
    }
    elseif ($xmlSize -gt 200000) {
        Add-Finding $gpoName $gpoId "GPO Size" "Medium" `
            "Large GPO (XML report is $([math]::Round($xmlSize/1KB)) KB)" `
            "This GPO is getting big. May want to split it up if it keeps growing."
    }

    # ============================================================
    #  CHECK: lots of GP Preferences items in general
    # ============================================================
    $prefCount = ([regex]::Matches($xmlStr, '<Properties ')).Count
    if ($prefCount -gt 30) {
        Add-Finding $gpoName $gpoId "GP Preferences" "Medium" `
            "$prefCount GP Preference items in one GPO" `
            "Each preference item is evaluated on every GP refresh. Consider if all items are still needed and use item-level targeting to limit scope."
    }

    # ============================================================
    #  CHECK: mapped network paths that might be slow/dead
    # ============================================================
    $uncPaths = [regex]::Matches($xmlStr, '\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9$._-]+')
    $uniquePaths = $uncPaths | ForEach-Object { $_.Value } | Sort-Object -Unique
    if ($uniquePaths.Count -gt 10) {
        Add-Finding $gpoName $gpoId "Network References" "Medium" `
            "$($uniquePaths.Count) unique UNC paths referenced" `
            "GPO references many network paths. If any of these servers are slow or offline, GP processing will hang waiting for timeouts. Paths include: $(($uniquePaths | Select-Object -First 5) -join ', ')..."
    }

    # ============================================================
    #  CHECK: desktop wallpaper from network path
    # ============================================================
    if ($xmlStr -match 'Wallpaper.*\\\\' -or $xmlStr -match 'WallpaperStyle.*\\\\') {
        Add-Finding $gpoName $gpoId "Network Wallpaper" "Low" `
            "Desktop wallpaper set to a network path" `
            "Loading wallpaper from a network share adds a small delay at logon. Copy the image locally via a script or use a local path."
    }

    # ============================================================
    #  CHECK: credential delegation / CredSSP
    # ============================================================
    if ($xmlStr -match 'AllowDefCredentials|AllowFreshCredentials.*wsman' -and $xmlStr -match 'Concatenate.*true') {
        Add-Finding $gpoName $gpoId "Credential Delegation" "Low" `
            "CredSSP or credential delegation is configured" `
            "Not a direct performance issue but CredSSP has security implications. Just flagging it for awareness."
    }
}

Write-Progress -Activity "Analyzing GPOs" -Completed

# ============================================================
#  CHECK: total number of GPOs linked to domain root
# ============================================================
# too many GPOs at the domain level = slow processing for EVERY machine
try {
    $domDN   = (Get-ADDomain -Server $Domain).DistinguishedName
    $domLinks = (Get-ADObject -Identity $domDN -Properties gPLink -Server $Domain).gPLink
    if ($domLinks) {
        $linkCount = ([regex]::Matches($domLinks, 'LDAP://')).Count
        if ($linkCount -gt 15) {
            Add-Finding "(Domain Root)" "N/A" "Excessive Domain Links" "High" `
                "$linkCount GPOs linked at the domain root" `
                "Every domain-linked GPO is processed by every computer. Move GPOs to specific OUs where possible."
        }
    }
}
catch {
    # AD module might not be loaded, no big deal
}

# ============================================================
#  OUTPUT
# ============================================================

if ($results.Count -eq 0) {
    Write-Host "`nNo performance issues found! Either the GPOs are clean or the check missed something." -ForegroundColor Green
    Write-Host "If machines are still slow, the problem is probably not GPOs." -ForegroundColor Green
    return
}

# sort by weight descending so the worst stuff is at the top
$sorted = $results | Sort-Object -Property Weight -Descending

# summary
Write-Host "`n=========================================" -ForegroundColor White
Write-Host "  GPO Performance Analysis - $Domain" -ForegroundColor White
Write-Host "=========================================" -ForegroundColor White
Write-Host ""

$critCount = @($sorted | Where-Object Severity -eq 'Critical').Count
$highCount = @($sorted | Where-Object Severity -eq 'High').Count
$medCount  = @($sorted | Where-Object Severity -eq 'Medium').Count
$lowCount  = @($sorted | Where-Object Severity -eq 'Low').Count
$affectedGPOs = ($sorted | Select-Object -ExpandProperty GPO -Unique).Count

Write-Host "Scanned: $($allGPOs.Count) GPOs | Flagged: $affectedGPOs GPOs with issues" -ForegroundColor Cyan
Write-Host "Findings: " -NoNewline
if ($critCount -gt 0) { Write-Host "$critCount Critical " -ForegroundColor Red -NoNewline }
if ($highCount -gt 0) { Write-Host "$highCount High " -ForegroundColor Yellow -NoNewline }
if ($medCount -gt 0)  { Write-Host "$medCount Medium " -ForegroundColor DarkYellow -NoNewline }
if ($lowCount -gt 0)  { Write-Host "$lowCount Low" -ForegroundColor Gray -NoNewline }
Write-Host ""

# show critical + high first with full details
$importantFindings = $sorted | Where-Object { $_.Severity -in @('Critical','High') }
if ($importantFindings) {
    Write-Host "`n--- CRITICAL & HIGH FINDINGS ---`n" -ForegroundColor Red

    $importantFindings | ForEach-Object {
        $color = if ($_.Severity -eq 'Critical') { 'Red' } else { 'Yellow' }
        Write-Host "[$($_.Severity.ToUpper())] " -ForegroundColor $color -NoNewline
        Write-Host "$($_.GPO)" -ForegroundColor White
        Write-Host "  Category: $($_.Category)"
        Write-Host "  Detail: $($_.Detail)"
        Write-Host "  Fix: $($_.Recommendation)"
        Write-Host ""
    }
}

# medium findings, less detail
$medFindings = $sorted | Where-Object Severity -eq 'Medium'
if ($medFindings) {
    Write-Host "--- MEDIUM FINDINGS ---`n" -ForegroundColor DarkYellow

    $medFindings | ForEach-Object {
        Write-Host "[MEDIUM] " -ForegroundColor DarkYellow -NoNewline
        Write-Host "$($_.GPO) " -ForegroundColor White -NoNewline
        Write-Host "- $($_.Category): $($_.Detail)"
    }
    Write-Host ""
}

# low findings, just count them
$lowFindings = $sorted | Where-Object Severity -eq 'Low'
if ($lowFindings) {
    Write-Host "--- LOW FINDINGS ($(${lowFindings}.Count)) ---`n" -ForegroundColor Gray
    $lowFindings | Group-Object Category | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count) finding(s)" -ForegroundColor Gray
    }
    Write-Host ""
}

# per-GPO summary so you can see which GPOs are the worst offenders
Write-Host "--- WORST OFFENDERS (by total severity score) ---`n" -ForegroundColor Cyan
$sorted | Group-Object GPO | ForEach-Object {
    $totalWeight = ($_.Group | Measure-Object -Property Weight -Sum).Sum
    [PSCustomObject]@{
        GPO   = $_.Name
        Score = $totalWeight
        Issues = $_.Count
    }
} | Sort-Object Score -Descending | Select-Object -First 15 | Format-Table -AutoSize

# export to CSV for sharing with others
$csvPath = Join-Path $PWD "GPO-Performance-Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$sorted | Select-Object GPO, GPOID, Category, Severity, Detail, Recommendation | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Full report exported to: $csvPath`n" -ForegroundColor Green

# quick top-3 recommendations
Write-Host "TOP RECOMMENDATIONS:" -ForegroundColor White
$topRecs = $sorted | Where-Object { $_.Severity -in @('Critical','High') } | Select-Object -First 3
$i = 1
foreach ($rec in $topRecs) {
    Write-Host "  $i. $($rec.GPO): $($rec.Recommendation)" -ForegroundColor Cyan
    $i++
}
if (-not $topRecs) {
    Write-Host "  No critical/high issues found. Review medium findings for optimization opportunities." -ForegroundColor Gray
}

Write-Host "`ndone.`n"
