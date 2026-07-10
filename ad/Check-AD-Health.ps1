<#
.SYNOPSIS
    Runs a quick overall health check against an Active Directory domain.

.DESCRIPTION
    Performs a set of common AD health checks:
      - Domain controller reachability (ping + LDAP bind), SYSVOL/NETLOGON share access, and repadmin replication summary per DC
      - FSMO role holder enumeration
      - Forest-wide replication error scan via repadmin
      - Inactive and disabled user account counts
      - Basic DNS health via dcdiag

    Intended to be run interactively (or via a scheduled task) on a domain-joined
    machine with the RSAT Active Directory PowerShell module and the AD DS tools
    (repadmin, dcdiag) available, using an account with rights to query AD and
    reach each domain controller over LDAP/SMB.

.PARAMETER InactiveDays
    Number of days of inactivity before a user account is reported as inactive.
    Defaults to 90.

.EXAMPLE
    .\Check-AD-Health.ps1

    Runs all checks against the current domain using the default 90-day
    inactivity window.

.EXAMPLE
    .\Check-AD-Health.ps1 -InactiveDays 60

    Runs all checks, flagging accounts inactive for 60+ days.

.NOTES
    Requires the ActiveDirectory PowerShell module (RSAT-AD-PowerShell) and the
    AD DS Tools (dcdiag, repadmin) to be available on the machine running the
    script. Run from an elevated PowerShell session with an account that has
    read access to AD and network access to each domain controller.
#>

[CmdletBinding()]
param(
    [int]$InactiveDays = 90
)

Import-Module ActiveDirectory

function Test-DomainControllersHealth {
    Write-Host "Checking Domain Controllers Health..."
    $dcs = Get-ADDomainController -Filter *
    foreach ($dc in $dcs) {
        Write-Host "Checking health for $($dc.HostName)..."
        Try {
            $pingResult = Test-Connection -ComputerName $dc.HostName -Count 2 -Quiet
            if ($pingResult -eq $false) {
                Write-Host "Domain Controller $($dc.HostName) is not reachable."
                continue
            }

            $ldapResult = [ADSI]"LDAP://$($dc.HostName)"
            if ($null -eq $ldapResult) {
                Write-Host "LDAP query failed for $($dc.HostName)."
                continue
            }

            $replicationStatus = repadmin /replsummary $dc.HostName
            if ($replicationStatus -match "Error") {
                Write-Host "Replication issues found on $($dc.HostName)."
            } else {
                Write-Host "Replication for $($dc.HostName) is functioning normally."
            }

            $sysvolPath = "\\$($dc.HostName)\SYSVOL"
            $netlogonPath = "\\$($dc.HostName)\NETLOGON"
            if (!(Test-Path $sysvolPath)) {
                Write-Host "SYSVOL share is not accessible on $($dc.HostName)."
            }
            if (!(Test-Path $netlogonPath)) {
                Write-Host "NETLOGON share is not accessible on $($dc.HostName)."
            }
        } Catch {
            Write-Host "An error occurred while checking $($dc.HostName): $_"
        }
    }
}

function Test-FSMORoles {
    Write-Host "Checking FSMO Roles..."
    Try {
        $forest = Get-ADForest
        $domain = Get-ADDomain
        $fsmoRoles = @(
            $forest.DomainNamingMaster,
            $domain.RIDMaster,
            $domain.PDCEmulator,
            $domain.InfrastructureMaster,
            $forest.SchemaMaster
        )
        foreach ($role in $fsmoRoles) {
            Write-Host "FSMO Role: $role is present."
        }
    } Catch {
        Write-Host "An error occurred while checking FSMO roles: $_"
    }
}

function Test-ReplicationErrors {
    Write-Host "Checking for Replication Errors..."
    Try {
        $replicationErrors = repadmin /showrepl * /errorsonly
        if ($replicationErrors) {
            Write-Host "Replication errors found: $replicationErrors"
        } else {
            Write-Host "No replication errors found."
        }
    } Catch {
        Write-Host "An error occurred while checking replication errors: $_"
    }
}

function Test-InactiveDisabledUsers {
    param(
        [int]$InactiveDays = 90
    )
    Write-Host "Checking for Inactive or Disabled User Accounts..."
    Try {
        $inactiveUsers = Search-ADAccount -AccountInactive -UsersOnly -TimeSpan "$InactiveDays.00:00:00"
        $disabledUsers = Search-ADAccount -AccountDisabled -UsersOnly
        if ($inactiveUsers) {
            Write-Host "Inactive user accounts found: $($inactiveUsers.Count)"
        } else {
            Write-Host "No inactive user accounts found."
        }
        if ($disabledUsers) {
            Write-Host "Disabled user accounts found: $($disabledUsers.Count)"
        } else {
            Write-Host "No disabled user accounts found."
        }
    } Catch {
        Write-Host "An error occurred while checking for inactive or disabled user accounts: $_"
    }
}

function Test-DNSIssues {
    Write-Host "Checking for DNS Issues..."
    Try {
        $dnsTest = dcdiag /test:dns
        if ($dnsTest -match "failed") {
            Write-Host "DNS issues found: $dnsTest"
        } else {
            Write-Host "No DNS issues found."
        }
    } Catch {
        Write-Host "An error occurred while checking DNS issues: $_"
    }
}

Test-DomainControllersHealth
Test-FSMORoles
Test-ReplicationErrors
Test-InactiveDisabledUsers -InactiveDays $InactiveDays
Test-DNSIssues

Write-Host "Active Directory environment check completed."
