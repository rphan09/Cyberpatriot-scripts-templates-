# Hardening for server roles. Each part runs only when the role is installed.

function Invoke-CPServerRoles {
    $cfg = $script:CP.Settings.serverRoles

    if ($script:CP.IsDomainController) {
        Write-CPLog 'This machine is a domain controller. Domain password policy, audit policy and user rights are set in Group Policy (gpmc.msc), which this script does not change.' WARN
    }

    # ---- DNS Server ----------------------------------------------------------------------------
    if ((Get-Service -Name DNS -ErrorAction SilentlyContinue) -and (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue)) {
        foreach ($zone in @(Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.ZoneType -eq 'Primary' -and -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' })) {
            $zoneName = $zone.ZoneName
            if ($cfg.dnsDisableZoneTransfers -and $zone.SecureSecondaries -ne 'NoTransfer') {
                Invoke-CPChange "Disabled zone transfers for DNS zone $zoneName" { Set-DnsServerPrimaryZone -Name $zoneName -SecureSecondaries NoTransfer }
            }
            if ($cfg.dnsSecureDynamicUpdates -and $zone.IsDsIntegrated -and $zone.DynamicUpdate -ne 'Secure') {
                Invoke-CPChange "Set DNS zone $zoneName to secure dynamic updates only" { Set-DnsServerPrimaryZone -Name $zoneName -DynamicUpdate Secure }
            }
        }
        if ($cfg.dnsCachePollutionProtection) {
            Invoke-CPChange 'Enabled DNS cache pollution protection' { Set-DnsServerCache -PollutionProtection $true }
        }
    }

    # ---- IIS -------------------------------------------------------------------------------------
    if ((Get-Service -Name W3SVC -ErrorAction SilentlyContinue) -and (Test-CPCritical 'HTTP')) {
        if (Get-Module -ListAvailable -Name WebAdministration) {
            Import-Module WebAdministration -ErrorAction SilentlyContinue
            if ($cfg.iisDisableDirectoryBrowsing) {
                Invoke-CPChange 'Disabled IIS directory browsing' {
                    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/directoryBrowse' -Name 'enabled' -Value $false
                }
            }
            if ($cfg.iisRemoveServerHeader) {
                Invoke-CPChange 'Removed the IIS Server response header' {
                    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering' -Name 'removeServerHeader' -Value $true
                }
            }
        }
        else {
            Write-CPLog 'IIS is installed, but the WebAdministration module is not available. IIS settings must be checked manually in IIS Manager.' WARN
        }
    }
}
