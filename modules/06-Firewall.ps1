# Configures Windows Defender Firewall. Profile settings come from the "firewall" section of
# config\settings.json. Rule groups and blocked ports come from config\firewall.json.

function ConvertTo-CPGpoBoolean {
    param($Value)
    if ($Value) { return 'True' } else { return 'False' }
}

function Invoke-CPFirewall {
    $set = $script:CP.Settings.firewall
    $rules = $script:CP.Firewall
    $groupBlock = 'CP-Hardening Block'
    $groupAllow = 'CP-Hardening Allow'

    # ---- Services ------------------------------------------------------------------------
    foreach ($svc in @('BFE', 'MpsSvc')) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s -and $s.Status -ne 'Running') {
            Invoke-CPChange "Started service $svc" { Start-Service -Name $svc }
        }
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
        Set-CPRegistryValue -Path $regPath -Name 'Start' -Type DWord -Value 2 -Label "$svc startup type Automatic"
    }

    # ---- Profiles ------------------------------------------------------------------------
    $profileArgs = @{
        Name                             = @('Domain', 'Private', 'Public')
        Enabled                          = 'True'
        DefaultInboundAction             = $set.defaultInboundAction
        DefaultOutboundAction            = $set.defaultOutboundAction
        NotifyOnListen                   = (ConvertTo-CPGpoBoolean $set.notifyOnListen)
        AllowUnicastResponseToMulticast  = (ConvertTo-CPGpoBoolean $set.allowUnicastResponseToMulticast)
        LogFileName                      = $set.logFileName
        LogMaxSizeKilobytes              = [uint64]$set.logMaxSizeKilobytes
        LogBlocked                       = (ConvertTo-CPGpoBoolean $set.logBlocked)
        LogAllowed                       = (ConvertTo-CPGpoBoolean $set.logAllowed)
        LogIgnored                       = (ConvertTo-CPGpoBoolean $set.logIgnored)
    }
    Invoke-CPChange "Firewall enabled on all profiles. Inbound default $($set.defaultInboundAction), outbound default $($set.defaultOutboundAction), logging configured" {
        Set-NetFirewallProfile @profileArgs
    }

    # ---- Disable built-in rule groups ------------------------------------------------------
    if ($set.disableRuleGroups) {
        foreach ($g in @($rules.disableRuleGroups)) {
            if (Test-CPItemSkipped $g $g.group) { continue }
            $found = @(Get-NetFirewallRule -DisplayGroup $g.group -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' })
            if ($found.Count -eq 0) {
                Write-CPLog "Firewall group '$($g.group)' has no enabled rules." INFO
                continue
            }
            Invoke-CPChange "Disabled $($found.Count) rule(s) in firewall group '$($g.group)'" {
                $found | Disable-NetFirewallRule
            }
        }
    }

    # ---- Remove rules created by earlier runs so the script can be run again safely ----------
    $old = @(Get-NetFirewallRule -Group $groupBlock -ErrorAction SilentlyContinue) + @(Get-NetFirewallRule -Group $groupAllow -ErrorAction SilentlyContinue)
    $old = @($old | Where-Object { $_ })
    if ($old.Count -gt 0) {
        Invoke-CPChange "Removed $($old.Count) rule(s) created by an earlier run" { $old | Remove-NetFirewallRule }
    }

    # ---- Block rules --------------------------------------------------------------------------
    if ($set.addBlockRules) {
        foreach ($r in @($rules.blockPorts)) {
            if (Test-CPItemSkipped $r $r.name) { continue }
            $ports = @(([string]$r.ports -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            $protocols = if ($r.protocol -eq 'TCP/UDP') { @('TCP', 'UDP') } else { @($r.protocol) }
            $directions = if ($r.direction -eq 'Both') { @('Inbound', 'Outbound') } else { @($r.direction) }
            foreach ($proto in $protocols) {
                foreach ($dir in $directions) {
                    $ruleArgs = @{
                        DisplayName = "CP Block $($r.name) $proto $dir"
                        Group       = $groupBlock
                        Direction   = $dir
                        Action      = 'Block'
                        Protocol    = $proto
                        Profile     = 'Any'
                        Enabled     = 'True'
                    }
                    # Inbound rules match the port on this machine. Outbound rules match the port on the remote machine.
                    if ($dir -eq 'Inbound') { $ruleArgs.LocalPort = $ports } else { $ruleArgs.RemotePort = $ports }
                    Invoke-CPChange "Blocked $($r.name) ($proto $($ports -join ',') $dir)" { New-NetFirewallRule @ruleArgs }
                }
            }
        }
    }

    if ($set.blockInboundIcmpEcho) {
        Invoke-CPChange 'Blocked inbound ICMPv4 echo requests (ping)' {
            New-NetFirewallRule -DisplayName 'CP Block inbound ping' -Group $groupBlock -Direction Inbound -Action Block -Protocol ICMPv4 -IcmpType 8 -Profile Any
        }
    }

    # ---- Allow rules for critical services ------------------------------------------------------
    foreach ($tag in $script:CP.Critical) {
        $entry = Get-CPProp $script:CP.CriticalMap $tag
        foreach ($g in @(Get-CPProp $entry 'firewallGroups')) {
            if (-not $g) { continue }
            $found = @(Get-NetFirewallRule -DisplayGroup $g -ErrorAction SilentlyContinue)
            if ($found.Count -gt 0) {
                Invoke-CPChange "Enabled firewall group '$g' for critical service $tag" { $found | Enable-NetFirewallRule }
            }
        }
        foreach ($port in @(Get-CPProp $entry 'ports')) {
            if (-not $port) { continue }
            $ports = @(([string]$port.port -split ',') | ForEach-Object { $_.Trim() })
            Invoke-CPChange "Allowed inbound $($port.protocol) $($port.port) for critical service $tag" {
                New-NetFirewallRule -DisplayName "CP Allow $tag $($port.protocol) $($port.port)" -Group $groupAllow -Direction Inbound -Action Allow -Protocol $port.protocol -LocalPort $ports -Profile Any
            }
        }
    }
}
