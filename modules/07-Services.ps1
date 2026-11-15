# Disables insecure services and makes sure security services are running.
# Lists come from config\services.json. Services that belong to a critical tag in
# config\competition.json are never disabled.

function Set-CPServiceStartup {
    param([string]$Name, [string]$StartupType)
    $map = @{ 'Automatic' = 2; 'Manual' = 3; 'Disabled' = 4 }
    try {
        Set-Service -Name $Name -StartupType $StartupType -ErrorAction Stop
    }
    catch {
        # Per-user and protected services often reject Set-Service. Writing the Start value works for most of them.
        Set-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$Name" -Name 'Start' -Value $map[$StartupType] -Type DWord -ErrorAction Stop
    }
}

function Invoke-CPServices {
    $cfg = $script:CP.Services
    $protected = $script:CP.ProtectedServices

    # ---- Disable --------------------------------------------------------------------------
    foreach ($item in @($cfg.disable)) {
        $label = "$($item.name) ($($item.description))"
        if (Test-CPItemSkipped $item $label) { continue }

        $found = @(Get-Service -Name $item.name -ErrorAction SilentlyContinue)
        if ($found.Count -eq 0) {
            Write-CPLog "Service $($item.name) is not installed." INFO
            continue
        }
        foreach ($svc in $found) {
            if ($protected -contains $svc.Name) {
                Write-CPLog "Service $($svc.Name) belongs to a critical service and was not disabled." INFO
                continue
            }
            $startType = (Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue).StartMode
            if ($svc.Status -eq 'Stopped' -and $startType -eq 'Disabled') {
                Write-CPLog "Service $($svc.Name) is already stopped and disabled." INFO
                continue
            }
            $svcName = $svc.Name
            Invoke-CPChange "Stopped and disabled service $svcName ($($item.description))" {
                if ((Get-Service -Name $svcName).Status -ne 'Stopped') { Stop-Service -Name $svcName -Force -ErrorAction Stop }
                Set-CPServiceStartup -Name $svcName -StartupType 'Disabled'
            }
        }
    }

    # ---- Ensure running -------------------------------------------------------------------
    $ensure = @($cfg.ensureRunning)
    foreach ($tag in $script:CP.Critical) {
        foreach ($name in @(Get-CPProp (Get-CPProp $script:CP.CriticalMap $tag) 'services')) {
            if ($name) { $ensure += [pscustomobject]@{ name = $name; startupType = 'Automatic'; description = "critical service $tag" } }
        }
    }

    foreach ($item in $ensure) {
        $found = @(Get-Service -Name $item.name -ErrorAction SilentlyContinue)
        if ($found.Count -eq 0) {
            if ($item.description -like 'critical service*') {
                Write-CPLog "Critical service $($item.name) is not installed. Check the README." WARN
            }
            continue
        }
        foreach ($svc in $found) {
            $svcName = $svc.Name
            $startType = (Get-CimInstance Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue).StartMode
            $wantedMode = if ($item.startupType -eq 'Automatic') { 'Auto' } else { $item.startupType }
            if ($startType -ne $wantedMode) {
                Invoke-CPChange "Set service $svcName startup type to $($item.startupType) ($($item.description))" {
                    Set-CPServiceStartup -Name $svcName -StartupType $item.startupType
                }
            }
            if ((Get-Service -Name $svcName).Status -ne 'Running') {
                Invoke-CPChange "Started service $svcName ($($item.description))" { Start-Service -Name $svcName }
            }
        }
    }
}
