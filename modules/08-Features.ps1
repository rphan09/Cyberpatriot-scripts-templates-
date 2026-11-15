# Removes insecure Windows optional features and disables SMBv1.
# The feature list is in the "features" section of config\settings.json.

function Invoke-CPFeatures {
    $cfg = $script:CP.Settings.features

    foreach ($item in @($cfg.disable)) {
        if (Test-CPItemSkipped $item $item.name) { continue }
        $feature = $null
        try { $feature = Get-WindowsOptionalFeature -Online -FeatureName $item.name -ErrorAction Stop } catch { }
        if (-not $feature) {
            Write-CPLog "Optional feature $($item.name) does not exist on this edition." INFO
            continue
        }
        if ($feature.State -notlike 'Enabled*') {
            Write-CPLog "Optional feature $($item.name) is already disabled." INFO
            continue
        }
        $featureName = $item.name
        Invoke-CPChange "Disabled optional feature $featureName ($($item.description))" {
            $r = Disable-WindowsOptionalFeature -Online -FeatureName $featureName -NoRestart -ErrorAction Stop
            if ($r.RestartNeeded) { $script:CP.RebootNeeded = $true }
        }
    }

    if ($cfg.disableSmb1Server) {
        $smb = $null
        try { $smb = Get-SmbServerConfiguration -ErrorAction Stop } catch { }
        if ($smb -and $smb.EnableSMB1Protocol) {
            Invoke-CPChange 'Disabled the SMBv1 server protocol' { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force }
        }
    }
}
