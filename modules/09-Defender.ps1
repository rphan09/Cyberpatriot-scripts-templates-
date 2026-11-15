# Configures Microsoft Defender Antivirus. Preferences are in the "defender" section of
# config\settings.json. Policy values that turn Defender off are removed by the
# "DefenderPolicy" category of config\registry.json.

function Invoke-CPDefender {
    $cfg = $script:CP.Settings.defender

    if (-not (Get-Command Set-MpPreference -ErrorAction SilentlyContinue)) {
        Write-CPLog 'The Defender cmdlets are not available. Defender may be removed or replaced by another antivirus product.' WARN
        return
    }

    $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running') {
        Invoke-CPChange 'Started the Microsoft Defender Antivirus service' { Start-Service -Name WinDefend }
    }

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        if ($status.IsTamperProtected) {
            Write-CPLog 'Tamper Protection is on. Some Defender preferences can only be changed in Windows Security.' INFO
        }
    }
    catch { }

    # Each preference is set separately so that one rejected value does not stop the rest.
    foreach ($p in $cfg.preferences.PSObject.Properties) {
        if ($p.Name -like '_*') { continue }
        $prefName = $p.Name
        $prefValue = $p.Value
        Invoke-CPChange "Defender preference $prefName set to $prefValue" {
            $args1 = @{ $prefName = $prefValue }
            Set-MpPreference @args1
        }
    }

    # ---- Exclusions -------------------------------------------------------------------------
    $mp = Get-MpPreference
    $rows = @()
    foreach ($kind in @('ExclusionPath', 'ExclusionExtension', 'ExclusionProcess', 'ExclusionIpAddress')) {
        foreach ($value in @($mp.$kind)) {
            if ($value) { $rows += [pscustomobject]@{ Type = $kind; Value = $value } }
        }
    }
    Export-CPReport 'defender-exclusions' $rows
    if ($cfg.removeExclusions) {
        foreach ($row in $rows) {
            $kind = $row.Type
            $value = $row.Value
            Invoke-CPChange "Removed Defender exclusion $kind '$value'" {
                $args2 = @{ $kind = $value }
                Remove-MpPreference @args2
            }
        }
    }

    # ---- Signatures and scan ----------------------------------------------------------------
    if ($cfg.updateSignatures) {
        Invoke-CPChange 'Updated Defender signatures' { Update-MpSignature -ErrorAction Stop }
    }
    if ($cfg.startQuickScan) {
        $mpcmd = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
        if (Test-Path -LiteralPath $mpcmd) {
            Invoke-CPChange 'Started a Defender quick scan in the background' {
                Start-Process -FilePath $mpcmd -ArgumentList '-Scan', '-ScanType', '1' -WindowStyle Hidden
            }
        }
    }
}
