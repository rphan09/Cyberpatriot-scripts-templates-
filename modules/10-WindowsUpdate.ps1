# Makes sure Windows Update can run and starts a scan. The update policy values
# themselves are in the "WindowsUpdatePolicy" category of config\registry.json.

function Invoke-CPWindowsUpdate {
    $cfg = $script:CP.Settings.windowsUpdate

    foreach ($name in @('wuauserv', 'BITS', 'UsoSvc', 'CryptSvc')) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        $mode = (Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue).StartMode
        if ($mode -eq 'Disabled') {
            $svcName = $name
            Invoke-CPChange "Re-enabled service $svcName required by Windows Update" { Set-CPServiceStartup -Name $svcName -StartupType 'Manual' }
        }
    }
    if ($cfg.setWuauservAutomatic) {
        Invoke-CPChange 'Set Windows Update service (wuauserv) to Automatic' { Set-CPServiceStartup -Name 'wuauserv' -StartupType 'Automatic' }
    }
    $wu = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($wu -and $wu.Status -ne 'Running') {
        Invoke-CPChange 'Started the Windows Update service' { Start-Service -Name wuauserv }
    }

    if ($cfg.triggerScan) {
        $uso = Join-Path $env:SystemRoot 'System32\UsoClient.exe'
        if (Test-Path -LiteralPath $uso) {
            Invoke-CPChange 'Started a Windows Update scan (UsoClient StartScan)' { Start-Process -FilePath $uso -ArgumentList 'StartScan' -WindowStyle Hidden }
        }
        else {
            Invoke-CPChange 'Started a Windows Update scan (wuauclt /detectnow)' { Start-Process -FilePath 'wuauclt.exe' -ArgumentList '/detectnow' -WindowStyle Hidden }
        }
        Write-CPLog 'Open Settings > Windows Update to confirm that updates are downloading. Installation can take a long time, so it should be started early.' INFO
    }
}
