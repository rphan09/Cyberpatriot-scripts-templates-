# Reports installed programs and executables that match config\prohibited.json.
# Uninstalling is optional and off by default.

function Get-CPInstalledPrograms {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($hive in @(Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
        $keys += "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    }
    foreach ($k in $keys) {
        Get-ItemProperty -Path $k -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation, UninstallString, QuietUninstallString
    }
}

function Invoke-CPSoftwareReport {
    $cfg = $script:CP.Settings.software
    $prohibited = @(@($script:CP.Prohibited.software) | Where-Object { $_ })
    $required = @(@($script:CP.Competition.requiredSoftware) | Where-Object { $_ })

    $installed = @(Get-CPInstalledPrograms)
    Export-CPReport 'installed-programs' ($installed | Sort-Object DisplayName -Unique)

    $hits = @()
    foreach ($prog in $installed) {
        $isRequired = $false
        foreach ($r in $required) { if ($prog.DisplayName -like "*$r*") { $isRequired = $true } }
        if ($isRequired) { continue }
        foreach ($p in $prohibited) {
            if ($prog.DisplayName -like "*$p*") {
                $hits += [pscustomobject]@{ Program = $prog.DisplayName; Version = $prog.DisplayVersion; MatchedRule = $p; UninstallString = $prog.UninstallString; QuietUninstallString = $prog.QuietUninstallString }
                break
            }
        }
    }

    # Microsoft Store apps such as games.
    foreach ($pkg in @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue)) {
        foreach ($p in @($script:CP.Prohibited.storeApps)) {
            if ($p -and $pkg.Name -like "*$p*") {
                $hits += [pscustomobject]@{ Program = $pkg.Name; Version = $pkg.Version; MatchedRule = $p; UninstallString = "Remove-AppxPackage -AllUsers -Package $($pkg.PackageFullName)"; QuietUninstallString = '' }
                break
            }
        }
    }
    Export-CPReport 'prohibited-software' $hits

    # Stand-alone executables of hacking tools that do not appear in Programs and Features.
    $names = @(@($script:CP.Prohibited.executables) | Where-Object { $_ })
    $exeRows = @()
    if ($names.Count -gt 0) {
        foreach ($root in @($cfg.executableSearchRoots)) {
            $rootPath = Expand-CPPath $root
            if (-not (Test-Path -LiteralPath $rootPath)) { continue }
            foreach ($f in @(Get-ChildItem -LiteralPath $rootPath -Recurse -File -Force -Include $names -ErrorAction SilentlyContinue)) {
                $exeRows += [pscustomobject]@{ File = $f.FullName; Size = $f.Length; Modified = $f.LastWriteTime }
            }
        }
    }
    Export-CPReport 'prohibited-executables' $exeRows

    if ($cfg.attemptUninstall) {
        foreach ($m in $hits) {
            $cmd = if ($m.QuietUninstallString) { $m.QuietUninstallString } else { $m.UninstallString }
            if (-not $cmd) { continue }
            if (-not (Confirm-CPAction "Uninstall '$($m.Program)' with: $cmd ?")) { continue }
            $program = $m.Program
            if ($cmd -match '(?i)msiexec(\.exe)?\s+/[IX]\s*(\{[0-9A-F-]+\})') {
                $guid = $Matches[2]
                Invoke-CPChange "Uninstalled '$program' (MSI $guid)" { Start-Process -FilePath 'msiexec.exe' -ArgumentList '/x', $guid, '/qn', '/norestart' -Wait }
            }
            elseif ($cmd -like 'Remove-AppxPackage*') {
                $full = ($cmd -split ' ')[-1]
                Invoke-CPChange "Removed Store app '$program'" { Remove-AppxPackage -AllUsers -Package $full }
            }
            else {
                Invoke-CPChange "Started the uninstaller for '$program'. Complete it in the window that opens" { Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $cmd -Wait }
            }
        }
    }
}
