# Report-only. Lists locations where malware and backdoors commonly persist.
# Nothing is changed. Every finding must be reviewed manually.

function Invoke-CPPersistenceReport {
    # ---- Run keys ------------------------------------------------------------------------
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($hive in @(Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) {
        $runKeys += "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
        $runKeys += "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    $rows = @()
    foreach ($key in $runKeys) {
        $props = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        if (-not $props) { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -like 'PS*') { continue }
            $rows += [pscustomobject]@{ Location = $key; Name = $p.Name; Command = $p.Value }
        }
    }

    # ---- Startup folders -------------------------------------------------------------------
    $folders = @(Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp')
    foreach ($userProfile in @(Get-ChildItem -Path (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue)) {
        $folders += Join-Path $userProfile.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'
    }
    foreach ($f in $folders) {
        foreach ($file in @(Get-ChildItem -LiteralPath $f -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
            $rows += [pscustomobject]@{ Location = $f; Name = $file.Name; Command = $file.FullName }
        }
    }
    Export-CPReport 'autostart-entries' $rows

    # ---- Winlogon, AppInit and Image File Execution Options -------------------------------------
    $rows = @()
    $winlogon = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    if ($winlogon) {
        if ($winlogon.Shell -and $winlogon.Shell -ne 'explorer.exe') {
            $rows += [pscustomobject]@{ Check = 'Winlogon Shell is not explorer.exe'; Value = $winlogon.Shell }
        }
        if ($winlogon.Userinit -and $winlogon.Userinit.TrimEnd(',') -notmatch '\\system32\\userinit\.exe$') {
            $rows += [pscustomobject]@{ Check = 'Winlogon Userinit is not the default'; Value = $winlogon.Userinit }
        }
        if ($winlogon.DefaultPassword) {
            $rows += [pscustomobject]@{ Check = 'Plain-text automatic logon password stored in Winlogon'; Value = '<hidden>' }
        }
    }
    foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        $w = Get-ItemProperty -LiteralPath $key -ErrorAction SilentlyContinue
        if ($w -and $w.AppInit_DLLs) { $rows += [pscustomobject]@{ Check = "AppInit_DLLs is set ($key)"; Value = $w.AppInit_DLLs } }
    }
    foreach ($ifeo in @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue)) {
        $d = (Get-ItemProperty -LiteralPath $ifeo.PSPath -ErrorAction SilentlyContinue).Debugger
        if ($d) { $rows += [pscustomobject]@{ Check = "Image File Execution Options debugger for $($ifeo.PSChildName)"; Value = $d } }
    }

    # Accessibility programs that can be replaced to open a SYSTEM shell at the logon screen.
    foreach ($exe in @('sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe')) {
        $file = Join-Path $env:SystemRoot "System32\$exe"
        if (-not (Test-Path -LiteralPath $file)) { continue }
        $sig = Get-AuthenticodeSignature -LiteralPath $file -ErrorAction SilentlyContinue
        $desc = (Get-Item -LiteralPath $file).VersionInfo.FileDescription
        if (-not $sig -or $sig.Status -ne 'Valid' -or $desc -match 'Command Processor|PowerShell') {
            $rows += [pscustomobject]@{ Check = "$exe is not a valid Microsoft-signed accessibility program"; Value = "Signature: $($sig.Status). Description: $desc" }
        }
    }
    Export-CPReport 'backdoor-checks' $rows

    # ---- Services outside the Windows folder ---------------------------------------------------
    $rows = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.PathName -and $_.PathName -notmatch '(?i)\\Windows\\(System32|SysWOW64|Microsoft\.NET|servicing|WinSxS)\\' -and $_.PathName -notmatch '(?i)\\Program Files( \(x86\))?\\(Windows Defender|Microsoft|Common Files\\Microsoft)' } |
        Select-Object Name, DisplayName, State, StartMode, StartName, PathName)
    Export-CPReport 'services-non-windows' $rows

    # ---- WMI event subscriptions --------------------------------------------------------------
    $rows = @()
    foreach ($class in @('__EventFilter', 'CommandLineEventConsumer', 'ActiveScriptEventConsumer', '__FilterToConsumerBinding')) {
        foreach ($o in @(Get-CimInstance -Namespace 'root\subscription' -ClassName $class -ErrorAction SilentlyContinue)) {
            if ($o.Name -eq 'SCM Event Log Filter' -or $o.Name -eq 'SCM Event Log Consumer') { continue }
            $detail = if ($o.PSObject.Properties['CommandLineTemplate']) { $o.CommandLineTemplate } elseif ($o.PSObject.Properties['Query']) { $o.Query } else { [string]$o.Consumer }
            $rows += [pscustomobject]@{ Class = $class; Name = $o.Name; Detail = $detail }
        }
    }
    Export-CPReport 'wmi-subscriptions' $rows

    # ---- Listening ports ------------------------------------------------------------------------
    $rows = @()
    foreach ($c in @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
        $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        $rows += [pscustomobject]@{ Protocol = 'TCP'; Address = $c.LocalAddress; Port = $c.LocalPort; Process = $proc.ProcessName; Path = $proc.Path }
    }
    foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
        $proc = Get-Process -Id $u.OwningProcess -ErrorAction SilentlyContinue
        $rows += [pscustomobject]@{ Protocol = 'UDP'; Address = $u.LocalAddress; Port = $u.LocalPort; Process = $proc.ProcessName; Path = $proc.Path }
    }
    Export-CPReport 'listening-ports' ($rows | Sort-Object Protocol, Port -Unique)
}
