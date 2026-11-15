# Configures OpenSSH Server only when SSH is listed as a critical service.
# When SSH is not critical, the sshd service is disabled by the Services step.

function Set-CPSshdOption {
    # Sets "Key Value" in sshd_config. New keys are inserted before the first Match block,
    # because settings placed after a Match line apply only to that block.
    param([System.Collections.Generic.List[string]]$Lines, [string]$Key, [string]$Value)
    $pattern = '^\s*#?\s*' + [regex]::Escape($Key) + '\s+'
    $firstMatch = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match '^\s*Match\s') { $firstMatch = $i; break }
    }
    $limit = if ($firstMatch -ge 0) { $firstMatch } else { $Lines.Count }
    for ($i = 0; $i -lt $limit; $i++) {
        if ($Lines[$i] -match $pattern) {
            $old = $Lines[$i]
            $Lines[$i] = "$Key $Value"
            return $old
        }
    }
    if ($firstMatch -ge 0) { $Lines.Insert($firstMatch, "$Key $Value") } else { $Lines.Add("$Key $Value") }
    return $null
}

function Invoke-CPSsh {
    if (-not (Test-CPCritical 'SSH')) {
        Write-CPLog 'SSH is not a critical service. sshd_config is not changed. The Services step disables sshd if it is installed.' INFO
        return
    }
    $cfg = $script:CP.Settings.ssh
    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-CPLog 'SSH is a critical service, but OpenSSH Server is not installed. Install it with: Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0' WARN
        return
    }

    $path = Expand-CPPath $cfg.sshdConfigPath
    if (-not (Test-Path -LiteralPath $path)) {
        Write-CPLog "sshd_config was not found at $path. Start the sshd service once to create it, then run the SSH step again." WARN
        return
    }

    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($l in (Get-Content -LiteralPath $path)) { $lines.Add($l) }

    $changes = @()
    foreach ($p in $cfg.options.PSObject.Properties) {
        if ($p.Name -like '_*') { continue }
        $old = Set-CPSshdOption -Lines $lines -Key $p.Name -Value ([string]$p.Value)
        if ($old -ne "$($p.Name) $($p.Value)") { $changes += "$($p.Name) $($p.Value)" }
    }

    if ($changes.Count -eq 0) {
        Write-CPLog 'sshd_config already matches settings.json.' INFO
    }
    else {
        Invoke-CPChange "Updated sshd_config: $($changes -join '; ')" {
            Copy-Item -LiteralPath $path -Destination (Join-Path $script:CP.BackupDir 'sshd_config') -Force
            Set-Content -LiteralPath $path -Value $lines -Encoding Ascii
        }
        $sshd = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
        if (Test-Path -LiteralPath $sshd) {
            $test = & $sshd -t 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-CPLog "sshd -t reported a configuration error: $($test -join ' '). Restore the backup from $($script:CP.BackupDir) if sshd does not start." ERROR
            }
        }
    }

    Invoke-CPChange 'Set sshd to Automatic and restarted it' {
        Set-Service -Name sshd -StartupType Automatic
        Restart-Service -Name sshd -Force
    }
}
