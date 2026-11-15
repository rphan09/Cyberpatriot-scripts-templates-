# Writes a Firefox enterprise policies.json. Chrome and Edge policies are registry values
# and are applied by the "ChromePolicy" and "EdgePolicy" categories of config\registry.json.

function Invoke-CPBrowsers {
    $cfg = $script:CP.Settings.browsers
    if (-not $cfg.firefox.enabled) {
        Write-CPLog 'Firefox policies are disabled in settings.json.' INFO
        return
    }

    $dirs = @(
        foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
            if (-not $base) { continue }
            $candidate = Join-Path $base 'Mozilla Firefox'
            if (Test-Path -LiteralPath (Join-Path $candidate 'firefox.exe')) { $candidate }
        }
    ) | Sort-Object -Unique

    if (@($dirs).Count -eq 0) {
        Write-CPLog 'Firefox is not installed.' INFO
        return
    }

    $json = (@{ policies = $cfg.firefox.policies } | ConvertTo-Json -Depth 10)
    foreach ($dir in $dirs) {
        $dist = Join-Path $dir 'distribution'
        $file = Join-Path $dist 'policies.json'
        Invoke-CPChange "Wrote Firefox policies to $file" {
            if (-not (Test-Path -LiteralPath $dist)) { New-Item -ItemType Directory -Path $dist -Force | Out-Null }
            if (Test-Path -LiteralPath $file) {
                Copy-Item -LiteralPath $file -Destination (Join-Path $script:CP.BackupDir 'firefox-policies.json') -Force
            }
            # Firefox does not accept a byte order mark, so the file is written as UTF-8 without one.
            [System.IO.File]::WriteAllText($file, $json, (New-Object System.Text.UTF8Encoding($false)))
        }
    }
    Write-CPLog 'Restart Firefox and open about:policies to confirm that the policies are active.' INFO
}
