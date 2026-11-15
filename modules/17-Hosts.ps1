# Checks the hosts file for entries that redirect names, and optionally resets it.

function Invoke-CPHosts {
    $cfg = $script:CP.Settings.hosts
    $path = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (-not (Test-Path -LiteralPath $path)) {
        Write-CPLog 'The hosts file does not exist.' INFO
        return
    }

    $entries = @(Get-Content -LiteralPath $path | Where-Object { $_.Trim() -and $_.Trim() -notmatch '^#' })
    $rows = @($entries | ForEach-Object { [pscustomobject]@{ Entry = $_.Trim() } })
    Export-CPReport 'hosts-entries' $rows

    if ($entries.Count -eq 0) { return }

    if ($cfg.action -eq 'Reset') {
        $default = @(
            '# Hosts file reset by CP-Hardening.',
            '# localhost name resolution is handled within DNS itself.',
            '#   127.0.0.1       localhost',
            '#   ::1             localhost'
        )
        Invoke-CPChange "Reset the hosts file. $($entries.Count) entr(ies) removed. A copy is in the backup folder" {
            Copy-Item -LiteralPath $path -Destination (Join-Path $script:CP.BackupDir 'hosts.before-reset') -Force
            $item = Get-Item -LiteralPath $path
            if ($item.IsReadOnly) { $item.IsReadOnly = $false }
            Set-Content -LiteralPath $path -Value $default -Encoding Ascii
        }
        Invoke-CPChange 'Flushed the DNS client cache' { Clear-DnsClientCache }
    }
    else {
        Write-CPLog "The hosts file has $($entries.Count) active entr(ies). Review hosts-entries.csv." REPORT
    }
}
