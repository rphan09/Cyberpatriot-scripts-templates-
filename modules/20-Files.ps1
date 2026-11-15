# Finds media files, password lists and other prohibited files. By default the files are only
# reported. When "action" is "Quarantine", they are moved to the quarantine folder instead of deleted.

function Invoke-CPFilesReport {
    $cfg = $script:CP.Settings.files
    $p = $script:CP.Prohibited

    $extensions = @(@($p.mediaExtensions) + @($p.otherExtensions) | Where-Object { $_ } | ForEach-Object { '*' + $_.TrimStart('*') })
    $namePatterns = @(@($p.namePatterns) | Where-Object { $_ })
    $exclude = @(@($cfg.excludePathPatterns) | Where-Object { $_ })

    $rows = @()
    foreach ($root in @($cfg.roots)) {
        $rootPath = Expand-CPPath $root
        if (-not (Test-Path -LiteralPath $rootPath)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $rootPath -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            $skip = $false
            foreach ($e in $exclude) { if ($f.FullName -like $e) { $skip = $true; break } }
            if ($skip) { continue }

            $reason = $null
            foreach ($ext in $extensions) { if ($f.Name -like $ext) { $reason = "extension $ext"; break } }
            if (-not $reason) {
                foreach ($n in $namePatterns) { if ($f.Name -like $n) { $reason = "name matches $n"; break } }
            }
            if ($reason) {
                $rows += [pscustomobject]@{ File = $f.FullName; Reason = $reason; SizeKB = [math]::Round($f.Length / 1KB, 1); Modified = $f.LastWriteTime }
            }
        }
    }
    Export-CPReport 'prohibited-files' $rows

    if ($cfg.action -eq 'Quarantine' -and $rows.Count -gt 0) {
        $q = Expand-CPPath $cfg.quarantinePath
        if (Confirm-CPAction "Move $($rows.Count) file(s) to $q ? Check that none of them is needed for a forensic question.") {
            foreach ($r in $rows) {
                $src = $r.File
                $dest = Join-Path $q ($src -replace '^[A-Za-z]:\\', '' )
                Invoke-CPChange "Moved $src to quarantine" {
                    New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force | Out-Null
                    Move-Item -LiteralPath $src -Destination $dest -Force
                }
            }
        }
    }
}
