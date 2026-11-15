# Removes SMB shares that are not default, not required by the README and not on the keep list.

function Invoke-CPShares {
    if (-not (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) {
        Write-CPLog 'The SMB share cmdlets are not available.' WARN
        return
    }
    $keep = @(@($script:CP.Settings.shares.keep) + @($script:CP.Competition.requiredShares) | Where-Object { $_ })
    $shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { -not $_.Special -and $keep -notcontains $_.Name })

    # Report shares that grant access to Everyone, Guests or Anonymous.
    $rows = @()
    foreach ($s in @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { -not $_.Special })) {
        foreach ($a in @(Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue)) {
            if ($a.AccountName -match 'Everyone|Guest|ANONYMOUS') {
                $rows += [pscustomobject]@{ Share = $s.Name; Path = $s.Path; Account = $a.AccountName; Right = $a.AccessRight; Control = $a.AccessControlType }
            }
        }
    }
    Export-CPReport 'shares-open-access' $rows

    if ($shares.Count -eq 0) {
        Write-CPLog 'No non-default shares found.' INFO
        return
    }

    $reportOnly = (Test-CPCritical 'SMB') -and (@($script:CP.Competition.requiredShares).Count -eq 0)
    foreach ($s in $shares) {
        if ($reportOnly) {
            Write-CPLog "Share '$($s.Name)' ($($s.Path)) was found. SMB is a critical service and requiredShares is empty, so it was not removed." REPORT
            continue
        }
        if (Confirm-CPAction "Remove share '$($s.Name)' ($($s.Path))?") {
            $shareName = $s.Name
            Invoke-CPChange "Removed share '$shareName' ($($s.Path))" { Remove-SmbShare -Name $shareName -Force }
        }
    }
}
