# Reviews scheduled tasks. Tasks are disabled, not deleted, so the change can be reversed.

function Invoke-CPTasks {
    $cfg = $script:CP.Settings.tasks
    $all = @(Get-ScheduledTask -ErrorAction SilentlyContinue)

    # ---- Task folders to disable ------------------------------------------------------------
    foreach ($pattern in @($cfg.disableTaskPathPatterns)) {
        if (-not $pattern) { continue }
        foreach ($t in @($all | Where-Object { $_.TaskPath -like $pattern -and $_.State -ne 'Disabled' })) {
            $taskName = $t.TaskName
            $taskPath = $t.TaskPath
            Invoke-CPChange "Disabled scheduled task $taskPath$taskName" { Disable-ScheduledTask -TaskName $taskName -TaskPath $taskPath | Out-Null }
        }
    }

    # ---- Non-Microsoft tasks -----------------------------------------------------------------
    $regex = (@($cfg.suspiciousPatterns) | Where-Object { $_ }) -join '|'
    $rows = @()
    foreach ($t in @($all | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })) {
        $actions = @($t.Actions | ForEach-Object {
            if ($_.PSObject.Properties['Execute']) { ("$($_.Execute) $($_.Arguments)").Trim() } else { $_.CimClass.CimClassName }
        }) -join ' | '
        $suspicious = ($regex -and $actions -match $regex)
        $rows += [pscustomobject]@{
            Path       = "$($t.TaskPath)$($t.TaskName)"
            State      = [string]$t.State
            Author     = $t.Author
            RunAs      = $t.Principal.UserId
            Actions    = $actions
            Suspicious = $suspicious
        }

        if ($suspicious -and $cfg.disableSuspicious -and $t.State -ne 'Disabled') {
            if (Confirm-CPAction "Disable suspicious task $($t.TaskPath)$($t.TaskName) [$actions]?") {
                $taskName = $t.TaskName
                $taskPath = $t.TaskPath
                Invoke-CPChange "Disabled suspicious scheduled task $taskPath$taskName ($actions)" { Disable-ScheduledTask -TaskName $taskName -TaskPath $taskPath | Out-Null }
            }
        }
    }
    Export-CPReport 'scheduled-tasks-non-microsoft' $rows
}
