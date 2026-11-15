# Applies password policy, lockout policy, legacy audit policy and user rights assignment
# through secedit. Values come from config\security-policy.json.

function Set-CPInfValue {
    # Sets "Key = Value" inside [Section] of an INF file held as a list of lines.
    # Returns the previous value, or $null when the key did not exist.
    param(
        [System.Collections.Generic.List[string]]$Lines,
        [string]$Section,
        [string]$Key,
        [string]$Value
    )
    $header = "[$Section]"
    $start = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i].Trim() -eq $header) { $start = $i; break }
    }
    if ($start -lt 0) {
        $Lines.Add($header)
        $Lines.Add("$Key = $Value")
        return $null
    }
    $end = $Lines.Count
    for ($j = $start + 1; $j -lt $Lines.Count; $j++) {
        if ($Lines[$j].Trim().StartsWith('[')) { $end = $j; break }
    }
    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    for ($k = $start + 1; $k -lt $end; $k++) {
        if ($Lines[$k] -match $pattern) {
            $old = ($Lines[$k] -split '=', 2)[1].Trim()
            $Lines[$k] = "$Key = $Value"
            return $old
        }
    }
    $Lines.Insert($end, "$Key = $Value")
    return $null
}

function Invoke-CPSecurityPolicy {
    $policy = $script:CP.SecurityPolicy
    $usersCfg = $script:CP.Settings.users

    # Copy System Access values into a hashtable so they can be adjusted safely.
    $sa = [ordered]@{}
    foreach ($p in $policy.SystemAccess.PSObject.Properties) {
        if ($p.Name -notlike '_*') { $sa[$p.Name] = $p.Value }
    }

    # ---- Validation -----------------------------------------------------------------
    if ($sa.Contains('MinimumPasswordAge') -and $sa.Contains('MaximumPasswordAge')) {
        if ([int]$sa.MaximumPasswordAge -gt 0 -and [int]$sa.MinimumPasswordAge -ge [int]$sa.MaximumPasswordAge) {
            Write-CPLog "MinimumPasswordAge ($($sa.MinimumPasswordAge)) must be lower than MaximumPasswordAge ($($sa.MaximumPasswordAge)). Correct security-policy.json." ERROR
            return
        }
    }
    if ($sa.Contains('ResetLockoutCount') -and $sa.Contains('LockoutDuration')) {
        if ([int]$sa.LockoutDuration -ge 0 -and [int]$sa.ResetLockoutCount -gt [int]$sa.LockoutDuration) {
            Write-CPLog "ResetLockoutCount ($($sa.ResetLockoutCount)) cannot exceed LockoutDuration ($($sa.LockoutDuration)). ResetLockoutCount will be set to $($sa.LockoutDuration)." WARN
            $sa.ResetLockoutCount = $sa.LockoutDuration
        }
    }
    if ($sa.Contains('MinimumPasswordLength') -and [int]$sa.MinimumPasswordLength -gt 14) {
        Write-CPLog "MinimumPasswordLength above 14 requires the 'Relax minimum password length limits' setting. It will be enabled. Older Windows versions accept a maximum of 14." WARN
        Set-CPRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SAM' -Name 'RelaxMinimumPasswordLengthLimits' -Type DWord -Value 1 -Label 'Relax minimum password length limits'
    }

    # Do not disable the built-in Administrator account when it is the account running this script.
    $currentSid = Get-CPCurrentUserSid
    if ($currentSid -match '-500$' -and $sa.Contains('EnableAdminAccount') -and [int]$sa.EnableAdminAccount -eq 0) {
        Write-CPLog 'This script is running as the built-in Administrator account. That account will not be disabled. Disable it manually after logging in as another administrator.' WARN
        $sa.Remove('EnableAdminAccount')
    }

    # Optional renaming of built-in accounts.
    if ($usersCfg.renameAdministratorTo) { $sa['NewAdministratorName'] = '"' + $usersCfg.renameAdministratorTo + '"' }
    if ($usersCfg.renameGuestTo)         { $sa['NewGuestName']         = '"' + $usersCfg.renameGuestTo + '"' }

    # ---- Build the INF ----------------------------------------------------------------
    $exported = Join-Path $script:CP.WorkDir 'secpol-export.inf'
    $newInf   = Join-Path $script:CP.WorkDir 'secpol-new.inf'
    $database = Join-Path $script:CP.WorkDir 'secpol.sdb'

    try {
        Invoke-CPNative 'secedit.exe' @('/export', '/cfg', $exported, '/quiet') | Out-Null
    }
    catch {
        Write-CPLog "Could not export the current security policy: $($_.Exception.Message)" ERROR
        return
    }

    $lines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($l in (Get-Content -LiteralPath $exported)) { $lines.Add($l) }

    $planned = New-Object 'System.Collections.Generic.List[string]'

    foreach ($key in $sa.Keys) {
        $old = Set-CPInfValue -Lines $lines -Section 'System Access' -Key $key -Value ([string]$sa[$key])
        if ("$old" -ne [string]$sa[$key]) { $planned.Add("System Access: $key changed from $(if ($null -eq $old) { '<not set>' } else { $old }) to $($sa[$key])") }
    }

    foreach ($p in $policy.EventAudit.PSObject.Properties) {
        if ($p.Name -like '_*') { continue }
        $old = Set-CPInfValue -Lines $lines -Section 'Event Audit' -Key $p.Name -Value ([string]$p.Value)
        if ("$old" -ne [string]$p.Value) { $planned.Add("Event Audit: $($p.Name) changed from $(if ($null -eq $old) { '<not set>' } else { $old }) to $($p.Value)") }
    }

    $areas = @('SECURITYPOLICY')
    $applyRights = [bool]$script:CP.Settings.securityPolicy.applyUserRights
    if ($applyRights -and $script:CP.IsDomainController) {
        Write-CPLog 'User rights assignment is skipped on a domain controller. Configure it in the Default Domain Controllers Policy instead.' WARN
        $applyRights = $false
    }
    if ($applyRights) {
        $areas += 'USER_RIGHTS'
        foreach ($p in $policy.PrivilegeRights.PSObject.Properties) {
            if ($p.Name -like '_*') { continue }
            $value = (@($p.Value) | Where-Object { $_ }) -join ','
            $old = Set-CPInfValue -Lines $lines -Section 'Privilege Rights' -Key $p.Name -Value $value
            if ("$old" -ne $value) { $planned.Add("Privilege Rights: $($p.Name) changed from $(if ($null -eq $old) { '<not set>' } else { $old }) to $(if ($value) { $value } else { '<no one>' })") }
        }
    }

    if ($planned.Count -eq 0) {
        Write-CPLog 'Security policy already matches security-policy.json.' INFO
        return
    }

    if ($script:CP.DryRun) {
        foreach ($p in $planned) { Write-CPLog "Would set $p" DRYRUN }
        return
    }

    Set-Content -LiteralPath $newInf -Value $lines -Encoding Unicode
    $output = & secedit.exe /configure /db $database /cfg $newInf /areas @areas /quiet 2>&1
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        foreach ($p in $planned) { Write-CPLog $p CHANGE }
    }
    else {
        foreach ($p in $planned) { Write-CPLog "Attempted: $p" INFO }
        Write-CPLog "secedit returned exit code $code. Some settings may not have applied. Check $env:SystemRoot\security\logs\scesrv.log. $($output -join ' ')" WARN
    }
}
