# Manages local users and groups according to config\competition.json and the
# "users" section of config\settings.json.

function Get-CPGroupMembers {
    # Returns objects with Name (short name), FullName, ObjectClass and IsLocal.
    # Falls back to ADSI when Get-LocalGroupMember fails (it fails when a group contains orphaned SIDs).
    param([string]$GroupName)
    $computer = $env:COMPUTERNAME
    try {
        return @(Get-LocalGroupMember -Group $GroupName -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Name        = ($_.Name -split '\\')[-1]
                FullName    = $_.Name
                ObjectClass = [string]$_.ObjectClass
                IsLocal     = ([string]$_.PrincipalSource -eq 'Local') -or ($_.Name -like "$computer\*")
            }
        })
    }
    catch {
        $result = @()
        $group = [ADSI]"WinNT://$computer/$GroupName,group"
        foreach ($m in @($group.psbase.Invoke('Members'))) {
            $path = $m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
            $name = $m.GetType().InvokeMember('Name', 'GetProperty', $null, $m, $null)
            $class = $m.GetType().InvokeMember('Class', 'GetProperty', $null, $m, $null)
            $result += [pscustomobject]@{
                Name        = $name
                FullName    = $path
                ObjectClass = $class
                IsLocal     = ($path -like "WinNT://$computer/*") -or ($path -like "WinNT://*/$computer/*")
            }
        }
        return $result
    }
}

function Invoke-CPUsers {
    if ($script:CP.IsDomainController) {
        Write-CPLog 'This machine is a domain controller. Local user management does not apply. Manage domain users in Active Directory Users and Computers.' WARN
        return
    }

    $comp = $script:CP.Competition
    $cfg  = $script:CP.Settings.users

    $authAdmins = @(@($comp.authorizedAdministrators) | Where-Object { $_ } | ForEach-Object { $_.Trim() })
    $authUsersOnly = @(@($comp.authorizedUsers) | Where-Object { $_ } | ForEach-Object { $_.Trim() })

    if ($authAdmins.Count -eq 0 -and $authUsersOnly.Count -eq 0) {
        Write-CPLog 'competition.json does not list any authorized users or administrators. User management is skipped to avoid removing valid accounts.' WARN
        return
    }

    $currentName = $env:USERNAME
    $currentSid  = Get-CPCurrentUserSid
    $authAll = @($authAdmins + $authUsersOnly + $currentName | Sort-Object -Unique)

    $builtinRids = '-(500|501|503|504)$'
    $localUsers = @(Get-LocalUser)
    $regularUsers = @($localUsers | Where-Object { $_.SID.Value -notmatch $builtinRids })

    # ---- Unauthorized users ------------------------------------------------------------
    $unauthorized = @($regularUsers | Where-Object { $authAll -notcontains $_.Name })
    foreach ($u in $unauthorized) {
        switch ($cfg.unauthorizedUserAction) {
            'Remove' {
                if (Confirm-CPAction "Remove unauthorized user '$($u.Name)'?") {
                    Invoke-CPChange "Removed unauthorized user '$($u.Name)'" { Remove-LocalUser -SID $u.SID }
                }
                else { Write-CPLog "Kept user '$($u.Name)' at the operator's request." INFO }
            }
            'Disable' {
                Invoke-CPChange "Disabled unauthorized user '$($u.Name)'" { Disable-LocalUser -SID $u.SID }
            }
            default {
                Write-CPLog "Unauthorized user found: '$($u.Name)'. Not changed because unauthorizedUserAction is '$($cfg.unauthorizedUserAction)'." REPORT
            }
        }
    }

    # ---- Missing authorized users ------------------------------------------------------
    $existingNames = @($localUsers | ForEach-Object { $_.Name })
    $missing = @($authAll | Where-Object { $existingNames -notcontains $_ })

    $password = $null
    $needPassword = ([bool]$cfg.setPasswords) -or ($missing.Count -gt 0 -and [bool]$cfg.createMissingUsers)
    if ($needPassword -and -not $script:CP.DryRun) {
        if ($comp.defaultPassword) {
            $password = ConvertTo-SecureString -String $comp.defaultPassword -AsPlainText -Force
        }
        elseif (-not $script:CP.Force) {
            $password = Read-Host 'Enter the password to assign to authorized users (the current account is not changed)' -AsSecureString
        }
        else {
            Write-CPLog 'No defaultPassword in competition.json and -Force was used, so no password can be requested. Passwords will not be changed.' WARN
        }
    }

    foreach ($name in $missing) {
        if ($cfg.createMissingUsers -and ($password -or $script:CP.DryRun)) {
            Invoke-CPChange "Created missing authorized user '$name'" { New-LocalUser -Name $name -Password $password -PasswordNeverExpires:$false }
        }
        else {
            Write-CPLog "Authorized user '$name' does not exist on this machine. Create it if the README requires it." REPORT
        }
    }

    # ---- Administrators group ------------------------------------------------------------
    $adminGroup = (Get-LocalGroup -SID 'S-1-5-32-544').Name
    $usersGroup = (Get-LocalGroup -SID 'S-1-5-32-545').Name
    $members = @(Get-CPGroupMembers $adminGroup)

    foreach ($m in $members) {
        $isBuiltinAdmin = ($m.IsLocal -and ($localUsers | Where-Object { $_.Name -eq $m.Name -and $_.SID.Value -match '-500$' }))
        if ($isBuiltinAdmin) { continue }
        if (-not $m.IsLocal) {
            Write-CPLog "Administrators contains non-local member '$($m.FullName)'. Review it manually." REPORT
            continue
        }
        if ($authAdmins -contains $m.Name -or $m.Name -eq $currentName) { continue }

        if ($cfg.unauthorizedAdminAction -eq 'Demote') {
            Invoke-CPChange "Removed '$($m.Name)' from the $adminGroup group" {
                Invoke-CPNative 'net.exe' @('localgroup', $adminGroup, $m.Name, '/delete') | Out-Null
            }
        }
        else {
            Write-CPLog "'$($m.Name)' is an administrator but is not listed as one in competition.json." REPORT
        }
    }

    if ($cfg.addMissingAdministrators) {
        $memberNames = @($members | ForEach-Object { $_.Name })
        foreach ($name in $authAdmins) {
            if ($memberNames -contains $name) { continue }
            if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) -and -not $script:CP.DryRun) {
                Write-CPLog "Cannot add '$name' to $adminGroup because the account does not exist." WARN
                continue
            }
            Invoke-CPChange "Added authorized administrator '$name' to the $adminGroup group" {
                Invoke-CPNative 'net.exe' @('localgroup', $adminGroup, $name, '/add') | Out-Null
            }
        }
    }

    # Make sure standard users are in the Users group.
    $userMembers = @(Get-CPGroupMembers $usersGroup | ForEach-Object { $_.Name })
    foreach ($name in $authAll) {
        if ($userMembers -contains $name) { continue }
        if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) { continue }
        Invoke-CPChange "Added '$name' to the $usersGroup group" {
            Invoke-CPNative 'net.exe' @('localgroup', $usersGroup, $name, '/add') | Out-Null
        }
    }

    # ---- Account properties for authorized users ------------------------------------------
    foreach ($name in $authAll) {
        $u = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
        if (-not $u) { continue }
        $isCurrent = ($u.SID.Value -eq $currentSid)

        if ($cfg.setPasswords -and $password -and -not $isCurrent) {
            Invoke-CPChange "Set a new password for '$name'" { Set-LocalUser -SID $u.SID -Password $password }
        }

        if (-not $cfg.passwordNeverExpires -and $null -eq $u.PasswordExpires) {
            Invoke-CPChange "Cleared 'Password never expires' for '$name'" { Set-LocalUser -SID $u.SID -PasswordNeverExpires $false }
        }

        if ($cfg.requirePassword -and -not $u.PasswordRequired) {
            Invoke-CPChange "Required a password for '$name'" { Invoke-CPNative 'net.exe' @('user', $name, '/passwordreq:yes') | Out-Null }
        }

        if (-not $u.UserMayChangePassword) {
            Invoke-CPChange "Allowed '$name' to change their password" { Set-LocalUser -SID $u.SID -UserMayChangePassword $true }
        }

        if ($cfg.requirePasswordChangeAtNextLogon -and -not $isCurrent) {
            Invoke-CPChange "Required '$name' to change their password at next logon" { Invoke-CPNative 'net.exe' @('user', $name, '/logonpasswordchg:yes') | Out-Null }
        }

        if (-not $u.Enabled) {
            if ($cfg.enableDisabledAuthorizedUsers) {
                Invoke-CPChange "Enabled authorized user '$name'" { Enable-LocalUser -SID $u.SID }
            }
            else {
                Write-CPLog "Authorized user '$name' is disabled. Enable it if the README requires it." REPORT
            }
        }
    }

    # ---- Built-in accounts -------------------------------------------------------------------
    $guest = Get-CPBuiltinAccount 501
    if ($cfg.disableGuest -and $guest -and $guest.Enabled) {
        Invoke-CPChange "Disabled the built-in Guest account ('$($guest.Name)')" { Disable-LocalUser -SID $guest.SID }
    }
    $admin = Get-CPBuiltinAccount 500
    if ($cfg.disableBuiltinAdministrator -and $admin -and $admin.Enabled) {
        if ($admin.SID.Value -eq $currentSid) {
            Write-CPLog 'The built-in Administrator account is the current account and will not be disabled.' WARN
        }
        else {
            Invoke-CPChange "Disabled the built-in Administrator account ('$($admin.Name)')" { Disable-LocalUser -SID $admin.SID }
        }
    }

    # ---- Groups required by the README -----------------------------------------------------
    foreach ($g in $comp.groups.PSObject.Properties) {
        if ($g.Name -like '_*') { continue }
        $groupName = $g.Name
        $wanted = @(@($g.Value) | Where-Object { $_ })
        if (-not (Get-LocalGroup -Name $groupName -ErrorAction SilentlyContinue)) {
            Invoke-CPChange "Created group '$groupName'" { New-LocalGroup -Name $groupName }
        }
        $current = @()
        if (Get-LocalGroup -Name $groupName -ErrorAction SilentlyContinue) {
            $current = @(Get-CPGroupMembers $groupName | ForEach-Object { $_.Name })
        }
        foreach ($name in $wanted) {
            if ($current -notcontains $name) {
                Invoke-CPChange "Added '$name' to group '$groupName'" { Invoke-CPNative 'net.exe' @('localgroup', $groupName, $name, '/add') | Out-Null }
            }
        }
        foreach ($name in $current) {
            if ($wanted -notcontains $name) {
                if ($cfg.removeExtraGroupMembers) {
                    Invoke-CPChange "Removed '$name' from group '$groupName'" { Invoke-CPNative 'net.exe' @('localgroup', $groupName, $name, '/delete') | Out-Null }
                }
                else {
                    Write-CPLog "Group '$groupName' contains '$name', who is not listed for it in competition.json." REPORT
                }
            }
        }
    }

    # ---- Report other privileged groups ------------------------------------------------------
    $rows = @()
    foreach ($groupName in @($cfg.reviewGroups)) {
        if (-not (Get-LocalGroup -Name $groupName -ErrorAction SilentlyContinue)) { continue }
        foreach ($m in @(Get-CPGroupMembers $groupName)) {
            $rows += [pscustomobject]@{ Group = $groupName; Member = $m.FullName; Type = $m.ObjectClass }
        }
    }
    Export-CPReport 'privileged-group-members' $rows
}
