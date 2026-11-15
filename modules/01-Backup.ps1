# Saves the current configuration so that changes can be reviewed or reversed.

function Invoke-CPBackup {
    $dir = $script:CP.BackupDir
    if ($script:CP.DryRun) {
        Write-CPLog "Would save backups to $dir" DRYRUN
        return
    }

    Invoke-CPChange 'Backed up local security policy (secpol.inf)' {
        Invoke-CPNative 'secedit.exe' @('/export', '/cfg', (Join-Path $dir 'secpol.inf'), '/quiet') | Out-Null
    }
    Invoke-CPChange 'Backed up audit policy (auditpol.csv)' {
        Invoke-CPNative 'auditpol.exe' @('/backup', "/file:$(Join-Path $dir 'auditpol.csv')") | Out-Null
    }
    Invoke-CPChange 'Backed up firewall policy (firewall.wfw)' {
        Invoke-CPNative 'netsh.exe' @('advfirewall', 'export', (Join-Path $dir 'firewall.wfw')) | Out-Null
    }
    Invoke-CPChange 'Backed up service list (services.csv)' {
        Get-CimInstance Win32_Service |
            Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
            Export-Csv -LiteralPath (Join-Path $dir 'services.csv') -NoTypeInformation
    }
    Invoke-CPChange 'Backed up local users and group membership (users.csv, groups.csv)' {
        Get-LocalUser | Select-Object Name, Enabled, SID, PasswordRequired, PasswordExpires, LastLogon, Description |
            Export-Csv -LiteralPath (Join-Path $dir 'users.csv') -NoTypeInformation
        $rows = foreach ($g in Get-LocalGroup) {
            $members = @()
            try { $members = @(Get-LocalGroupMember -Group $g -ErrorAction Stop | ForEach-Object { $_.Name }) } catch { $members = @('<could not read>') }
            [pscustomobject]@{ Group = $g.Name; Members = ($members -join '; ') }
        }
        $rows | Export-Csv -LiteralPath (Join-Path $dir 'groups.csv') -NoTypeInformation
    }

    $keys = @(
        'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies',
        'HKLM\SOFTWARE\Policies',
        'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
        'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters',
        'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server',
        'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    )
    $i = 0
    foreach ($key in $keys) {
        $i++
        $file = Join-Path $dir ("registry-$i.reg")
        Invoke-CPChange "Backed up registry key $key" {
            Invoke-CPNative 'reg.exe' @('export', $key, $file, '/y') | Out-Null
        }
    }

    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (Test-Path -LiteralPath $hosts) {
        Copy-Item -LiteralPath $hosts -Destination (Join-Path $dir 'hosts') -Force -ErrorAction SilentlyContinue
    }
}
