# Shared helpers used by every step. This file is loaded first.

function Get-CPProp {
    # Returns a property of a JSON object, or $null when the property does not exist.
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}

function Read-CPJson {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Configuration file not found: $Path"
    }
    try {
        return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
    }
    catch {
        throw "Configuration file '$Path' is not valid JSON: $($_.Exception.Message)"
    }
}

function Initialize-CPContext {
    param(
        [string]$ConfigPath,
        [string]$OutputPath,
        [switch]$DryRun,
        [switch]$Force
    )

    $ctx = @{
        ConfigPath  = $ConfigPath
        OutputPath  = $OutputPath
        WorkDir     = Join-Path $OutputPath 'work'
        BackupDir   = Join-Path $OutputPath 'backup'
        ReportDir   = Join-Path $OutputPath 'reports'
        LogFile     = Join-Path $OutputPath 'hardening.log'
        DryRun      = [bool]$DryRun
        Force       = [bool]$Force
        Counts      = @{}
        RebootNeeded = $false
    }

    foreach ($dir in @($ctx.OutputPath, $ctx.WorkDir, $ctx.BackupDir, $ctx.ReportDir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $script:CP = $ctx

    try {
        $ctx.Competition      = Read-CPJson (Join-Path $ConfigPath 'competition.json')
        $ctx.Settings         = Read-CPJson (Join-Path $ConfigPath 'settings.json')
        $ctx.SecurityPolicy   = Read-CPJson (Join-Path $ConfigPath 'security-policy.json')
        $ctx.AuditPolicy      = Read-CPJson (Join-Path $ConfigPath 'audit-policy.json')
        $ctx.Registry         = Read-CPJson (Join-Path $ConfigPath 'registry.json')
        $ctx.Services         = Read-CPJson (Join-Path $ConfigPath 'services.json')
        $ctx.Firewall         = Read-CPJson (Join-Path $ConfigPath 'firewall.json')
        $ctx.Prohibited       = Read-CPJson (Join-Path $ConfigPath 'prohibited.json')
        $ctx.CriticalMap      = Read-CPJson (Join-Path $ConfigPath 'critical-services.json')
    }
    catch {
        Write-CPLog $_.Exception.Message ERROR
        return $null
    }

    $ctx.Critical = @(@($ctx.Competition.criticalServices) | Where-Object { $_ })
    foreach ($tag in $ctx.Critical) {
        if (-not (Get-CPProp $ctx.CriticalMap $tag)) {
            Write-CPLog "Critical service tag '$tag' is not defined in critical-services.json. Add it there or correct the spelling." ERROR
            return $null
        }
    }

    # Names of Windows services that belong to a critical tag. These are never disabled.
    $protected = @()
    foreach ($tag in $ctx.Critical) {
        $protected += @((Get-CPProp (Get-CPProp $ctx.CriticalMap $tag) 'services'))
    }
    $ctx.ProtectedServices = @($protected | Where-Object { $_ })

    $ctx.IsDomainController = $false
    $ctx.IsServer = $false
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $ctx.IsDomainController = ($cs.DomainRole -ge 4)
        $ctx.IsServer = ($os.ProductType -ne 1)
        $ctx.OsCaption = $os.Caption
    }
    catch { }

    Write-CPLog "Output folder: $OutputPath" INFO
    Write-CPLog "Operating system: $($ctx.OsCaption). Server: $($ctx.IsServer). Domain controller: $($ctx.IsDomainController)." INFO
    Write-CPLog "Critical services: $(if ($ctx.Critical.Count) { $ctx.Critical -join ', ' } else { 'none' })" INFO
    if ($ctx.DryRun) { Write-CPLog 'Dry run. No changes will be made.' WARN }
    return $ctx
}

function Write-CPLog {
    param(
        [Parameter(Mandatory = $true, Position = 0)][string]$Message,
        [Parameter(Position = 1)][ValidateSet('INFO', 'WARN', 'ERROR', 'CHANGE', 'DRYRUN', 'REPORT', 'STEP')][string]$Level = 'INFO'
    )
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    $color = switch ($Level) {
        'WARN'   { 'Yellow' }
        'ERROR'  { 'Red' }
        'CHANGE' { 'Green' }
        'DRYRUN' { 'Cyan' }
        'REPORT' { 'Magenta' }
        'STEP'   { 'White' }
        default  { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
    if ($script:CP) {
        if ($script:CP.LogFile) { Add-Content -LiteralPath $script:CP.LogFile -Value $line -ErrorAction SilentlyContinue }
        $script:CP.Counts[$Level] = [int]$script:CP.Counts[$Level] + 1
    }
}

function Invoke-CPChange {
    # Runs a change, logs the result, and respects -DryRun.
    # Sets $script:CP.LastOk to $true or $false.
    param(
        [Parameter(Mandatory = $true, Position = 0)][string]$CPChangeText,
        [Parameter(Mandatory = $true, Position = 1)][scriptblock]$CPChangeBlock
    )
    if ($script:CP.DryRun) {
        Write-CPLog "Would: $CPChangeText" DRYRUN
        $script:CP.LastOk = $true
        return
    }
    $ErrorActionPreference = 'Stop'
    try {
        & $CPChangeBlock | Out-Null
        Write-CPLog $CPChangeText CHANGE
        $script:CP.LastOk = $true
    }
    catch {
        Write-CPLog "$CPChangeText - FAILED: $($_.Exception.Message)" ERROR
        $script:CP.LastOk = $false
    }
}

function Invoke-CPNative {
    # Runs an external program and throws when it returns a non-zero exit code.
    param([string]$FilePath, [string[]]$ArgumentList)
    $output = & $FilePath @ArgumentList 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath exited with code $LASTEXITCODE. $($output -join ' ')"
    }
    return $output
}

function Test-CPCritical {
    param([string]$Tag)
    return ($script:CP.Critical -contains $Tag)
}

function Test-CPItemSkipped {
    # Returns $true when an item must be skipped because of the critical service list.
    # skipIfCritical: skip the item when any listed tag is critical.
    # onlyIfCritical: apply the item only when at least one listed tag is critical.
    param($Item, [string]$Label)
    $skipTags = @(@(Get-CPProp $Item 'skipIfCritical') | Where-Object { $_ })
    foreach ($tag in $skipTags) {
        if (Test-CPCritical $tag) {
            Write-CPLog "Skipped '$Label' because $tag is a critical service." INFO
            return $true
        }
    }
    $onlyTags = @(@(Get-CPProp $Item 'onlyIfCritical') | Where-Object { $_ })
    if ($onlyTags.Count -gt 0) {
        foreach ($tag in $onlyTags) {
            if (Test-CPCritical $tag) { return $false }
        }
        return $true
    }
    return $false
}

function Confirm-CPAction {
    param([string]$Prompt)
    if ($script:CP.Force -or $script:CP.DryRun) { return $true }
    $answer = Read-Host "$Prompt [y/N]"
    return ($answer -match '^(y|yes)$')
}

function Confirm-CPPreflight {
    Write-Host ''
    Write-Host 'Before this script runs, the following must be complete:' -ForegroundColor Yellow
    Write-Host '  1. Every forensic question has been answered. Some steps remove files, users and software.' -ForegroundColor Yellow
    Write-Host '  2. config\competition.json lists the authorized users, administrators and critical services from the README.' -ForegroundColor Yellow
    Write-Host '  3. A snapshot of the virtual machine has been taken, if the environment allows it.' -ForegroundColor Yellow
    Write-Host ''
    $c = $script:CP.Competition
    Write-Host ("Authorized administrators: {0}" -f ((@($c.authorizedAdministrators) | Where-Object { $_ }) -join ', '))
    Write-Host ("Authorized users:          {0}" -f ((@($c.authorizedUsers) | Where-Object { $_ }) -join ', '))
    Write-Host ("Critical services:         {0}" -f ($script:CP.Critical -join ', '))
    Write-Host ''
    if ($script:CP.Force -or $script:CP.DryRun) { return $true }
    $answer = Read-Host "Type YES to continue"
    return ($answer -ceq 'YES')
}

function Export-CPReport {
    param([string]$Name, $Data)
    $items = @($Data | Where-Object { $_ })
    if ($items.Count -eq 0) {
        Write-CPLog "$Name - no findings." INFO
        return
    }
    $path = Join-Path $script:CP.ReportDir ("$Name.csv")
    $items | Export-Csv -LiteralPath $path -NoTypeInformation -Force
    Write-CPLog "$Name - $($items.Count) finding(s) written to $path. Review them manually." REPORT
}

function Set-CPRegistryValue {
    # Type is one of: DWord, QWord, String, ExpandString, MultiString, Delete.
    param(
        [string]$Path,
        [string]$Name,
        [string]$Type,
        $Value,
        [string]$Label
    )
    if (-not $Label) { $Label = "$Path\$Name" }

    if ($Type -eq 'Delete') {
        $existing = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $existing) {
            Write-CPLog "$Label - already absent." INFO
            return
        }
        Invoke-CPChange "$Label - deleted $Path\$Name" {
            Remove-ItemProperty -LiteralPath $Path -Name $Name -Force
        }
        return
    }

    if ($Type -eq 'MultiString') { $Value = [string[]]@($Value | ForEach-Object { "$_" }) }

    $current = $null
    $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $item) { $current = $item.$Name }

    $currentText = if ($null -eq $current) { '<not set>' } else { (@($current) -join ',') }
    $newText = (@($Value) -join ',')
    if ($null -ne $current -and $currentText -eq $newText) {
        Write-CPLog "$Label - already $newText." INFO
        return
    }

    Invoke-CPChange "$Label - $Path\$Name changed from $currentText to $newText" {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
    }
}

function Get-CPBuiltinAccount {
    # Rid 500 = built-in Administrator, 501 = Guest, 503 = DefaultAccount, 504 = WDAGUtilityAccount.
    param([int]$Rid)
    return (Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -match "-$Rid$" } | Select-Object -First 1)
}

function Get-CPCurrentUserSid {
    return ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
}

function Expand-CPPath {
    param([string]$Path)
    return [Environment]::ExpandEnvironmentVariables($Path)
}

function Write-CPSummary {
    $c = $script:CP.Counts
    Write-Host ''
    Write-CPLog ('Finished. Changes: {0}. Errors: {1}. Warnings: {2}. Reports: {3}.' -f [int]$c['CHANGE'], [int]$c['ERROR'], [int]$c['WARN'], [int]$c['REPORT']) STEP
    Write-CPLog "Log file: $($script:CP.LogFile)" STEP
    Write-CPLog "Reports for manual review: $($script:CP.ReportDir)" STEP
    Write-CPLog "Backups: $($script:CP.BackupDir)" STEP
    if ($script:CP.RebootNeeded) {
        Write-CPLog 'Some changes take effect only after a restart. Restart the machine when convenient and check the score afterwards.' WARN
    }
}
