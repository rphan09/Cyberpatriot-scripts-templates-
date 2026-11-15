#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Configuration-driven Windows hardening script for CyberPatriot practice and competition images.

.DESCRIPTION
    Every setting is read from the JSON files in the config folder. Edit those files to change
    values. The code itself does not need to be edited.

    Before running:
      1. Answer every forensic question.
      2. Fill in config\competition.json from the competition README.

.PARAMETER ConfigPath
    Folder that contains the JSON configuration files.

.PARAMETER Only
    Run only the named steps, for example: -Only Firewall,Services

.PARAMETER Skip
    Skip the named steps, for example: -Skip Files,Software

.PARAMETER DryRun
    Log every change that would be made without making it.

.PARAMETER Force
    Do not ask for confirmation. Destructive actions (user removal, share removal) run without prompts.

.PARAMETER OutputPath
    Folder for the log, backups and reports.

.EXAMPLE
    .\Run-Hardening.ps1 -DryRun

.EXAMPLE
    .\Run-Hardening.ps1 -Only SecurityPolicy,AuditPolicy
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config'),
    [string[]]$Only,
    [string[]]$Skip,
    [switch]$DryRun,
    [switch]$Force,
    [string]$OutputPath = (Join-Path $env:SystemDrive ('CP-Hardening\' + (Get-Date -Format 'yyyyMMdd-HHmmss')))
)

$ErrorActionPreference = 'Continue'

# Load every module file into this script's scope.
foreach ($moduleFile in (Get-ChildItem -Path (Join-Path $PSScriptRoot 'modules') -Filter '*.ps1' | Sort-Object Name)) {
    . $moduleFile.FullName
}

$script:CP = Initialize-CPContext -ConfigPath $ConfigPath -OutputPath $OutputPath -DryRun:$DryRun -Force:$Force
if (-not $script:CP) { exit 1 }

# Ordered list of steps. The key is the step name used in settings.json, -Only and -Skip.
$steps = [ordered]@{
    Backup         = 'Invoke-CPBackup'
    SecurityPolicy = 'Invoke-CPSecurityPolicy'
    AuditPolicy    = 'Invoke-CPAuditPolicy'
    Users          = 'Invoke-CPUsers'
    Registry       = 'Invoke-CPRegistry'
    Firewall       = 'Invoke-CPFirewall'
    Printers       = 'Invoke-CPPrinters'   # Must run before Services, which may disable the Print Spooler.
    Shares         = 'Invoke-CPShares'
    Services       = 'Invoke-CPServices'
    Features       = 'Invoke-CPFeatures'
    Defender       = 'Invoke-CPDefender'
    WindowsUpdate  = 'Invoke-CPWindowsUpdate'
    Tasks          = 'Invoke-CPTasks'
    SSH            = 'Invoke-CPSsh'
    Browsers       = 'Invoke-CPBrowsers'
    ServerRoles    = 'Invoke-CPServerRoles'
    Hosts          = 'Invoke-CPHosts'
    Persistence    = 'Invoke-CPPersistenceReport'
    Software       = 'Invoke-CPSoftwareReport'
    Files          = 'Invoke-CPFilesReport'
}

foreach ($name in @($Only) + @($Skip)) {
    if ($name -and -not $steps.Contains($name)) {
        Write-CPLog "Unknown step name '$name'. Valid names: $($steps.Keys -join ', ')" ERROR
        exit 1
    }
}

if (-not (Confirm-CPPreflight)) {
    Write-CPLog 'Run cancelled by the user.' WARN
    exit 1
}

if (-not $DryRun) {
    try { Start-Transcript -Path (Join-Path $script:CP.OutputPath 'transcript.txt') -Force | Out-Null } catch { }
}

foreach ($stepName in $steps.Keys) {
    $enabled = [bool](Get-CPProp $script:CP.Settings.steps $stepName)
    if ($Only) { $enabled = ($Only -contains $stepName) }
    if ($Skip -contains $stepName) { $enabled = $false }

    if (-not $enabled) {
        Write-CPLog "Step '$stepName' is disabled." INFO
        continue
    }

    Write-CPLog "===== $stepName =====" STEP
    try {
        & $steps[$stepName]
    }
    catch {
        Write-CPLog "Step '$stepName' stopped with an error: $($_.Exception.Message)" ERROR
    }
}

Write-CPSummary

if (-not $DryRun) {
    try { Stop-Transcript | Out-Null } catch { }
}
