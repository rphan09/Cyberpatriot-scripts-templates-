# Applies the registry settings in config\registry.json.
# Each category can be turned off with "enabled": false.

function Invoke-CPRegistry {
    $cfg = $script:CP.Registry
    foreach ($cat in $cfg.categories.PSObject.Properties) {
        if ($cat.Name -like '_*') { continue }
        $category = $cat.Value
        if (-not $category.enabled) {
            Write-CPLog "Registry category '$($cat.Name)' is disabled." INFO
            continue
        }
        Write-CPLog "Registry category: $($cat.Name)" INFO
        foreach ($entry in @($category.entries)) {
            $label = if ($entry.description) { $entry.description } else { "$($entry.path)\$($entry.name)" }
            if (Test-CPItemSkipped $entry $label) { continue }
            Set-CPRegistryValue -Path $entry.path -Name $entry.name -Type $entry.type -Value $entry.value -Label $label
        }
        if ($category.PSObject.Properties['requiresRestart'] -and $category.requiresRestart) {
            $script:CP.RebootNeeded = $true
        }
    }
}
