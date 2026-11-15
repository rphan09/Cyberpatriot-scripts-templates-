# Applies advanced audit policy (subcategories) with auditpol.
# Values come from config\audit-policy.json.

function Invoke-CPAuditPolicy {
    $cfg = $script:CP.AuditPolicy

    foreach ($p in $cfg.subcategories.PSObject.Properties) {
        if ($p.Name -like '_*') { continue }
        $subcategory = $p.Name
        $setting = [string]$p.Value

        $map = @{
            'Success and Failure' = @('enable', 'enable')
            'Success'             = @('enable', 'disable')
            'Failure'             = @('disable', 'enable')
            'No Auditing'         = @('disable', 'disable')
        }
        if (-not $map.ContainsKey($setting)) {
            Write-CPLog "Audit setting '$setting' for '$subcategory' is not valid. Use 'Success and Failure', 'Success', 'Failure' or 'No Auditing'." ERROR
            continue
        }
        $success = $map[$setting][0]
        $failure = $map[$setting][1]

        Invoke-CPChange "Audit '$subcategory' set to $setting" {
            Invoke-CPNative 'auditpol.exe' @('/set', "/subcategory:$subcategory", "/success:$success", "/failure:$failure") | Out-Null
        }
    }
}
