# Removes printers. This feature was listed in the original project but was never implemented.

function Invoke-CPPrinters {
    if (Test-CPCritical 'Printing') {
        Write-CPLog 'Printing is a critical service. Printers were not removed.' INFO
        return
    }
    if (-not (Get-Command Get-Printer -ErrorAction SilentlyContinue)) {
        Write-CPLog 'The printer cmdlets are not available.' WARN
        return
    }
    $spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    if (-not $spooler -or $spooler.Status -ne 'Running') {
        Write-CPLog 'The Print Spooler is not running, so printers cannot be listed. Printers are skipped.' INFO
        return
    }
    $keep = @(@($script:CP.Settings.printers.keep) | Where-Object { $_ })
    foreach ($printer in @(Get-Printer -ErrorAction SilentlyContinue)) {
        if ($keep -contains $printer.Name) { continue }
        $printerName = $printer.Name
        Invoke-CPChange "Removed printer '$printerName'" { Remove-Printer -Name $printerName }
    }
}
