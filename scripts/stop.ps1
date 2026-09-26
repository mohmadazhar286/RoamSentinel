$ErrorActionPreference = "SilentlyContinue"

$listeners = Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort 5117 |
    Where-Object { $_.State -eq "Listen" } |
    Select-Object -ExpandProperty OwningProcess -Unique

foreach ($processId in $listeners) {
    $process = Get-Process -Id $processId
    if ($process.ProcessName -eq "RoamSentinel" -or $process.Path -like "*\RoamSentinel\*") {
        try {
            Stop-Process -Id $processId -Force -ErrorAction Stop
            Write-Host "Stopped RoamSentinel process $processId."
        } catch {
            Write-Warning "Could not stop RoamSentinel process $processId. Run this script from an elevated PowerShell session or stop the RoamSentinel service."
        }
    }
}

if (-not $listeners) {
    Write-Host "RoamSentinel is not listening on 127.0.0.1:5117."
}
