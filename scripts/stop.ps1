$ErrorActionPreference = "SilentlyContinue"

$listeners = Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort 5117 |
    Where-Object { $_.State -eq "Listen" } |
    Select-Object -ExpandProperty OwningProcess -Unique

foreach ($processId in $listeners) {
    $process = Get-Process -Id $processId
    if ($process.ProcessName -in @("PcGuardian", "RoamSentinel") -or $process.Path -like "*\PcGuardian\*" -or $process.Path -like "*\RoamSentinel\*") {
        Stop-Process -Id $processId -Force
        Write-Host "Stopped RoamSentinel process $processId."
    }
}

if (-not $listeners) {
    Write-Host "RoamSentinel is not listening on 127.0.0.1:5117."
}
