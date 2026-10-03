[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$PublishDirectory,
    [ValidateSet("Workstation", "AgentOnly", "CodeGateVm")]
    [string]$Profile = "Workstation"
)

$ErrorActionPreference = "Stop"
$root = [System.IO.Path]::GetFullPath($PublishDirectory)
$required = @(
    "RoamSentinel.exe",
    "RoamSentinel.dll",
    "appsettings.json",
    "public\index.html",
    "public\app.js",
    "public\styles.css",
    "install-profile.json",
    "scripts\Invoke-RoamSentinelCodeGateGitHook.ps1",
    "scripts\Install-CodeGateGitHook.ps1",
    "scripts\Approve-CodeGateGitHookPolicy.ps1",
    "scripts\Test-CodeGateGitHookPolicy.ps1",
    "scripts\Invoke-RoamSentinelEvidenceExport.ps1",
    "scripts\Invoke-OfflineVmReleaseRehearsal.ps1",
    "scripts\Test-OfflineVmReadiness.ps1",
    "scripts\Register-RoamSentinelMobileDevice.ps1",
    "scripts\Submit-RoamSentinelMobileHeartbeat.ps1",
    "scripts\Invoke-RoamSentinelStagingGate.ps1",
    "scripts\Invoke-RoamSentinelReleaseGate.ps1",
    "scripts\git-hooks\pre-receive",
    "scripts\git-hooks\post-receive"
)

if ($Profile -ne "AgentOnly") {
    $required += "Console\RoamSentinel.Console.exe"
}

$missing = $required | Where-Object {
    -not (Test-Path -LiteralPath (Join-Path $root $_) -PathType Leaf)
}
if ($missing) {
    throw "Publish output is incomplete: $($missing -join ', ')"
}

$manifestPath = Join-Path $root "install-profile.json"
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.product -ne "RoamSentinel") {
    throw "Publish profile manifest has invalid product: $($manifest.product)"
}
if ($manifest.profile -ne $Profile) {
    throw "Publish profile manifest mismatch. Expected $Profile, found $($manifest.profile)."
}
if ($Profile -eq "AgentOnly" -and
    (Test-Path -LiteralPath (Join-Path $root "Console\RoamSentinel.Console.exe"))) {
    throw "AgentOnly publish output must not include RS Console."
}
if ($Profile -eq "CodeGateVm" -and -not $manifest.includesCodeGateVmTools) {
    throw "CodeGateVm publish profile must include CodeGate VM tools."
}

$forbidden = Get-ChildItem -LiteralPath $root -Recurse -File |
    Where-Object { $_.FullName -match '[\\/](data|logs|config)[\\/]' }
if ($forbidden) {
    throw "Publish output contains mutable runtime data: $($forbidden.FullName -join ', ')"
}

Write-Host "RoamSentinel publish output validated: $root"
