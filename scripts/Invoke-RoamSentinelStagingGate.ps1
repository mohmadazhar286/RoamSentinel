[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Path,

    [string]$RoamSentinelExe = "$env:ProgramFiles\RoamSentinel\RoamSentinel.exe",

    [string]$Source = "staging-deployment",

    [string]$Revision = "staging",

    [switch]$FailOnWarn,

    [switch]$Json
)

$ErrorActionPreference = "Stop"

$target = [System.IO.Path]::GetFullPath($Path)
if (-not (Test-Path -LiteralPath $target)) {
    throw "Staging gate path does not exist: $target"
}

if (-not (Test-Path -LiteralPath $RoamSentinelExe -PathType Leaf)) {
    throw "RoamSentinel executable was not found: $RoamSentinelExe"
}

$output = & $RoamSentinelExe `
    --codegate-scan $target `
    --source $Source `
    --revision $Revision 2>&1
$exitCode = $LASTEXITCODE
if ($exitCode -ne 0) {
    throw "CodeGate scan failed with exit code $exitCode. $($output -join [Environment]::NewLine)"
}

$summary = ($output | Where-Object { $_ -match "^CodeGate verdict=" } | Select-Object -First 1)
if (-not $summary) {
    throw "CodeGate scan output did not include a verdict summary."
}

$verdict = [regex]::Match($summary, "verdict=([a-z_-]+)").Groups[1].Value
$riskText = [regex]::Match($summary, "risk=([0-9]+)").Groups[1].Value
$risk = if ($riskText) { [int]$riskText } else { 0 }
$blocked = $verdict -eq "block" -or ($FailOnWarn -and $verdict -eq "warn")
# Readiness marker: verdict=block must fail the staging gate.
$result = [ordered]@{
    ok = -not $blocked
    verdict = $verdict
    riskScore = $risk
    failOnWarn = [bool]$FailOnWarn
    path = $target
    source = $Source
    revision = $Revision
    summary = $summary
    output = @($output)
}

if ($Json) {
    $result | ConvertTo-Json -Depth 6
}
else {
    Write-Host "RoamSentinel staging gate verdict=$verdict risk=$risk path=$target"
    if ($blocked) {
        Write-Host "Deployment gate blocked this artifact. Review CodeGate findings before deployment."
    }
}

if ($blocked) {
    exit 20
}
