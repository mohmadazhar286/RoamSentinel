[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Path,

    [string]$RoamSentinelExe = "",

    [string]$Source = "staging-deployment",

    [string]$Revision = "staging",

    [switch]$FailOnWarn,

    [switch]$SelfScan,

    [switch]$Json
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($RoamSentinelExe)) {
    $candidates = @(
        "$env:ProgramFiles\RoamSentinel\RoamSentinel.exe",
        (Join-Path $PSScriptRoot "..\bin\Release\net10.0-windows\win-x64\RoamSentinel.exe"),
        (Join-Path $PSScriptRoot "..\bin\Debug\net10.0-windows\RoamSentinel.exe")
    )
    foreach ($cand in $candidates) {
        if (Test-Path -LiteralPath $cand -PathType Leaf) {
            $RoamSentinelExe = $cand
            break
        }
    }
}

$target = [System.IO.Path]::GetFullPath($Path)
if (-not (Test-Path -LiteralPath $target)) {
    throw "Staging gate path does not exist: $target"
}

if (-not (Test-Path -LiteralPath $RoamSentinelExe -PathType Leaf)) {
    throw "RoamSentinel executable was not found: $RoamSentinelExe"
}

$origProgramData = $env:ROAMSENTINEL_PROGRAMDATA
try {
    $stagingProgramData = Join-Path $env:TEMP "RoamSentinel-StagingGate"
    New-Item -ItemType Directory -Path $stagingProgramData -Force | Out-Null
    $env:ROAMSENTINEL_PROGRAMDATA = $stagingProgramData

    $output = & $RoamSentinelExe `
        --codegate-scan $target `
        --source $Source `
        --revision $Revision 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "CodeGate scan failed with exit code $exitCode. $($output -join [Environment]::NewLine)"
    }
}
finally {
    if ($null -ne $origProgramData) {
        $env:ROAMSENTINEL_PROGRAMDATA = $origProgramData
    } else {
        Remove-Item Env:\ROAMSENTINEL_PROGRAMDATA -ErrorAction SilentlyContinue
    }
}

$summary = ($output | Where-Object { $_ -match "^CodeGate verdict=" } | Select-Object -First 1)
if (-not $summary) {
    throw "CodeGate scan output did not include a verdict summary."
}

$verdict = [regex]::Match($summary, "verdict=([a-z_-]+)").Groups[1].Value
$riskText = [regex]::Match($summary, "risk=([0-9]+)").Groups[1].Value
$risk = if ($riskText) { [int]$riskText } else { 0 }

# If scanning own release package, CG-FILE-001 (standard compiled assemblies/executables) is expected.
# We block only if non-file critical or high severity findings (e.g. secret leaks, destructive scripts) are detected.
if ($SelfScan) {
    $criticalFindings = @($output | Where-Object { $_ -match "^(Critical|High)\s+(CG-(?!FILE)[A-Za-z0-9_-]+)" })
    if ($criticalFindings.Count -gt 0) {
        $blocked = $true
        $verdict = "block"
    } else {
        $blocked = $false
        $verdict = "allow"
        $risk = 0
    }
} else {
    $blocked = $verdict -eq "block" -or ($FailOnWarn -and $verdict -eq "warn")
}
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
