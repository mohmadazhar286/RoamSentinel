[CmdletBinding()]
param(
    [string]$RoamSentinelExe = "$env:ProgramFiles\RoamSentinel\RoamSentinel.exe",
    [string]$OutputDirectory = "$env:ProgramData\RoamSentinel\evidence",
    [int]$RetentionDays = 30,
    [string[]]$Repository = @(),
    [ValidateSet("pre-receive", "post-receive")]
    [string]$ExpectedMode = "pre-receive",
    [switch]$RequireApproval
)

$ErrorActionPreference = "Stop"

if ($RetentionDays -lt 1 -or $RetentionDays -gt 3650) {
    throw "RetentionDays must be between 1 and 3650."
}

if (-not (Test-Path -LiteralPath $RoamSentinelExe -PathType Leaf)) {
    throw "RoamSentinel executable was not found: $RoamSentinelExe"
}

function Get-FileSha256([string]$Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            return ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '')
        }
        finally {
            $stream.Dispose()
        }
    }
    finally {
        $sha.Dispose()
    }
}

$root = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $root -Force | Out-Null

$createdAt = [DateTimeOffset]::UtcNow
$exportId = $createdAt.ToString("yyyyMMdd-HHmmss")
$runDirectory = Join-Path $root "RoamSentinel-evidence-$exportId"
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null

try {
    $backupDirectory = Join-Path $runDirectory "backup"
    New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
    $backupOutput = & $RoamSentinelExe --export-backup $backupDirectory
    if ($LASTEXITCODE -ne 0) {
        throw "RoamSentinel backup export failed with exit code $LASTEXITCODE."
    }

    $schedulerStatusPath = Join-Path $runDirectory "scheduler-status.json"
    $schedulerOutput = & $RoamSentinelExe --scheduler-status --json --output $schedulerStatusPath
    if ($LASTEXITCODE -ne 0) {
        throw "RoamSentinel scheduler status export failed with exit code $LASTEXITCODE."
    }
    if (-not (Test-Path -LiteralPath $schedulerStatusPath -PathType Leaf)) {
        throw "RoamSentinel scheduler status export did not create: $schedulerStatusPath"
    }

    $policyReviewPath = ""
    if ($Repository.Count -gt 0) {
        $reviewScript = Join-Path $PSScriptRoot "Test-CodeGateGitHookPolicy.ps1"
        if (-not (Test-Path -LiteralPath $reviewScript -PathType Leaf)) {
            throw "CodeGate hook policy review script was not found: $reviewScript"
        }

        $policyReviewPath = Join-Path $runDirectory "codegate-hook-policy-review.json"
        $reviewArgs = @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            $reviewScript,
            "-Repository"
        ) + $Repository + @(
            "-ExpectedMode",
            $ExpectedMode,
            "-Json"
        )
        if ($RequireApproval) {
            $reviewArgs += "-RequireApproval"
        }

        $reviewOutput = & powershell @reviewArgs
        $reviewExit = $LASTEXITCODE
        $reviewOutput | Set-Content -LiteralPath $policyReviewPath -Encoding UTF8
        if ($reviewExit -ne 0) {
            throw "CodeGate hook policy review failed. See $policyReviewPath"
        }
    }

    $files = Get-ChildItem -LiteralPath $runDirectory -Recurse -File |
        Sort-Object FullName |
        ForEach-Object {
            [pscustomobject]@{
                path = $_.FullName.Substring($runDirectory.Length + 1)
                length = $_.Length
                sha256 = Get-FileSha256 -Path $_.FullName
            }
        }
    $manifest = [ordered]@{
        schemaVersion = "1.0"
        product = "RoamSentinel"
        exportId = $exportId
        createdAt = $createdAt.ToString("O")
        machine = $env:COMPUTERNAME
        retentionDays = $RetentionDays
        backupCommand = @($backupOutput)
        schedulerStatusCommand = @($schedulerOutput)
        schedulerStatus = "scheduler-status.json"
        repositories = @($Repository)
        requireApproval = [bool]$RequireApproval
        files = @($files)
    }
    $manifestPath = Join-Path $runDirectory "evidence-manifest.json"
    $manifest | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath $manifestPath -Encoding UTF8

    $threshold = (Get-Date).ToUniversalTime().AddDays(-$RetentionDays)
    Get-ChildItem -LiteralPath $root -Directory -Filter "RoamSentinel-evidence-*" |
        Where-Object { $_.LastWriteTimeUtc -lt $threshold } |
        ForEach-Object {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force
        }

    Write-Host "RoamSentinel evidence export created: $runDirectory"
}
catch {
    if (Test-Path -LiteralPath $runDirectory -PathType Container) {
        $failure = [ordered]@{
            schemaVersion = "1.0"
            product = "RoamSentinel"
            exportId = $exportId
            createdAt = $createdAt.ToString("O")
            ok = $false
            error = $_.Exception.Message
        }
        $failure | ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath (
                Join-Path $runDirectory "evidence-export-failed.json") -Encoding UTF8
    }
    throw
}
