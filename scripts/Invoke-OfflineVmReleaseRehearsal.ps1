[CmdletBinding()]
param(
    [string]$Runtime = "win-x64",
    [string]$Output = (Join-Path $PSScriptRoot "..\artifacts\offline-vm-release"),
    [switch]$FrameworkDependent,
    [switch]$SkipPublish,
    [switch]$SkipTests,
    [string]$TestResultsDirectory = (Join-Path $PSScriptRoot "..\artifacts\test-results-offline-vm-release")
)

$ErrorActionPreference = "Stop"
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$outputPath = [System.IO.Path]::GetFullPath($Output)
$resultPath = [System.IO.Path]::GetFullPath($TestResultsDirectory)

function Invoke-Step([string]$Name, [scriptblock]$Action) {
    Write-Host "==> $Name"
    & $Action
    Write-Host "OK: $Name"
}

Invoke-Step "PowerShell parser checks" {
    $scripts = @(
        "Publish-RoamSentinel.ps1",
        "Install-RoamSentinelService.ps1",
        "Invoke-RoamSentinelCodeGateGitHook.ps1",
        "Install-CodeGateGitHook.ps1",
        "Approve-CodeGateGitHookPolicy.ps1",
        "Test-CodeGateGitHookPolicy.ps1",
        "Invoke-RoamSentinelEvidenceExport.ps1",
        "Test-OfflineVmReadiness.ps1",
        "Test-PublishOutput.ps1"
    )
    foreach ($script in $scripts) {
        $path = Join-Path $PSScriptRoot $script
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile(
            $path,
            [ref]$tokens,
            [ref]$errors) | Out-Null
        if ($errors) {
            throw (($errors | ForEach-Object {
                ('{0}:{1}' -f $script, $_.Message)
            }) -join "`n")
        }
    }
}

Invoke-Step "JavaScript syntax" {
    & node --check (Join-Path $repoRoot "public\app.js")
    if ($LASTEXITCODE -ne 0) {
        throw "node --check failed."
    }
}

Invoke-Step "Release build" {
    & dotnet build (Join-Path $repoRoot "RoamSentinel.slnx") `
        -c Release `
        --no-restore
    if ($LASTEXITCODE -ne 0) {
        throw "Release build failed."
    }
}

if (-not $SkipTests) {
    Invoke-Step "Automated tests" {
        New-Item -ItemType Directory -Path $resultPath -Force | Out-Null
        & dotnet vstest `
            (Join-Path $repoRoot "tests\RoamSentinel.Tests\bin\Release\net10.0-windows\RoamSentinel.Tests.dll") `
            "--ResultsDirectory:$resultPath" `
            "--Logger:trx"
        if ($LASTEXITCODE -ne 0) {
            throw "Automated tests failed."
        }
    }
}

if (-not $SkipPublish) {
    Invoke-Step "CodeGate VM publish" {
        $publishArgs = @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            (Join-Path $PSScriptRoot "Publish-RoamSentinel.ps1"),
            "-Profile",
            "CodeGateVm",
            "-Runtime",
            $Runtime,
            "-Output",
            $outputPath
        )
        if ($FrameworkDependent) {
            $publishArgs += "-FrameworkDependent"
        }

        & powershell @publishArgs
        if ($LASTEXITCODE -ne 0) {
            throw "CodeGate VM publish failed."
        }
    }
}

Invoke-Step "Publish profile validation" {
    & powershell `
        -NoProfile `
        -ExecutionPolicy Bypass `
        -File (Join-Path $PSScriptRoot "Test-PublishOutput.ps1") `
        -PublishDirectory $outputPath `
        -Profile CodeGateVm
    if ($LASTEXITCODE -ne 0) {
        throw "Publish profile validation failed."
    }
}

Invoke-Step "Offline VM readiness" {
    & powershell `
        -NoProfile `
        -ExecutionPolicy Bypass `
        -File (Join-Path $PSScriptRoot "Test-OfflineVmReadiness.ps1") `
        -PublishDirectory $outputPath `
        -ExpectedProfile CodeGateVm
    if ($LASTEXITCODE -ne 0) {
        throw "Offline VM readiness validation failed."
    }
}

$manifest = Get-Content -LiteralPath (
    Join-Path $outputPath "install-profile.json") -Raw | ConvertFrom-Json
$summary = [ordered]@{
    product = "RoamSentinel"
    rehearsal = "offline-vm-release"
    ok = $true
    profile = $manifest.profile
    runtime = $manifest.runtime
    frameworkDependent = [bool]$manifest.frameworkDependent
    publishDirectory = $outputPath
    completedAt = [DateTimeOffset]::UtcNow.ToString("O")
}
$summaryPath = Join-Path $outputPath "offline-vm-release-rehearsal.json"
$summary | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath $summaryPath -Encoding UTF8

Write-Host "RoamSentinel offline VM release rehearsal passed: $summaryPath"
