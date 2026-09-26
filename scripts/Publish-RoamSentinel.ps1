[CmdletBinding()]
param(
    [string]$Runtime = "win-x64",
    [string]$Output = "",
    [ValidateSet("Workstation", "AgentOnly", "CodeGateVm")]
    [string]$Profile = "Workstation",
    [switch]$FrameworkDependent
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
    $PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrWhiteSpace($Output)) {
    $Output = Join-Path $PSScriptRoot "..\artifacts\publish\$Runtime"
}
$project = Resolve-Path (Join-Path $PSScriptRoot "..\RoamSentinel.csproj")
$outputPath = [System.IO.Path]::GetFullPath($Output)

$arguments = @(
    "publish", $project,
    "--configuration", "Release",
    "--runtime", $Runtime,
    "--output", $outputPath,
    "-p:PublishSingleFile=false",
    "-p:DebugType=None",
    "-p:DebugSymbols=false",
    "--self-contained", (!$FrameworkDependent).ToString().ToLowerInvariant()
)
& dotnet @arguments
if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE."
}

if ($Profile -ne "AgentOnly") {
    $consoleProject = Resolve-Path (
        Join-Path $PSScriptRoot "..\Console\RoamSentinel.Console.csproj")
    $consoleOutput = Join-Path $outputPath "Console"
    $consoleArguments = @(
        "publish", $consoleProject,
        "--configuration", "Release",
        "--runtime", $Runtime,
        "--output", $consoleOutput,
        "-p:DebugType=None",
        "-p:DebugSymbols=false",
        "--self-contained", (!$FrameworkDependent).ToString().ToLowerInvariant()
    )
    & dotnet @consoleArguments
    if ($LASTEXITCODE -ne 0) {
        throw "RS Console publish failed with exit code $LASTEXITCODE."
    }
}
else {
    $consoleOutput = Join-Path $outputPath "Console"
    if (Test-Path -LiteralPath $consoleOutput) {
        Remove-Item -LiteralPath $consoleOutput -Recurse -Force
    }
}

$manifest = [ordered]@{
    schemaVersion = "1.0"
    product = "RoamSentinel"
    profile = $Profile
    runtime = $Runtime
    frameworkDependent = [bool]$FrameworkDependent
    includesConsole = $Profile -ne "AgentOnly"
    includesCodeGateVmTools = $Profile -eq "CodeGateVm"
    createdAt = [DateTimeOffset]::UtcNow.ToString("O")
}
$manifest | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath (Join-Path $outputPath "install-profile.json") -Encoding UTF8

& (Join-Path $PSScriptRoot "Test-PublishOutput.ps1") `
    -PublishDirectory $outputPath `
    -Profile $Profile
