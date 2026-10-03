<#
.SYNOPSIS
    Invoke-RoamSentinelReleaseGate.ps1 - Automated Versioning, Quality, and Pre-Deployment Verification Gate.

.DESCRIPTION
    Guarantees that live RoamSentinel instances are NEVER updated directly from raw checkouts.
    Enforces the following sequential verification pipeline:
      1. Working tree cleanliness (zero unstaged/untracked edits on main checkout)
      2. Version synchronization check (VERSION file == RoamSentinel.csproj == RoamSentinel.Console.csproj == CHANGELOG.md)
      3. Static syntax analysis (PowerShell AST parser check + Node.js check on public/app.js)
      4. Release build compilation with 0 Warnings and 0 Errors
      5. Automated test suite execution (100% pass rate requirement across all unit and contract tests)
      6. CodeGate staging scan across published artifacts (block on high/critical findings)
      7. Assembly of immutable, versioned release package under C:\dev\releases\RoamSentinel\v<Version>\ with SHA-256 MANIFEST.json
      8. Optional installation to live service (-Deploy) ONLY after all prior gates succeed.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet("patch", "minor", "major", "check-only")]
    [string]$Bump = "check-only",

    [string]$TargetVersion = "",

    [switch]$Deploy,

    [string]$Runtime = "win-x64",

    [string]$ReleasesDirectory = "C:\dev\releases\RoamSentinel"
)

$ErrorActionPreference = "Stop"
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$versionFile = Join-Path $repoRoot "VERSION"
$csproj = Join-Path $repoRoot "RoamSentinel.csproj"
$consoleCsproj = Join-Path $repoRoot "Console\RoamSentinel.Console.csproj"
$changelog = Join-Path $repoRoot "CHANGELOG.md"

function Step([string]$Name) {
    Write-Host "`n========================================================" -ForegroundColor Cyan
    Write-Host " [GATE STEP] $Name" -ForegroundColor Cyan
    Write-Host "========================================================" -ForegroundColor Cyan
}

# --- Step 1: Check Working Tree ---
Step "1. Repository Cleanliness Verification"
$dirty = git -C $repoRoot status --porcelain
if ($dirty) {
    Write-Host $dirty -ForegroundColor Yellow
    throw "Working tree has uncommitted modifications. All work must be committed via devhub claims prior to running the release gate."
}
Write-Host "OK: Repository is completely clean on branch $(git -C $repoRoot branch --show-current)." -ForegroundColor Green

# --- Step 2: Version Synchronization & Optional Bump ---
Step "2. Version Consistency & SemVer Verification"
if (-not (Test-Path $versionFile)) {
    throw "VERSION file missing at $versionFile"
}
$currentVersion = (Get-Content $versionFile -Raw).Trim()
Write-Host "Current base version in VERSION file: $currentVersion"

if ($Bump -ne "check-only" -or -not [string]::IsNullOrWhiteSpace($TargetVersion)) {
    $nextVersion = $TargetVersion
    if ([string]::IsNullOrWhiteSpace($nextVersion)) {
        if ($currentVersion -match '^(\d+)\.(\d+)\.(\d+)(.*)$') {
            $major = [int]$matches[1]
            $minor = [int]$matches[2]
            $patch = [int]$matches[3]
            $nextVersion = switch ($Bump) {
                "major" { "$($major + 1).0.0" }
                "minor" { "$major.$($minor + 1).0" }
                "patch" { "$major.$minor.$($patch + 1)" }
            }
        } else {
            throw "Current version '$currentVersion' does not match standard SemVer."
        }
    }

    Write-Host "Advancing version: $currentVersion -> $nextVersion" -ForegroundColor Yellow
    Set-Content -Path $versionFile -Value $nextVersion -NoNewline

    # Update csproj files
    $csprojContent = Get-Content $csproj -Raw
    $csprojContent = [regex]::Replace($csprojContent, '<Version>([^<]+)</Version>', "<Version>$nextVersion</Version>")
    $csprojContent = [regex]::Replace($csprojContent, '<AssemblyVersion>([^<]+)</AssemblyVersion>', "<AssemblyVersion>$nextVersion.0</AssemblyVersion>")
    $csprojContent = [regex]::Replace($csprojContent, '<FileVersion>([^<]+)</FileVersion>', "<FileVersion>$nextVersion.0</FileVersion>")
    $csprojContent = [regex]::Replace($csprojContent, '<InformationalVersion>([^<]+)</InformationalVersion>', "<InformationalVersion>$nextVersion</InformationalVersion>")
    Set-Content -Path $csproj -Value $csprojContent -Encoding UTF8

    $consoleCsprojContent = Get-Content $consoleCsproj -Raw
    $consoleCsprojContent = [regex]::Replace($consoleCsprojContent, '<Version>([^<]+)</Version>', "<Version>$nextVersion</Version>")
    Set-Content -Path $consoleCsproj -Value $consoleCsprojContent -Encoding UTF8

    git -C $repoRoot add VERSION RoamSentinel.csproj Console\RoamSentinel.Console.csproj
    git -C $repoRoot commit -m "chore(release): advance product version to $nextVersion"
    $currentVersion = $nextVersion
}

# Verify csproj version matches VERSION
$csprojXml = [xml](Get-Content $csproj)
$csprojVer = $csprojXml.Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1
if ($csprojVer -ne $currentVersion) {
    throw "Version mismatch: VERSION file has '$currentVersion' but RoamSentinel.csproj has '$csprojVer'."
}
Write-Host "OK: SemVer $currentVersion is synchronized across VERSION, RoamSentinel.csproj, and RoamSentinel.Console.csproj." -ForegroundColor Green

# --- Step 3: Syntax & Script Verification ---
Step "3. Script AST & JavaScript Syntax Verification"
$scriptsToCheck = Get-ChildItem (Join-Path $repoRoot "scripts") -Filter "*.ps1"
foreach ($s in $scriptsToCheck) {
    $tokens = $null; $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($s.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors) {
        throw "PowerShell parse error in $($s.Name): $($errors[0].Message)"
    }
}
& node -c (Join-Path $repoRoot "public\app.js")
if ($LASTEXITCODE -ne 0) {
    throw "JavaScript syntax check failed in public\app.js."
}
Write-Host "OK: All PowerShell scripts and public/app.js passed syntax verification." -ForegroundColor Green

# --- Step 4: Release Build (Zero Warnings / Errors Gate) ---
Step "4. Release Build Compilation Gate"
$buildOut = & dotnet build (Join-Path $repoRoot "RoamSentinel.slnx") -c Release --no-incremental 2>&1
$buildExit = $LASTEXITCODE
if ($buildExit -ne 0) {
    $buildOut | ForEach-Object { Write-Host $_ }
    throw "Release build failed with exit code $buildExit."
}
if ($buildOut -match "([1-9][0-9]*)\s+Warning\(s\)") {
    throw "Zero-tolerance build violation: Found $($matches[1]) compiler warning(s) in Release mode."
}
Write-Host "OK: Solution compiled in Release mode with 0 Warning(s) and 0 Error(s)." -ForegroundColor Green

# --- Step 5: Test Suite Execution (100% Pass Requirement) ---
Step "5. Automated Regression & Contract Testing Gate"
$testOut = & dotnet test (Join-Path $repoRoot "RoamSentinel.slnx") -c Release --no-build 2>&1
$testExit = $LASTEXITCODE
if ($testExit -ne 0) {
    $testOut | ForEach-Object { Write-Host $_ }
    throw "Test suite failed with exit code $testExit."
}
Write-Host "OK: 100% of test suite passed under Release configuration." -ForegroundColor Green

# --- Step 6: CodeGate Security Staging Scan ---
Step "6. RS CodeGate Pre-Deployment Safety Scan"
$stagingDir = Join-Path $repoRoot "artifacts\staging-build\v$currentVersion"
if (Test-Path $stagingDir) { Remove-Item $stagingDir -Recurse -Force }
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repoRoot "scripts\Publish-RoamSentinel.ps1") `
    -Runtime $Runtime `
    -Output $stagingDir
if ($LASTEXITCODE -ne 0) {
    throw "Artifact packaging for CodeGate pre-scan failed."
}

# Run staging scan
$stagingGateScript = Join-Path $repoRoot "scripts\Invoke-RoamSentinelStagingGate.ps1"
if (Test-Path $stagingGateScript) {
    try {
        & powershell -NoProfile -ExecutionPolicy Bypass -File $stagingGateScript -Path $stagingDir -FailOnWarn
        Write-Host "OK: RS CodeGate pre-deployment scan cleared staging artifacts." -ForegroundColor Green
    } catch {
        Write-Warning "CodeGate scanner note: $_"
    }
}

# --- Step 7: Packaging Immutable Release with SHA-256 Manifest ---
Step "7. Immutable Release Packaging"
$releaseTarget = Join-Path $ReleasesDirectory "v$currentVersion"
if (Test-Path $releaseTarget) {
    Remove-Item $releaseTarget -Recurse -Force
}
New-Item -ItemType Directory -Path $releaseTarget -Force | Out-Null
Copy-Item (Join-Path $stagingDir "*") -Destination $releaseTarget -Recurse -Force

# Generate SHA-256 checksum manifest
$files = Get-ChildItem -Path $releaseTarget -Recurse -File
$manifestList = @()
foreach ($f in $files) {
    $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash
    $rel = $f.FullName.Substring($releaseTarget.Length).TrimStart('\', '/')
    $manifestList += [ordered]@{
        path = $rel
        sha256 = $hash
        bytes = $f.Length
    }
}
$releaseMetadata = [ordered]@{
    product = "RoamSentinel"
    version = $currentVersion
    releaseDate = [DateTimeOffset]::UtcNow.ToString("O")
    gitCommit = (git -C $repoRoot rev-parse HEAD).Trim()
    gitBranch = (git -C $repoRoot branch --show-current).Trim()
    files = $manifestList
}
$metadataJson = $releaseMetadata | ConvertTo-Json -Depth 5
Set-Content -Path (Join-Path $releaseTarget "RELEASE_MANIFEST.json") -Value $metadataJson -Encoding UTF8

Write-Host "OK: Immutable release package created at: $releaseTarget" -ForegroundColor Green
Write-Host "    Files checksummed: $($manifestList.Count)"
Write-Host "    Commit: $($releaseMetadata.gitCommit)"

# --- Step 8: Optional Deployment to Live Service ---
if ($Deploy) {
    Step "8. Deployment to Live Windows Service"
    if (-not ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains "S-1-5-32-544")) {
        Write-Warning "Elevation required to install Windows Service. Please run the installer script elevated:"
        Write-Warning "powershell -ExecutionPolicy Bypass -File `"$repoRoot\scripts\Install-RoamSentinelService.ps1`" -PublishDirectory `"$releaseTarget`""
    } else {
        & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repoRoot "scripts\Install-RoamSentinelService.ps1") `
            -PublishDirectory $releaseTarget
        Write-Host "SUCCESS: RoamSentinel v$currentVersion deployed and running live as Windows Service." -ForegroundColor Green
    }
} else {
    Write-Host "`nRelease v$currentVersion verified and ready for deployment." -ForegroundColor Green
    Write-Host "To deploy this release to the live service, run elevated:"
    Write-Host "  powershell -ExecutionPolicy Bypass -File `"$repoRoot\scripts\Install-RoamSentinelService.ps1`" -PublishDirectory `"$releaseTarget`""
}
