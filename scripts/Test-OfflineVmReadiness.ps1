[CmdletBinding()]
param(
    [string]$PublishDirectory,
    [string]$InstallDirectory = "$env:ProgramFiles\RoamSentinel",
    [string]$ProgramDataDirectory = "$env:ProgramData\RoamSentinel",
    [ValidateSet("Workstation", "AgentOnly", "CodeGateVm")]
    [string]$ExpectedProfile = "CodeGateVm",
    [switch]$Installed,
    [switch]$RequireService
)

$ErrorActionPreference = "Stop"

function Resolve-CheckRoot {
    if ($Installed) {
        return [System.IO.Path]::GetFullPath($InstallDirectory)
    }

    if ([string]::IsNullOrWhiteSpace($PublishDirectory)) {
        throw "Provide -PublishDirectory or use -Installed."
    }

    return [System.IO.Path]::GetFullPath($PublishDirectory)
}

function Assert-File([string]$Root, [string]$RelativePath) {
    $path = Join-Path $Root $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing required offline VM asset: $RelativePath"
    }
}

function Assert-Directory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "Missing required directory: $Path"
    }
}

$root = Resolve-CheckRoot

$requiredFiles = @(
    "RoamSentinel.exe",
    "RoamSentinel.dll",
    "appsettings.json",
    "install-profile.json",
    "public\index.html",
    "public\app.js",
    "public\styles.css",
    "scripts\Invoke-RoamSentinelCodeGateGitHook.ps1",
    "scripts\Install-CodeGateGitHook.ps1",
    "scripts\Approve-CodeGateGitHookPolicy.ps1",
    "scripts\Test-CodeGateGitHookPolicy.ps1",
    "scripts\Invoke-RoamSentinelEvidenceExport.ps1",
    "scripts\Invoke-OfflineVmReleaseRehearsal.ps1",
    "scripts\Register-RoamSentinelMobileDevice.ps1",
    "scripts\Submit-RoamSentinelMobileHeartbeat.ps1",
    "scripts\Invoke-RoamSentinelStagingGate.ps1",
    "scripts\git-hooks\pre-receive",
    "scripts\git-hooks\post-receive"
)

foreach ($file in $requiredFiles) {
    Assert-File -Root $root -RelativePath $file
}

$profilePath = Join-Path $root "install-profile.json"
$profile = Get-Content -LiteralPath $profilePath -Raw | ConvertFrom-Json
if ($profile.product -ne "RoamSentinel") {
    throw "Install profile manifest has invalid product: $($profile.product)"
}
if ($ExpectedProfile -and $profile.profile -ne $ExpectedProfile) {
    throw "Install profile mismatch. Expected $ExpectedProfile, found $($profile.profile)."
}
if ($ExpectedProfile -eq "CodeGateVm" -and -not $profile.includesCodeGateVmTools) {
    throw "CodeGate VM profile must include CodeGate VM tools."
}

$hookHelper = Join-Path $root "scripts\Invoke-RoamSentinelCodeGateGitHook.ps1"
$helperText = Get-Content -LiteralPath $hookHelper -Raw
foreach ($marker in @("--codegate-git-push", "--repository", "--scan-path")) {
    if ($helperText -notmatch [regex]::Escape($marker)) {
        throw "Git hook helper does not contain required marker: $marker"
    }
}

$installerText = Get-Content -LiteralPath (
    Join-Path $root "scripts\Install-CodeGateGitHook.ps1") -Raw
foreach ($marker in @("roamsentinel-codegate.policy.json", "blockVerdicts")) {
    if ($installerText -notmatch [regex]::Escape($marker)) {
        throw "Git hook installer does not contain required marker: $marker"
    }
}

$reviewText = Get-Content -LiteralPath (
    Join-Path $root "scripts\Test-CodeGateGitHookPolicy.ps1") -Raw
foreach ($marker in @("roamsentinel-codegate.policy.json", "AllowedBlockVerdicts", "RequireApproval")) {
    if ($reviewText -notmatch [regex]::Escape($marker)) {
        throw "Git hook policy review script does not contain required marker: $marker"
    }
}

$approvalText = Get-Content -LiteralPath (
    Join-Path $root "scripts\Approve-CodeGateGitHookPolicy.ps1") -Raw
foreach ($marker in @("approvalHistory", "approvedBy", "approvalReason")) {
    if ($approvalText -notmatch [regex]::Escape($marker)) {
        throw "Git hook policy approval script does not contain required marker: $marker"
    }
}

$evidenceText = Get-Content -LiteralPath (
    Join-Path $root "scripts\Invoke-RoamSentinelEvidenceExport.ps1") -Raw
foreach ($marker in @("--export-backup", "--scheduler-status", "scheduler-status.json", "RetentionDays", "evidence-manifest.json")) {
    if ($evidenceText -notmatch [regex]::Escape($marker)) {
        throw "Evidence export script does not contain required marker: $marker"
    }
}

$rehearsalText = Get-Content -LiteralPath (
    Join-Path $root "scripts\Invoke-OfflineVmReleaseRehearsal.ps1") -Raw
foreach ($marker in @("CodeGateVm", "Test-OfflineVmReadiness.ps1", "offline-vm-release-rehearsal.json")) {
    if ($rehearsalText -notmatch [regex]::Escape($marker)) {
        throw "Offline VM release rehearsal script does not contain required marker: $marker"
    }
}

$mobileEnrollmentText = Get-Content -LiteralPath (
    Join-Path $root "scripts\Register-RoamSentinelMobileDevice.ps1") -Raw
foreach ($marker in @("/api/mobile-bridge/enroll", "PairingCode", "PairingPayload", "DeviceToken")) {
    if ($mobileEnrollmentText -notmatch [regex]::Escape($marker)) {
        throw "Mobile enrollment script does not contain required marker: $marker"
    }
}

$mobileHeartbeatText = Get-Content -LiteralPath (
    Join-Path $root "scripts\Submit-RoamSentinelMobileHeartbeat.ps1") -Raw
foreach ($marker in @("/api/mobile-bridge/heartbeat", "DeviceToken", "RiskScore")) {
    if ($mobileHeartbeatText -notmatch [regex]::Escape($marker)) {
        throw "Mobile heartbeat script does not contain required marker: $marker"
    }
}

$stagingGateText = Get-Content -LiteralPath (
    Join-Path $root "scripts\Invoke-RoamSentinelStagingGate.ps1") -Raw
foreach ($marker in @("--codegate-scan", "FailOnWarn", "staging-deployment", "verdict=block")) {
    if ($stagingGateText -notmatch [regex]::Escape($marker)) {
        throw "Staging gate script does not contain required marker: $marker"
    }
}

$indexHtml = Get-Content -LiteralPath (Join-Path $root "public\index.html") -Raw
if ($indexHtml -notmatch "Git Push Traceability" -or
    $indexHtml -notmatch "Offline Bundle Freshness") {
    throw "RS Console is missing CodeGate VM readiness views."
}

if ($Installed) {
    foreach ($folder in "data", "logs", "config") {
        Assert-Directory (Join-Path $ProgramDataDirectory $folder)
    }
}

if ($RequireService) {
    $service = Get-Service -Name RoamSentinel -ErrorAction SilentlyContinue
    if (-not $service) {
        throw "RoamSentinel Windows Service is not installed."
    }

    if ($service.StartType -ne "Automatic") {
        throw "RoamSentinel Windows Service must be configured for automatic start."
    }

    if ($service.Status -ne "Running") {
        throw "RoamSentinel Windows Service must be running. Current status: $($service.Status)."
    }
}

Write-Host "RoamSentinel offline VM readiness validated: $root"
