[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Repository,
    [ValidateSet("pre-receive", "post-receive")]
    [string]$Mode = "pre-receive",
    [string]$InstallDirectory = "$env:ProgramFiles\RoamSentinel",
    [string]$RoamSentinelExe = "$env:ProgramFiles\RoamSentinel\RoamSentinel.exe",
    [string[]]$BlockVerdicts = @("block"),
    [string]$Actor = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Assert-ValidVerdicts([string[]]$Verdicts) {
    $allowed = @("block", "warn", "needs_review")
    foreach ($verdict in $Verdicts) {
        if ($verdict -notin $allowed) {
            throw "Unsupported CodeGate blocking verdict '$verdict'. Allowed: $($allowed -join ', ')"
        }
    }
}

$repositoryPath = [System.IO.Path]::GetFullPath($Repository)
if (-not (Test-Path -LiteralPath $repositoryPath -PathType Container)) {
    throw "Repository directory was not found: $repositoryPath"
}

$hooksDirectory = Join-Path $repositoryPath "hooks"
if (-not (Test-Path -LiteralPath $hooksDirectory -PathType Container)) {
    throw "Git hooks directory was not found. Use a bare Git repository path: $repositoryPath"
}

$helperPath = Join-Path $InstallDirectory "scripts\Invoke-RoamSentinelCodeGateGitHook.ps1"
if (-not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
    throw "CodeGate hook helper was not found: $helperPath"
}

Assert-ValidVerdicts -Verdicts $BlockVerdicts

$hookPath = Join-Path $hooksDirectory $Mode
if ((Test-Path -LiteralPath $hookPath -PathType Leaf) -and -not $Force) {
    throw "Hook already exists: $hookPath. Re-run with -Force to replace it."
}

$policyPath = Join-Path $hooksDirectory "roamsentinel-codegate.policy.json"
$policy = [ordered]@{
    schemaVersion = "1.0"
    mode = $Mode
    actor = $Actor
    roamSentinelExe = $RoamSentinelExe
    blockVerdicts = @($BlockVerdicts)
    approvedBy = ""
    approvedAt = ""
    approvalReason = ""
    approvalTicket = ""
    approvalHistory = @()
}
$policy | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath $policyPath -Encoding UTF8

$helperForGit = $helperPath -replace '\\', '/'
$policyForGit = $policyPath -replace '\\', '/'
$hook = @"
#!/bin/sh
# Installed by RoamSentinel. Do not expose RS Agent outside loopback.
powershell.exe -NoProfile -ExecutionPolicy Bypass \
  -File "$helperForGit" \
  -Repository "`$(pwd)" \
  -PolicyPath "$policyForGit"
"@
$hook | Set-Content -LiteralPath $hookPath -Encoding ASCII

Write-Host "RoamSentinel CodeGate $Mode hook installed: $hookPath"
Write-Host "RoamSentinel CodeGate policy written: $policyPath"
