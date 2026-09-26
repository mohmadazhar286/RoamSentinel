[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Repository,
    [ValidateSet("pre-receive", "post-receive")]
    [string]$ExpectedMode = "pre-receive",
    [string[]]$AllowedBlockVerdicts = @("block"),
    [switch]$RequireApproval,
    [switch]$Json
)

$ErrorActionPreference = "Stop"

function Test-OneRepository([string]$Path) {
    $repositoryPath = [System.IO.Path]::GetFullPath($Path)
    $hooksDirectory = Join-Path $repositoryPath "hooks"
    $policyPath = Join-Path $hooksDirectory "roamsentinel-codegate.policy.json"
    $preReceive = Join-Path $hooksDirectory "pre-receive"
    $postReceive = Join-Path $hooksDirectory "post-receive"
    $issues = New-Object System.Collections.Generic.List[string]

    if (-not (Test-Path -LiteralPath $repositoryPath -PathType Container)) {
        $issues.Add("repository_missing")
        return [pscustomobject]@{
            repository = $repositoryPath
            ok = $false
            mode = ""
            hook = ""
            policyPath = $policyPath
            blockVerdicts = @()
            issues = @($issues)
        }
    }

    if (-not (Test-Path -LiteralPath $hooksDirectory -PathType Container)) {
        $issues.Add("hooks_directory_missing")
    }

    $expectedHook = if ($ExpectedMode -eq "pre-receive") { $preReceive } else { $postReceive }
    if (-not (Test-Path -LiteralPath $expectedHook -PathType Leaf)) {
        $issues.Add("expected_hook_missing")
    }
    else {
        $hookText = Get-Content -LiteralPath $expectedHook -Raw
        if ($hookText -notmatch "Invoke-RoamSentinelCodeGateGitHook.ps1") {
            $issues.Add("hook_helper_missing")
        }
        if ($hookText -notmatch "roamsentinel-codegate.policy.json") {
            $issues.Add("policy_reference_missing")
        }
    }

    $mode = ""
    $blockVerdicts = @()
    $approvedBy = ""
    $approvedAt = ""
    $approvalReason = ""
    $approvalTicket = ""
    $approvalHistoryCount = 0
    if (-not (Test-Path -LiteralPath $policyPath -PathType Leaf)) {
        $issues.Add("policy_missing")
    }
    else {
        try {
            $policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
            $mode = [string]$policy.mode
            $blockVerdicts = @($policy.blockVerdicts | ForEach-Object { [string]$_ })
            $approvedBy = [string]$policy.approvedBy
            $approvedAt = [string]$policy.approvedAt
            $approvalReason = [string]$policy.approvalReason
            $approvalTicket = [string]$policy.approvalTicket
            $approvalHistoryCount = @($policy.approvalHistory).Count
            if ($policy.schemaVersion -ne "1.0") {
                $issues.Add("unsupported_schema")
            }
            if ($mode -ne $ExpectedMode) {
                $issues.Add("mode_mismatch")
            }
            if ($blockVerdicts.Count -eq 0) {
                $issues.Add("block_verdicts_empty")
            }
            foreach ($verdict in $blockVerdicts) {
                if ($verdict -notin $AllowedBlockVerdicts) {
                    $issues.Add("unapproved_block_verdict:$verdict")
                }
            }
            if ($RequireApproval) {
                if ([string]::IsNullOrWhiteSpace($approvedBy)) {
                    $issues.Add("approval_missing")
                }
                if ([string]::IsNullOrWhiteSpace($approvedAt)) {
                    $issues.Add("approval_timestamp_missing")
                }
                if ([string]::IsNullOrWhiteSpace($approvalReason)) {
                    $issues.Add("approval_reason_missing")
                }
                if ($approvalHistoryCount -lt 1) {
                    $issues.Add("approval_history_missing")
                }
            }
        }
        catch {
            $issues.Add("policy_invalid_json")
        }
    }

    [pscustomobject]@{
        repository = $repositoryPath
        ok = $issues.Count -eq 0
        mode = $mode
        hook = $expectedHook
        policyPath = $policyPath
        blockVerdicts = @($blockVerdicts)
        approvedBy = $approvedBy
        approvedAt = $approvedAt
        approvalReason = $approvalReason
        approvalTicket = $approvalTicket
        approvalHistoryCount = $approvalHistoryCount
        issues = @($issues)
    }
}

$results = @($Repository | ForEach-Object { Test-OneRepository -Path $_ })
if ($Json) {
    $results | ConvertTo-Json -Depth 5
}
else {
    foreach ($result in $results) {
        $state = if ($result.ok) { "OK" } else { "FAIL" }
        Write-Host "$state $($result.repository)"
        if (-not $result.ok) {
            Write-Host "  Issues: $($result.issues -join ', ')"
        }
    }
}

if ($results | Where-Object { -not $_.ok }) {
    exit 1
}
