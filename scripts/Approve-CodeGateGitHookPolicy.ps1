[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Repository,
    [Parameter(Mandatory = $true)]
    [string]$ApprovedBy,
    [Parameter(Mandatory = $true)]
    [string]$Reason,
    [string]$Ticket = "",
    [ValidateSet("pre-receive", "post-receive")]
    [string]$Mode = "",
    [string[]]$BlockVerdicts,
    [switch]$Json
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

if ([string]::IsNullOrWhiteSpace($ApprovedBy) -or $ApprovedBy.Length -gt 128) {
    throw "ApprovedBy is required and must be 128 characters or fewer."
}

if ([string]::IsNullOrWhiteSpace($Reason) -or $Reason.Length -gt 500) {
    throw "Reason is required and must be 500 characters or fewer."
}

$repositoryPath = [System.IO.Path]::GetFullPath($Repository)
$policyPath = Join-Path (Join-Path $repositoryPath "hooks") "roamsentinel-codegate.policy.json"
if (-not (Test-Path -LiteralPath $policyPath -PathType Leaf)) {
    throw "CodeGate policy file was not found: $policyPath"
}

$policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
if ($policy.schemaVersion -ne "1.0") {
    throw "Unsupported CodeGate policy schema: $($policy.schemaVersion)"
}

$previous = [ordered]@{
    approvedBy = [string]$policy.approvedBy
    approvedAt = [string]$policy.approvedAt
    approvalReason = [string]$policy.approvalReason
    approvalTicket = [string]$policy.approvalTicket
    mode = [string]$policy.mode
    blockVerdicts = @($policy.blockVerdicts | ForEach-Object { [string]$_ })
}

if (-not [string]::IsNullOrWhiteSpace($Mode)) {
    $policy.mode = $Mode
}

if ($PSBoundParameters.ContainsKey("BlockVerdicts")) {
    Assert-ValidVerdicts -Verdicts $BlockVerdicts
    $policy.blockVerdicts = @($BlockVerdicts)
}

$approvedAt = [DateTimeOffset]::UtcNow.ToString("O")
$entry = [ordered]@{
    approvedBy = $ApprovedBy
    approvedAt = $approvedAt
    reason = $Reason
    ticket = $Ticket
    mode = [string]$policy.mode
    blockVerdicts = @($policy.blockVerdicts | ForEach-Object { [string]$_ })
    previous = $previous
}

$history = @()
if ($policy.approvalHistory) {
    $history = @($policy.approvalHistory)
}
$history += [pscustomobject]$entry

$policy.approvedBy = $ApprovedBy
$policy.approvedAt = $approvedAt
$policy.approvalReason = $Reason
$policy.approvalTicket = $Ticket
$policy.approvalHistory = @($history)

$policy | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath $policyPath -Encoding UTF8

$result = [pscustomobject]@{
    repository = $repositoryPath
    policyPath = $policyPath
    approvedBy = $ApprovedBy
    approvedAt = $approvedAt
    reason = $Reason
    ticket = $Ticket
    mode = [string]$policy.mode
    blockVerdicts = @($policy.blockVerdicts | ForEach-Object { [string]$_ })
}

if ($Json) {
    $result | ConvertTo-Json -Depth 5
}
else {
    Write-Host "RoamSentinel CodeGate policy approved: $policyPath"
    Write-Host "Approved by: $ApprovedBy"
    Write-Host "Reason: $Reason"
}
