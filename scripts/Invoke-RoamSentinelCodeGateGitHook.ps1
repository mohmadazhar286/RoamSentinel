[CmdletBinding()]
param(
    [string]$RoamSentinelExe = "$env:ProgramFiles\RoamSentinel\RoamSentinel.exe",
    [string]$Repository = (Get-Location).Path,
    [ValidateSet("pre-receive", "post-receive")]
    [string]$Mode = "pre-receive",
    [string]$Actor = $env:USERNAME,
    [string]$PolicyPath
)

$ErrorActionPreference = "Stop"

function Read-CodeGatePolicy([string]$Path) {
    $policy = [ordered]@{
        mode = $Mode
        actor = $Actor
        roamSentinelExe = $RoamSentinelExe
        blockVerdicts = @("block")
    }

    if ([string]::IsNullOrWhiteSpace($Path) -or
        -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]$policy
    }

    $loaded = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($loaded.mode -and $loaded.mode -in @("pre-receive", "post-receive")) {
        $policy.mode = [string]$loaded.mode
    }
    if ($loaded.actor) {
        $policy.actor = [string]$loaded.actor
    }
    if ($loaded.roamSentinelExe) {
        $policy.roamSentinelExe = [string]$loaded.roamSentinelExe
    }
    if ($loaded.blockVerdicts) {
        $policy.blockVerdicts = @($loaded.blockVerdicts |
            ForEach-Object { [string]$_ } |
            Where-Object { $_ -in @("block", "warn", "needs_review") })
        if ($policy.blockVerdicts.Count -eq 0) {
            $policy.blockVerdicts = @("block")
        }
    }

    return [pscustomobject]$policy
}

$policy = Read-CodeGatePolicy -Path $PolicyPath
$Mode = $policy.mode
$Actor = $policy.actor
$RoamSentinelExe = $policy.roamSentinelExe
$blockVerdicts = @($policy.blockVerdicts)

if (-not (Test-Path -LiteralPath $RoamSentinelExe)) {
    throw "RoamSentinel executable was not found: $RoamSentinelExe"
}

$repositoryPath = [System.IO.Path]::GetFullPath($Repository)
$repositoryName = Split-Path -Leaf $repositoryPath
$updates = @($input | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($updates.Count -eq 0) {
    return
}

foreach ($line in $updates) {
    $parts = @($line -split '\s+' | Where-Object { $_ })
    if ($parts.Count -lt 3) {
        Write-Error "Invalid Git hook input: $line"
        exit 1
    }

    $oldRevision = $parts[0]
    $newRevision = $parts[1]
    $refName = $parts[2]
    $branch = $refName -replace '^refs/heads/', ''
    if ($newRevision -match '^0+$') {
        Write-Host "RoamSentinel CodeGate: skipping deleted ref $refName"
        continue
    }

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        "RoamSentinel-CodeGate-" + [Guid]::NewGuid().ToString("N"))
    $archive = Join-Path $tempRoot "revision.tar"
    $changedFilesJson = Join-Path $tempRoot "changed-files.json"
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
    try {
        $changedFiles = @()
        if ($oldRevision -match '^0+$') {
            $changedFiles = @(& git --git-dir $repositoryPath ls-tree `
                -r --name-only $newRevision)
        }
        else {
            $changedFiles = @(& git --git-dir $repositoryPath diff-tree `
                --no-commit-id --name-only -r $oldRevision $newRevision)
        }

        ConvertTo-Json -InputObject @($changedFiles) -Depth 3 |
            Set-Content -LiteralPath $changedFilesJson -Encoding UTF8

        & git --git-dir $repositoryPath archive `
            --format=tar $newRevision -o $archive
        if ($LASTEXITCODE -ne 0) {
            throw "git archive failed for $newRevision"
        }

        & tar -xf $archive -C $tempRoot
        if ($LASTEXITCODE -ne 0) {
            throw "tar extraction failed for $newRevision"
        }

        $output = & $RoamSentinelExe `
            --codegate-git-push `
            --repository $repositoryPath `
            --repository-name $repositoryName `
            --scan-path $tempRoot `
            --ref $refName `
            --branch $branch `
            --old $oldRevision `
            --new $newRevision `
            --actor $Actor `
            --changed-files-json $changedFilesJson
        $exit = $LASTEXITCODE
        $output | ForEach-Object { Write-Host $_ }
        if ($exit -ne 0) {
            exit $exit
        }

        $verdictLine = ($output | Where-Object {
            $_ -match 'CodeGate git-push verdict='
        } | Select-Object -First 1)
        if ($Mode -eq "pre-receive" -and
            $verdictLine -match 'verdict=([a-z_]+)') {
            $verdict = $Matches[1]
            if ($blockVerdicts -contains $verdict) {
                Write-Error "RoamSentinel CodeGate blocked push to $refName with verdict=$verdict."
                exit 1
            }
        }
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
