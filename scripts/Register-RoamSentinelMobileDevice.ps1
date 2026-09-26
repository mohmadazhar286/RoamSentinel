[CmdletBinding()]
param(
    [ValidatePattern('^\d{6}$')]
    [string]$PairingCode,

    [string]$PairingPayload,

    [string]$BaseUrl = "http://127.0.0.1:5117",

    [string]$DeviceId = "android-test-1",

    [string]$DisplayName = "Android Companion",

    [string]$Platform = "Android",

    [string]$Manufacturer = "Unknown",

    [string]$Model = "Unknown",

    [string]$OsVersion = "Unknown",

    [string]$AppVersion = "0.1.0",

    [string]$TokenOutputPath
)

$ErrorActionPreference = "Stop"

if ($PairingPayload) {
    $uri = [Uri]$PairingPayload
    $parsed = @{}
    foreach ($part in $uri.Query.TrimStart("?").Split("&", [System.StringSplitOptions]::RemoveEmptyEntries)) {
        $nameValue = $part.Split("=", 2)
        if ($nameValue.Count -eq 2) {
            $parsed[[Uri]::UnescapeDataString($nameValue[0])] =
                [Uri]::UnescapeDataString($nameValue[1])
        }
    }

    if ([string]::IsNullOrWhiteSpace($PairingCode)) {
        if ($parsed.ContainsKey("c")) {
            $PairingCode = $parsed["c"]
        }
        elseif ($parsed.ContainsKey("code")) {
            $PairingCode = $parsed["code"]
        }
    }

    if ($parsed.ContainsKey("b") -and
        -not [string]::IsNullOrWhiteSpace($parsed["b"])) {
        $BaseUrl = $parsed["b"]
    }
    elseif ($parsed.ContainsKey("base") -and
        -not [string]::IsNullOrWhiteSpace($parsed["base"])) {
        $BaseUrl = $parsed["base"]
    }
}

if ([string]::IsNullOrWhiteSpace($PairingCode) -or $PairingCode -notmatch '^\d{6}$') {
    throw "Provide -PairingCode as a 6-digit code or -PairingPayload from the RS Console QR."
}

$base = $BaseUrl.TrimEnd("/")
$body = @{
    pairingCode = $PairingCode
    deviceId = $DeviceId
    displayName = $DisplayName
    platform = $Platform
    manufacturer = $Manufacturer
    model = $Model
    osVersion = $OsVersion
    appVersion = $AppVersion
} | ConvertTo-Json -Depth 4

$result = Invoke-RestMethod `
    -Method Post `
    -Uri "$base/api/mobile-bridge/enroll" `
    -ContentType "application/json" `
    -Body $body

if (-not $result.ok) {
    throw "Mobile enrollment failed: $($result.message)"
}

if ($TokenOutputPath) {
    $target = [System.IO.Path]::GetFullPath($TokenOutputPath)
    $parent = Split-Path -Parent $target
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent | Out-Null
    }
    $record = [ordered]@{
        deviceId = $result.deviceId
        deviceToken = $result.deviceToken
        baseUrl = $base
        enrolledAt = [DateTimeOffset]::UtcNow.ToString("O")
    }
    $record | ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath $target -Encoding UTF8
    Write-Host "Mobile device enrolled. Device token saved to $target"
}
else {
    Write-Host "Mobile device enrolled."
    Write-Host "DeviceId: $($result.deviceId)"
    Write-Host "DeviceToken: $($result.deviceToken)"
    Write-Host "Store the device token securely; it is required for heartbeat, inventory, and findings submissions."
}
