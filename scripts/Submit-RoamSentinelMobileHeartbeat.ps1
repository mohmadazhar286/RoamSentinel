[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$DeviceToken,

    [string]$BaseUrl = "http://127.0.0.1:5117",

    [string]$DeviceId = "android-test-1",

    [ValidateRange(0, 100)]
    [int]$BatteryPercent = 80,

    [switch]$Charging,

    [long]$StorageFreeMb = 64000,

    [bool]$ScreenLockEnabled = $true,

    [bool]$DeveloperModeEnabled = $false,

    [bool]$UsbDebuggingEnabled = $false,

    [bool]$UnknownSourcesEnabled = $false,

    [bool]$VpnActive = $false
)

$ErrorActionPreference = "Stop"

$base = $BaseUrl.TrimEnd("/")
$body = @{
    deviceToken = $DeviceToken
    deviceId = $DeviceId
    batteryPercent = $BatteryPercent
    charging = [bool]$Charging
    storageFreeMb = $StorageFreeMb
    screenLockEnabled = $ScreenLockEnabled
    developerModeEnabled = $DeveloperModeEnabled
    usbDebuggingEnabled = $UsbDebuggingEnabled
    unknownSourcesEnabled = $UnknownSourcesEnabled
    vpnActive = $VpnActive
    observedAt = [DateTimeOffset]::UtcNow.ToString("O")
} | ConvertTo-Json -Depth 4

$result = Invoke-RestMethod `
    -Method Post `
    -Uri "$base/api/mobile-bridge/heartbeat" `
    -ContentType "application/json" `
    -Body $body

Write-Host "Mobile heartbeat accepted."
Write-Host "DeviceId: $($result.deviceId)"
Write-Host "RiskScore: $($result.riskScore)"
Write-Host "RiskReason: $($result.riskReason)"
