[CmdletBinding()]
param()

$tokenBytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
$token = [Convert]::ToHexString($tokenBytes)

[Environment]::SetEnvironmentVariable(
    "Response__OperatorToken",
    $token,
    [EnvironmentVariableTarget]::User)

Set-Clipboard -Value $token
Write-Output "Response authorization token stored for the current Windows user."
Write-Output "The token is on the clipboard. Restart RoamSentinel, then paste it into Response authorization."
