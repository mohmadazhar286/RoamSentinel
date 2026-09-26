[CmdletBinding(SupportsShouldProcess)]
param()

#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
if ($PSCmdlet.ShouldProcess("RoamSentinel", "Remove Windows Service")) {
    & sc.exe stop RoamSentinel 2>$null
    & sc.exe delete RoamSentinel
    Remove-Item -LiteralPath (
        Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\RoamSentinel Management Console.lnk"
    ) -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath (
        Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "RoamSentinel.lnk"
    ) -Force -ErrorAction SilentlyContinue
}

Write-Host "ProgramData was retained for backup/recovery. Remove it explicitly if required."
