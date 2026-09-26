[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$PublishDirectory,
    [string]$InstallDirectory = "$env:ProgramFiles\RoamSentinel",
    [ValidateSet("Workstation", "AgentOnly", "CodeGateVm")]
    [string]$Profile = "Workstation",
    [switch]$AgentOnly
)

#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
$source = [System.IO.Path]::GetFullPath($PublishDirectory)
$destination = [System.IO.Path]::GetFullPath($InstallDirectory)
if ($AgentOnly) {
    $Profile = "AgentOnly"
}

function Stop-RoamSentinelConsoleProcesses {
    $processes = @()
    $processes += Get-CimInstance Win32_Process |
        Where-Object {
            $_.Name -eq "RoamSentinel.Console.exe" -or
            ($_.Name -eq "msedgewebview2.exe" -and
                $_.CommandLine -match "RoamSentinel.Console.exe")
        }

    foreach ($process in $processes) {
        Write-Host "Stopping RS Console process $($process.ProcessId) ($($process.Name))."
        Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
    }

    if ($processes.Count -gt 0) {
        Start-Sleep -Seconds 2
    }
}

function Clear-InstallDirectory([string]$Path) {
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            Get-ChildItem -LiteralPath $Path -Force |
                Remove-Item -Recurse -Force
            return
        }
        catch {
            if ($attempt -eq 3) {
                throw
            }

            Stop-RoamSentinelConsoleProcesses
            Start-Sleep -Seconds 2
        }
    }
}

& (Join-Path $PSScriptRoot "Test-PublishOutput.ps1") `
    -PublishDirectory $source `
    -Profile $Profile

if ($PSCmdlet.ShouldProcess($destination, "Install RoamSentinel Windows Service")) {
    Stop-RoamSentinelConsoleProcesses

    $service = Get-Service -Name RoamSentinel -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne "Stopped") {
        Stop-Service -Name RoamSentinel -Force
        $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }

    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    $destinationRoot = [System.IO.Path]::GetPathRoot($destination)
    if ([string]::IsNullOrWhiteSpace($destinationRoot) -or
        $destination.TrimEnd('\') -eq $destinationRoot.TrimEnd('\')) {
        throw "Refusing to clean unsafe install directory: $destination"
    }
    Clear-InstallDirectory -Path $destination
    Copy-Item -Path (Join-Path $source "*") -Destination $destination -Recurse -Force
    foreach ($folder in "data", "logs", "config") {
        New-Item -ItemType Directory -Path "$env:ProgramData\RoamSentinel\$folder" -Force |
            Out-Null
    }

    $binary = Join-Path $destination "RoamSentinel.exe"
    if ($service) {
        & sc.exe config RoamSentinel binPath= "`"$binary`"" start= auto DisplayName= "RoamSentinel Endpoint Security"
        if ($LASTEXITCODE -ne 0) { throw "Service update failed." }
    }
    else {
        New-Service `
            -Name "RoamSentinel" `
            -BinaryPathName "`"$binary`"" `
            -DisplayName "RoamSentinel Endpoint Security" `
            -Description "Local-first Windows endpoint security agent and dashboard." `
            -StartupType Automatic | Out-Null
    }

    & sc.exe failure RoamSentinel reset= 86400 actions= restart/5000/restart/15000/restart/60000
    if ($LASTEXITCODE -ne 0) { throw "Service recovery configuration failed." }
    Start-Service -Name RoamSentinel

    if ($Profile -ne "AgentOnly") {
        $console = Join-Path $destination "Console\RoamSentinel.Console.exe"
        $shell = New-Object -ComObject WScript.Shell
        $startMenu = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs"
        $startShortcut = $shell.CreateShortcut(
            (Join-Path $startMenu "RoamSentinel Management Console.lnk"))
        $startShortcut.TargetPath = $console
        $startShortcut.WorkingDirectory = (Split-Path $console)
        $startShortcut.Description = "RoamSentinel Endpoint Security Management Console"
        $startShortcut.Save()

        $publicDesktop = [Environment]::GetFolderPath("CommonDesktopDirectory")
        $consoleShortcut = $shell.CreateShortcut(
            (Join-Path $publicDesktop "RoamSentinel.lnk"))
        $consoleShortcut.TargetPath = $console
        $consoleShortcut.WorkingDirectory = (Split-Path $console)
        $consoleShortcut.Description = "RoamSentinel Endpoint Security"
        $consoleShortcut.Save()
    }
}
