using System.Diagnostics;
using System.Text;
using RoamSentinel.Core;

namespace RoamSentinel.App.Infrastructure;

public sealed class PowerShellRunner(
    IStructuredLogService logs) : IPowerShellRunner
{
    public async Task<CommandResult> RunAsync(
        PowerShellCommand command,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        Validate(command);
        var encodedCommand = Convert.ToBase64String(
            Encoding.Unicode.GetBytes(command.Script));
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("Bypass");
        startInfo.ArgumentList.Add("-EncodedCommand");
        startInfo.ArgumentList.Add(encodedCommand);
        foreach (var parameter in command.Parameters ??
                     new Dictionary<string, string>())
        {
            startInfo.Environment[
                $"ROAMSENTINEL_PARAM_{parameter.Key}"] = parameter.Value;
        }

        using var process = new Process { StartInfo = startInfo };
        try
        {
            process.Start();
            var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
            var waitTask = process.WaitForExitAsync(cancellationToken);
            var timeoutTask = Task.Delay(timeout, cancellationToken);
            var completed = await Task.WhenAny(waitTask, timeoutTask);

            if (completed != waitTask)
            {
                TryKill(process);
                return new CommandResult(-1, await outputTask, "Command timed out.");
            }

            return new CommandResult(
                process.ExitCode,
                (await outputTask).Trim(),
                (await errorTask).Trim());
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            TryKill(process);
            throw;
        }
        catch (Exception ex)
        {
            logs.Error(
                "powershell.execution_failed",
                ex,
                new { ParameterNames = command.Parameters?.Keys });
            return new CommandResult(-1, "", ex.Message);
        }
    }

    private static void Validate(PowerShellCommand command)
    {
        if (string.IsNullOrWhiteSpace(command.Script) ||
            command.Script.Length > 100_000)
        {
            throw new ArgumentException("Trusted PowerShell script is invalid.");
        }

        foreach (var parameter in command.Parameters ??
                     new Dictionary<string, string>())
        {
            if (parameter.Key.Length is < 1 or > 64 ||
                parameter.Key.Any(character =>
                    !char.IsAsciiLetterOrDigit(character) &&
                    character != '_'))
            {
                throw new ArgumentException(
                    "PowerShell parameter name is invalid.");
            }

            if (parameter.Value.Length > 32_000 ||
                parameter.Value.Contains('\0'))
            {
                throw new ArgumentException(
                    $"PowerShell parameter '{parameter.Key}' is invalid.");
            }
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // Best effort cleanup after timeout/cancellation.
        }
    }
}
