using System.Text.Json;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.Logs;

public sealed class StructuredLogService : IStructuredLogService
{
    private readonly object _gate = new();
    private readonly string _directory;
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public StructuredLogService(
        IHostEnvironment environment,
        StructuredLoggingOptions options)
        : this(
            Path.IsPathFullyQualified(options.Directory)
                ? Path.GetFullPath(options.Directory)
                : Path.GetFullPath(Path.Combine(
                    environment.ContentRootPath,
                    options.Directory)),
            options.RetentionDays)
    {
    }

    public StructuredLogService(
        IRuntimePathService runtimePaths,
        StructuredLoggingOptions options)
        : this(
            runtimePaths.ResolveLogPath(options.Directory),
            options.RetentionDays)
    {
    }

    private StructuredLogService(string directory, int retentionDays)
    {
        _directory = directory;
        Directory.CreateDirectory(_directory);
        RemoveExpiredLogs(retentionDays);
        foreach (var fileName in new[]
        {
            "app.log",
            "security.log",
            "response.log",
            "error.log"
        })
        {
            using var stream = File.Open(
                Path.Combine(_directory, fileName),
                FileMode.Append,
                FileAccess.Write,
                FileShare.ReadWrite);
        }
    }

    public void App(string eventName, string message, object? data = null) =>
        Write("app.log", "Information", eventName, message, data, null);

    public void Security(
        string eventName,
        string message,
        object? data = null) =>
        Write("security.log", "Security", eventName, message, data, null);

    public void Response(
        string eventName,
        string message,
        object? data = null) =>
        Write("response.log", "Response", eventName, message, data, null);

    public void Error(
        string eventName,
        Exception exception,
        object? data = null) =>
        Write(
            "error.log",
            "Error",
            eventName,
            exception.Message,
            data,
            exception);

    private void Write(
        string fileName,
        string level,
        string eventName,
        string message,
        object? data,
        Exception? exception)
    {
        var entry = new
        {
            timestamp = DateTimeOffset.UtcNow,
            level,
            eventName,
            message,
            machine = Environment.MachineName,
            processId = Environment.ProcessId,
            data,
            exception = exception is null
                ? null
                : new
                {
                    type = exception.GetType().FullName,
                    exception.StackTrace
                }
        };
        var line = JsonSerializer.Serialize(entry, _jsonOptions);
        lock (_gate)
        {
            File.AppendAllText(
                Path.Combine(_directory, fileName),
                line + Environment.NewLine);
        }
    }

    private void RemoveExpiredLogs(int retentionDays)
    {
        var threshold = DateTime.UtcNow.AddDays(-retentionDays);
        foreach (var fileName in new[]
        {
            "app.log",
            "security.log",
            "response.log",
            "error.log"
        })
        {
            var path = Path.Combine(_directory, fileName);
            if (File.Exists(path) &&
                File.GetLastWriteTimeUtc(path) < threshold)
            {
                File.Delete(path);
            }
        }
    }
}
