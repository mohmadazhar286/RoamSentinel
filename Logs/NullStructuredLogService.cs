using RoamSentinel.Core;

namespace RoamSentinel.Logs;

public sealed class NullStructuredLogService : IStructuredLogService
{
    public static NullStructuredLogService Instance { get; } = new();

    private NullStructuredLogService()
    {
    }

    public void App(string eventName, string message, object? data = null)
    {
    }

    public void Security(string eventName, string message, object? data = null)
    {
    }

    public void Response(string eventName, string message, object? data = null)
    {
    }

    public void Error(
        string eventName,
        Exception exception,
        object? data = null)
    {
    }
}
