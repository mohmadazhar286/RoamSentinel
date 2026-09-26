using RoamSentinel.Core;

namespace RoamSentinel.Logs;

public sealed class EventLogService(
    IEventRepository repository,
    IStructuredLogService logs) : IEventLogService
{
    public void RecordAlerts(IEnumerable<AlertDto> alerts)
    {
        foreach (var alert in alerts)
        {
            if (repository.TryAdd(alert))
            {
                logs.Security(
                    "security.alert",
                    alert.Title,
                    new
                    {
                        alert.Id,
                        alert.Category,
                        alert.Severity,
                        alert.Detail
                    });
            }
        }
    }

    public void RecordAction(string title, string severity, string detail)
    {
        repository.AddOrUpdate(new AlertDto(
            Guid.NewGuid().ToString("N"),
            DateTimeOffset.Now,
            "Action",
            severity,
            title,
            detail));
        logs.Security(
            "security.action",
            title,
            new { Severity = severity, Detail = detail });
    }

    public IReadOnlyList<AlertDto> GetRecent(int limit = 200) =>
        repository.GetRecent(limit);

    public int Purge() => repository.Purge();
}
