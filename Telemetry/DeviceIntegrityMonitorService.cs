using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.Telemetry;

public sealed class DeviceIntegrityMonitorService(
    IDeviceIntegrityInventoryService inventory,
    IDeviceIntegrityRepository repository,
    IDeviceIntegrityFindingRepository findings,
    IStructuredLogService logs,
    TelemetryOptions options) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(
            options.DeviceIntegrityIntervalSeconds));
        do
        {
            try
            {
                var snapshot = await inventory.CollectAsync(stoppingToken);
                if (snapshot.CollectionErrors.Count == 0)
                {
                    var changes = repository.RecordSnapshot(snapshot);
                    if (changes.Count > 0)
                    {
                        var projected = findings.RecordFromChanges(changes);
                        logs.Security(
                            "device_integrity.changed",
                            "Device Integrity changes were observed.",
                            new
                            {
                                Changes = changes.Count,
                                Findings = projected.Count
                            });
                    }
                }
                else
                {
                    logs.App(
                        "device_integrity.collection_incomplete",
                        "Device Integrity collection was incomplete.",
                        new { snapshot.CollectionErrors });
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                logs.Error("device_integrity.monitor.failed", exception);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
