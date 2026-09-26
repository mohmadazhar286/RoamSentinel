using Microsoft.Extensions.Configuration;
using RoamSentinel.Config;

namespace RoamSentinel.Tests;

public sealed class PlatformConfigurationTests
{
    [Fact]
    public void Load_UsesSafeDefaultsWhenSectionsAreMissing()
    {
        var configuration = new ConfigurationBuilder().Build();

        var options = PlatformConfiguration.Load(configuration);

        Assert.Equal("http://127.0.0.1:5117", options.Host.BindUrl);
        Assert.Equal("roamsentinel.db", options.Database.FilePath);
        Assert.Equal(300, options.Database.TelemetryPersistenceIntervalSeconds);
        Assert.Equal(70, options.Detection.HighSeverityScore);
        Assert.True(options.Scheduler.Enabled);
        Assert.False(options.Scheduler.EnableScheduledQuickScan);
    }

    [Fact]
    public void Load_RejectsNonLoopbackBinding()
    {
        var values = new Dictionary<string, string?>
        {
            ["RoamSentinel:BindUrl"] = "http://0.0.0.0:5117"
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(values)
            .Build();

        Assert.Throws<InvalidOperationException>(
            () => PlatformConfiguration.Load(configuration));
    }
}
