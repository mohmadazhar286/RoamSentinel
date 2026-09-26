using RoamSentinel.Core;

namespace RoamSentinel.Tests;

public sealed class RuntimePathServiceTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "RoamSentinel.Paths.Tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void ResolvesSeparatedApplicationAndProgramDataPaths()
    {
        var application = Path.Combine(_root, "application");
        var programData = Path.Combine(_root, "program-data");
        var service = new RuntimePathService(application, programData);

        service.EnsureDirectories();

        Assert.Equal(Path.GetFullPath(application), service.Paths.ApplicationDirectory);
        Assert.Equal(
            Path.Combine(programData, "RoamSentinel", "data"),
            service.Paths.DataDirectory);
        Assert.Equal(
            Path.Combine(programData, "RoamSentinel", "logs"),
            service.Paths.LogsDirectory);
        Assert.Equal(
            Path.Combine(programData, "RoamSentinel", "config"),
            service.Paths.ConfigDirectory);
        Assert.Equal(
            Path.Combine(service.Paths.DataDirectory, "roamsentinel.db"),
            service.ResolveDataPath("roamsentinel.db"));
        Assert.True(Directory.Exists(service.Paths.ConfigDirectory));
    }

    [Fact]
    public void AbsoluteConfiguredPathRemainsAbsolute()
    {
        var service = new RuntimePathService(
            Path.Combine(_root, "application"),
            Path.Combine(_root, "program-data"));
        var absolute = Path.Combine(_root, "custom", "database.db");

        Assert.Equal(Path.GetFullPath(absolute), service.ResolveDataPath(absolute));
    }

    [Fact]
    public void DpapiSecretStore_RoundTripsWithoutWritingPlaintext()
    {
        var paths = new RuntimePathService(
            Path.Combine(_root, "application"),
            Path.Combine(_root, "program-data"));
        var secrets = new DpapiSecretStore(paths);

        secrets.Set("api-token", "sensitive-test-value");

        Assert.Equal("sensitive-test-value", secrets.Get("api-token"));
        Assert.DoesNotContain(
            "sensitive-test-value",
            File.ReadAllText(paths.ResolveConfigPath("api-token.secret")));
        Assert.True(secrets.Delete("api-token"));
        Assert.Null(secrets.Get("api-token"));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }
}
