namespace RoamSentinel.Core;

public sealed record RuntimePaths(
    string ApplicationDirectory,
    string ProgramDataDirectory,
    string DataDirectory,
    string LogsDirectory,
    string ConfigDirectory);

public sealed class RuntimePathService : IRuntimePathService
{
    public const string ProgramDataOverride = "ROAMSENTINEL_PROGRAMDATA";

    public RuntimePathService(string applicationDirectory, string? programDataRoot = null)
    {
        var application = Path.GetFullPath(applicationDirectory);
        var root = programDataRoot;
        if (string.IsNullOrWhiteSpace(root))
        {
            root = Environment.GetEnvironmentVariable(ProgramDataOverride);
        }

        if (string.IsNullOrWhiteSpace(root))
        {
            root = Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData);
        }

        if (string.IsNullOrWhiteSpace(root))
        {
            throw new InvalidOperationException(
                "The Windows ProgramData directory could not be resolved.");
        }

        var productRoot = Path.Combine(Path.GetFullPath(root), "RoamSentinel");
        Paths = new RuntimePaths(
            application,
            productRoot,
            Path.Combine(productRoot, "data"),
            Path.Combine(productRoot, "logs"),
            Path.Combine(productRoot, "config"));
    }

    public RuntimePaths Paths { get; }

    public void EnsureDirectories()
    {
        Directory.CreateDirectory(Paths.ProgramDataDirectory);
        Directory.CreateDirectory(Paths.DataDirectory);
        Directory.CreateDirectory(Paths.LogsDirectory);
        Directory.CreateDirectory(Paths.ConfigDirectory);
    }

    public string ResolveDataPath(string path) =>
        Resolve(path, Paths.DataDirectory);

    public string ResolveLogPath(string path) =>
        Resolve(path, Paths.LogsDirectory);

    public string ResolveConfigPath(string path) =>
        Resolve(path, Paths.ConfigDirectory);

    private static string Resolve(string path, string baseDirectory) =>
        Path.GetFullPath(Path.IsPathFullyQualified(path)
            ? path
            : Path.Combine(baseDirectory, path));
}
