using System.Text.Json;

namespace RoamSentinel.Database;

internal static class JsonFileStore
{
    private static readonly JsonSerializerOptions IndentedOptions = new()
    {
        WriteIndented = true
    };

    public static T Load<T>(string path, Func<T> fallback)
    {
        try
        {
            if (!File.Exists(path))
            {
                return fallback();
            }

            return JsonSerializer.Deserialize<T>(File.ReadAllText(path)) ?? fallback();
        }
        catch
        {
            return fallback();
        }
    }

    public static void Save<T>(string path, T value)
    {
        var temporaryPath = path + ".tmp";
        File.WriteAllText(temporaryPath, JsonSerializer.Serialize(value, IndentedOptions));
        File.Move(temporaryPath, path, overwrite: true);
    }
}
