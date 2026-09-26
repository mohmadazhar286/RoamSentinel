using System.Reflection;

namespace RoamSentinel.Core;

public static class ProductInfo
{
    public const string Name = "RoamSentinel";

    public static string Version { get; } =
        typeof(ProductInfo).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion
        ?? typeof(ProductInfo).Assembly.GetName().Version?.ToString()
        ?? "0.0.0";
}
