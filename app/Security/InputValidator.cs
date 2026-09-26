using System.Text.RegularExpressions;

namespace RoamSentinel.App.Security;

public static partial class InputValidator
{
    public static bool IsRequiredText(
        string? value,
        int maximumLength) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length <= maximumLength &&
        !value.Contains('\0');

    public static bool IsOptionalText(
        string? value,
        int maximumLength) =>
        value is null ||
        value.Length <= maximumLength && !value.Contains('\0');

    public static bool IsAbsolutePath(string? value) =>
        IsRequiredText(value, 32_000) &&
        Path.IsPathFullyQualified(value!);

    public static bool IsIdentifier(string? value) =>
        IsRequiredText(value, 128) &&
        IdentifierPattern().IsMatch(value!);

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._:-]*$")]
    private static partial Regex IdentifierPattern();
}
