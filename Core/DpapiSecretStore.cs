using System.Security.Cryptography;
using System.Text;

namespace RoamSentinel.Core;

public sealed class DpapiSecretStore(IRuntimePathService runtimePaths)
    : ILocalSecretStore
{
    public void Set(string name, string value)
    {
        var path = GetPath(name);
        var plaintext = Encoding.UTF8.GetBytes(value);
        var protectedBytes = ProtectedData.Protect(
            plaintext,
            GetEntropy(name),
            DataProtectionScope.LocalMachine);
        var temporary = $"{path}.{Guid.NewGuid():N}.tmp";
        File.WriteAllBytes(temporary, protectedBytes);
        File.Move(temporary, path, overwrite: true);
    }

    public string? Get(string name)
    {
        var path = GetPath(name);
        if (!File.Exists(path))
        {
            return null;
        }

        var plaintext = ProtectedData.Unprotect(
            File.ReadAllBytes(path),
            GetEntropy(name),
            DataProtectionScope.LocalMachine);
        return Encoding.UTF8.GetString(plaintext);
    }

    public bool Delete(string name)
    {
        var path = GetPath(name);
        if (!File.Exists(path))
        {
            return false;
        }

        File.Delete(path);
        return true;
    }

    private string GetPath(string name)
    {
        if (string.IsNullOrWhiteSpace(name) ||
            name.Any(character =>
                !char.IsLetterOrDigit(character) &&
                character is not '-' and not '_' and not '.'))
        {
            throw new ArgumentException("Secret name is invalid.", nameof(name));
        }

        runtimePaths.EnsureDirectories();
        return runtimePaths.ResolveConfigPath($"{name}.secret");
    }

    private static byte[] GetEntropy(string name) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(
            $"RoamSentinel.LocalSecret.v1:{name}"));
}
