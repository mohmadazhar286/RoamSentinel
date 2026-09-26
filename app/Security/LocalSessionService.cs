using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using RoamSentinel.Config;
using RoamSentinel.Core;

namespace RoamSentinel.App.Security;

public sealed class LocalSessionService(
    AccessControlOptions options,
    ResponseOptions responseOptions,
    IAuditRepository audit,
    IStructuredLogService logs) : ILocalSessionService
{
    private readonly ConcurrentDictionary<string, LocalSession> _sessions =
        new(StringComparer.Ordinal);

    public SessionDto Login(
        string token,
        IPAddress? remoteAddress,
        HttpResponse response)
    {
        if (remoteAddress is null || !IPAddress.IsLoopback(remoteAddress))
        {
            RecordLogin("remote", remoteAddress, false, "Non-loopback login.");
            throw new UnauthorizedAccessException(
                "Login is restricted to the local computer.");
        }

        var role = MatchRole(token);
        if (role is null)
        {
            RecordLogin("unknown", remoteAddress, false, "Invalid token.");
            throw new UnauthorizedAccessException("Invalid login token.");
        }

        var session = new LocalSession(
            RandomToken(),
            role,
            RandomToken(),
            DateTimeOffset.UtcNow.AddMinutes(options.SessionMinutes));
        _sessions[session.SessionId] = session;
        response.Cookies.Append(
            options.SessionCookieName,
            session.SessionId,
            new CookieOptions
            {
                HttpOnly = true,
                SameSite = SameSiteMode.Strict,
                Secure = false,
                IsEssential = true,
                Path = "/",
                Expires = session.ExpiresAt
            });
        RecordLogin(role, remoteAddress, true, "Login succeeded.");
        return ToDto(session);
    }

    public SessionDto GetSession(HttpRequest request)
    {
        var session = Resolve(request);
        return session is null
            ? new SessionDto(false, "Viewer", "", null)
            : ToDto(session);
    }

    public LocalSession? Resolve(HttpRequest request)
    {
        if (!request.Cookies.TryGetValue(
                options.SessionCookieName,
                out var sessionId) ||
            !_sessions.TryGetValue(sessionId, out var session))
        {
            return null;
        }

        if (session.ExpiresAt <= DateTimeOffset.UtcNow)
        {
            _sessions.TryRemove(sessionId, out _);
            return null;
        }

        return session;
    }

    public void Logout(HttpRequest request, HttpResponse response)
    {
        var session = Resolve(request);
        if (session is not null)
        {
            _sessions.TryRemove(session.SessionId, out _);
            audit.Write(
                session.Role,
                "authentication.logout",
                "session",
                session.SessionId,
                true,
                "{}");
        }

        response.Cookies.Delete(options.SessionCookieName);
    }

    public bool HasRole(LocalSession? session, string requiredRole)
    {
        var actual = session?.Role ?? "Viewer";
        return Rank(actual) >= Rank(requiredRole);
    }

    public bool ValidateCsrf(LocalSession? session, string? token) =>
        session is not null &&
        FixedTimeEquals(session.CsrfToken, token);

    private string? MatchRole(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return null;
        }

        var administratorToken =
            string.IsNullOrWhiteSpace(options.AdministratorToken)
                ? responseOptions.OperatorToken
                : options.AdministratorToken;
        if (FixedTimeEquals(administratorToken, token))
        {
            return "Administrator";
        }

        if (FixedTimeEquals(options.AnalystToken, token))
        {
            return "Analyst";
        }

        return FixedTimeEquals(options.ViewerToken, token)
            ? "Viewer"
            : null;
    }

    private void RecordLogin(
        string actor,
        IPAddress? address,
        bool success,
        string message)
    {
        var data = System.Text.Json.JsonSerializer.Serialize(new
        {
            RemoteAddress = address?.ToString() ?? "unknown",
            Message = message
        });
        audit.Write(
            actor,
            "authentication.login",
            "session",
            address?.ToString() ?? "unknown",
            success,
            data);
        logs.Security(
            "authentication.login",
            message,
            new
            {
                Actor = actor,
                RemoteAddress = address?.ToString() ?? "unknown",
                Success = success
            });
    }

    private static SessionDto ToDto(LocalSession session) =>
        new(
            true,
            session.Role,
            session.CsrfToken,
            session.ExpiresAt);

    private static int Rank(string role) =>
        role switch
        {
            "Administrator" => 2,
            "Analyst" => 1,
            _ => 0
        };

    private static string RandomToken() =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    private static bool FixedTimeEquals(string expected, string? actual)
    {
        if (string.IsNullOrEmpty(expected) || string.IsNullOrEmpty(actual))
        {
            return false;
        }

        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        var actualBytes = Encoding.UTF8.GetBytes(actual);
        return expectedBytes.Length == actualBytes.Length &&
               CryptographicOperations.FixedTimeEquals(
                   expectedBytes,
                   actualBytes);
    }
}
