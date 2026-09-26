using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using RoamSentinel.App.Infrastructure;
using RoamSentinel.App.Security;
using RoamSentinel.Config;
using RoamSentinel.Core;
using RoamSentinel.Logs;

namespace RoamSentinel.Tests;

public sealed class SecurityHardeningTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        "RoamSentinel.Security.Tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public void Login_CreatesAdministratorSessionAndValidatesCsrf()
    {
        var audit = new MemoryAuditRepository();
        var service = new LocalSessionService(
            new AccessControlOptions
            {
                AdministratorToken = "test-administrator-token"
            },
            new ResponseOptions(),
            audit,
            NullStructuredLogService.Instance);
        var loginContext = new DefaultHttpContext();

        var result = service.Login(
            "test-administrator-token",
            IPAddress.Loopback,
            loginContext.Response);
        var setCookie = loginContext.Response.Headers.SetCookie.ToString();
        var cookie = setCookie.Split(';', 2)[0];
        var requestContext = new DefaultHttpContext();
        requestContext.Request.Headers.Cookie = cookie;
        var session = service.Resolve(requestContext.Request);

        Assert.True(result.Authenticated);
        Assert.Equal("Administrator", result.Role);
        Assert.NotNull(session);
        Assert.True(service.HasRole(session, "Analyst"));
        Assert.True(service.ValidateCsrf(session, result.CsrfToken));
        Assert.False(service.ValidateCsrf(session, "wrong-token"));
        Assert.Contains(
            audit.Entries,
            item =>
                item.Action == "authentication.login" &&
                item.Success);
    }

    [Fact]
    public void Login_RejectsInvalidTokenAndAuditsFailure()
    {
        var audit = new MemoryAuditRepository();
        var service = new LocalSessionService(
            new AccessControlOptions
            {
                AdministratorToken = "correct-token"
            },
            new ResponseOptions(),
            audit,
            NullStructuredLogService.Instance);

        Assert.Throws<UnauthorizedAccessException>(() => service.Login(
            "wrong-token",
            IPAddress.Loopback,
            new DefaultHttpContext().Response));
        Assert.Contains(
            audit.Entries,
            item =>
                item.Action == "authentication.login" &&
                !item.Success);
    }

    [Fact]
    public async Task PowerShellRunner_RejectsUnsafeParameterMetadata()
    {
        var runner = new PowerShellRunner(
            NullStructuredLogService.Instance);
        var command = new PowerShellCommand(
            "Write-Output 'safe'",
            new Dictionary<string, string>
            {
                ["BAD-NAME"] = "value"
            });

        await Assert.ThrowsAsync<ArgumentException>(() =>
            runner.RunAsync(command, TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public void InputValidator_RejectsRelativePathsAndControlCharacters()
    {
        Assert.False(InputValidator.IsAbsolutePath(@"relative\agent.exe"));
        Assert.False(InputValidator.IsRequiredText("bad\0value", 100));
        Assert.False(InputValidator.IsIdentifier("../rule"));
        Assert.True(InputValidator.IsIdentifier("RS-AGENT-NET-001"));
    }

    [Fact]
    public void StructuredLogger_CreatesAllRequiredJsonLogFiles()
    {
        Directory.CreateDirectory(_root);
        var logger = new StructuredLogService(
            new TestHostEnvironment(_root),
            new StructuredLoggingOptions
            {
                Directory = "Logs",
                RetentionDays = 7
            });
        logger.App("test.event", "Test event.", new { Value = 1 });

        foreach (var name in new[]
        {
            "app.log",
            "security.log",
            "response.log",
            "error.log"
        })
        {
            Assert.True(File.Exists(Path.Combine(_root, "Logs", name)));
        }

        Assert.Contains(
            "\"eventName\":\"test.event\"",
            File.ReadAllText(Path.Combine(_root, "Logs", "app.log")));
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }

    private sealed class MemoryAuditRepository : IAuditRepository
    {
        public List<AuditLogEntryDto> Entries { get; } = [];

        public void Write(
            string actor,
            string action,
            string entityType,
            string entityId,
            bool success,
            string detailJson) =>
            Entries.Add(new AuditLogEntryDto(
                Guid.NewGuid().ToString("N"),
                DateTimeOffset.UtcNow,
                actor,
                action,
                entityType,
                entityId,
                success,
                detailJson));

        public IReadOnlyList<AuditLogEntryDto> GetRecent(int limit) =>
            Entries.Take(limit).ToList();
    }

    private sealed class TestHostEnvironment(string contentRoot)
        : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Tests";
        public string ApplicationName { get; set; } = "RoamSentinel.Tests";
        public string ContentRootPath { get; set; } = contentRoot;
        public IFileProvider ContentRootFileProvider { get; set; } =
            new PhysicalFileProvider(contentRoot);
    }
}
