using RoamSentinel.Config;
using RoamSentinel.Core;
using RoamSentinel.ThreatIntel;

namespace RoamSentinel.Tests;

public sealed class ThreatIntelServiceTests
{
    [Fact]
    public async Task EnrichAsync_NormalizesAndReusesProviderCache()
    {
        var provider = new FakeProvider();
        var repository = new InMemoryIndicatorRepository();
        var service = new ThreatIntelService(
            [provider],
            repository,
            new ThreatIntelOptions());

        var first = await service.EnrichDomainAsync("Example.COM.");
        var second = await service.EnrichDomainAsync("example.com");

        Assert.Equal("example.com", first.Indicator);
        Assert.Equal("Malicious", first.Reputation);
        Assert.False(first.FromCache);
        Assert.True(second.FromCache);
        Assert.Equal(1, provider.CallCount);
    }

    [Theory]
    [InlineData("not an ip", "ip")]
    [InlineData("bad domain", "domain")]
    [InlineData("xyz", "file-hash")]
    [InlineData("value", "unknown")]
    public async Task EnrichAsync_RejectsMalformedIndicators(
        string indicator,
        string type)
    {
        var service = new ThreatIntelService(
            [],
            new InMemoryIndicatorRepository(),
            new ThreatIntelOptions());

        await Assert.ThrowsAsync<ArgumentException>(
            () => service.EnrichAsync(indicator, type));
    }

    [Fact]
    public async Task EnrichAsync_ContinuesWhenOneProviderFails()
    {
        var service = new ThreatIntelService(
            [new FailingProvider(), new FakeProvider()],
            new InMemoryIndicatorRepository(),
            new ThreatIntelOptions());

        var result = await service.EnrichIpAsync("203.0.113.25");

        Assert.True(result.HasIntelligence);
        Assert.Equal("Malicious", result.Reputation);
        Assert.Contains(
            result.Observations,
            item =>
                item.Provider == "Failing" &&
                !item.HasIntelligence &&
                item.Summary == "Provider query failed.");
        Assert.Contains(
            result.Observations,
            item => item.Provider == "Fake" && item.HasIntelligence);
    }

    private sealed class FakeProvider : IThreatIntelProvider
    {
        public int CallCount { get; private set; }
        public string Name => "Fake";
        public bool Enabled => true;
        public bool IsConfigured => true;
        public IReadOnlySet<string> SupportedIndicatorTypes =>
            ThreatIntelTypes.All;

        public Task<ThreatIntelObservationDto> EnrichAsync(
            string indicator,
            string indicatorType,
            CancellationToken cancellationToken = default)
        {
            CallCount++;
            return Task.FromResult(new ThreatIntelObservationDto(
                Name,
                true,
                90,
                "Malicious",
                "Test provider match",
                "https://example.test",
                DateTimeOffset.UtcNow,
                DateTimeOffset.UtcNow.AddHours(1)));
        }
    }

    private sealed class FailingProvider : IThreatIntelProvider
    {
        public string Name => "Failing";
        public bool Enabled => true;
        public bool IsConfigured => true;
        public IReadOnlySet<string> SupportedIndicatorTypes =>
            ThreatIntelTypes.All;

        public Task<ThreatIntelObservationDto> EnrichAsync(
            string indicator,
            string indicatorType,
            CancellationToken cancellationToken = default) =>
            throw new HttpRequestException("Provider unavailable.");
    }

    private sealed class InMemoryIndicatorRepository
        : IThreatIndicatorRepository
    {
        private readonly Dictionary<string, ThreatIndicatorDto> _items =
            new(StringComparer.OrdinalIgnoreCase);

        public IReadOnlySet<string> GetActiveSuspiciousIps(
            DateTimeOffset asOf) =>
            _items.Values
                .Where(item =>
                    item.IndicatorType == "ip" &&
                    item.Reputation is "Suspicious" or "Malicious")
                .Select(item => item.Indicator)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

        public IReadOnlyList<ThreatIndicatorDto> GetAll(int limit) =>
            _items.Values.Take(limit).ToList();

        public ThreatIndicatorDto? FindActive(
            string indicator,
            string indicatorType,
            string source,
            DateTimeOffset asOf) =>
            _items.GetValueOrDefault(Key(
                indicator,
                indicatorType,
                source)) is { } item &&
            (item.ExpiresAt is null || item.ExpiresAt > asOf)
                ? item
                : null;

        public ThreatIndicatorDto Upsert(
            ThreatIndicatorDto indicator,
            string actor)
        {
            _items[Key(
                indicator.Indicator,
                indicator.IndicatorType,
                indicator.Source)] = indicator;
            return indicator;
        }

        public bool RemoveLocal(string indicator, string indicatorType) =>
            _items.Remove(Key(indicator, indicatorType, "Local"));

        private static string Key(
            string indicator,
            string type,
            string source) =>
            $"{type}|{indicator}|{source}";
    }
}
