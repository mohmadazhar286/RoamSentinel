using System.Net;
using System.Net.Http.Headers;
using System.Text;
using RoamSentinel.Config;
using RoamSentinel.ThreatIntel;

namespace RoamSentinel.Tests;

public sealed class ThreatIntelProviderTests
{
    [Fact]
    public async Task VirusTotal_UsesV3ResourceAndParsesAnalysisStats()
    {
        var handler = Handler("""
            {"data":{"attributes":{"last_analysis_stats":{
              "malicious":4,"suspicious":1,"harmless":5,"undetected":10
            }}}}
            """);
        var provider = new VirusTotalProvider(
            new FakeClientFactory(handler),
            new ThreatIntelOptions
            {
                VirusTotal = new ThreatIntelProviderOptions
                {
                    Enabled = true,
                    ApiKey = "test-key",
                    BaseUrl = "https://vt.test"
                }
            });

        var result = await provider.EnrichAsync(
            "203.0.113.5",
            ThreatIntelTypes.Ip);

        Assert.Equal("Malicious", result.Reputation);
        Assert.Equal("/api/v3/ip_addresses/203.0.113.5",
            handler.RequestUri?.AbsolutePath);
        Assert.Equal("test-key", handler.Header("x-apikey"));
    }

    [Fact]
    public async Task AbuseIpDb_UsesV2CheckAndParsesConfidence()
    {
        var handler = Handler("""
            {"data":{"abuseConfidenceScore":82,"totalReports":14}}
            """);
        var provider = new AbuseIpDbProvider(
            new FakeClientFactory(handler),
            new ThreatIntelOptions
            {
                AbuseIpDb = new ThreatIntelProviderOptions
                {
                    Enabled = true,
                    ApiKey = "test-key",
                    BaseUrl = "https://abuse.test"
                }
            });

        var result = await provider.EnrichAsync(
            "203.0.113.6",
            ThreatIntelTypes.Ip);

        Assert.Equal("Malicious", result.Reputation);
        Assert.Equal(82, result.Confidence);
        Assert.Equal("/api/v2/check", handler.RequestUri?.AbsolutePath);
        Assert.Equal("test-key", handler.Header("Key"));
    }

    [Fact]
    public async Task AlienVaultOtx_UsesIndicatorEndpointAndPulseCount()
    {
        var handler = Handler("""{"pulse_info":{"count":3}}""");
        var provider = new AlienVaultOtxProvider(
            new FakeClientFactory(handler),
            new ThreatIntelOptions
            {
                AlienVaultOtx = new ThreatIntelProviderOptions
                {
                    Enabled = true,
                    ApiKey = "test-key",
                    BaseUrl = "https://otx.test"
                }
            });

        var result = await provider.EnrichAsync(
            "example.com",
            ThreatIntelTypes.Domain);

        Assert.Equal("Suspicious", result.Reputation);
        Assert.Equal(
            "/api/v1/indicators/domain/example.com/general",
            handler.RequestUri?.AbsolutePath);
        Assert.Equal("test-key", handler.Header("X-OTX-API-KEY"));
    }

    [Fact]
    public async Task Misp_UsesRestSearchAndParsesIdsAttributes()
    {
        var handler = Handler("""
            {"response":{"Attribute":[
              {"value":"example.com","to_ids":true}
            ]}}
            """);
        var provider = new MispProvider(
            new FakeClientFactory(handler),
            new ThreatIntelOptions
            {
                Misp = new MispProviderOptions
                {
                    Enabled = true,
                    ApiKey = "test-key",
                    BaseUrl = "https://misp.test"
                }
            });

        var result = await provider.EnrichAsync(
            "example.com",
            ThreatIntelTypes.Domain);

        Assert.Equal("Malicious", result.Reputation);
        Assert.Equal("/attributes/restSearch",
            handler.RequestUri?.AbsolutePath);
        Assert.Equal("test-key", handler.Header("Authorization"));
        Assert.Contains("example.com", handler.RequestBody);
    }

    private static RecordingHandler Handler(string json) =>
        new(json);

    private sealed class FakeClientFactory(
        HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(handler, disposeHandler: false);
    }

    private sealed class RecordingHandler(string responseJson)
        : HttpMessageHandler
    {
        private HttpRequestHeaders? _headers;
        public Uri? RequestUri { get; private set; }
        public string RequestBody { get; private set; } = "";

        public string? Header(string name) =>
            _headers?.TryGetValues(name, out var values) == true
                ? values.Single()
                : null;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestUri = request.RequestUri;
            _headers = request.Headers;
            RequestBody = request.Content is null
                ? ""
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    responseJson,
                    Encoding.UTF8,
                    "application/json")
            };
        }
    }
}
