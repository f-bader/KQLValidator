using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using KqlValidator.Contracts;
using Microsoft.AspNetCore.Mvc.Testing;

namespace KqlValidator.Tests;

public sealed class ApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient client;

    public ApiTests(WebApplicationFactory<Program> factory) => client = factory.CreateClient();

    [Fact]
    public async Task Discovery_and_health_are_public()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/", cancellationToken)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/live", cancellationToken)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/ready", cancellationToken)).StatusCode);
    }

    [Fact]
    public async Task Validate_endpoint_returns_invalid_kql_as_200()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var response = await client.PostAsJsonAsync("/api/v1/validate", new ValidateRequest(
            "DeviceEvents | project MissingColumn", KqlEnvironment.Xdr, LintProfile.General), cancellationToken);
        var result = await response.Content.ReadFromJsonAsync<ValidationResponse>(cancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(result);
        Assert.False(result.Valid);
    }

    [Fact]
    public async Task Schema_endpoints_support_search_and_lookup()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var searchResponse = await client.GetAsync("/api/v1/environments/xdr/schema?query=BehaviorInfo&kind=table", cancellationToken);
        var searchBody = await searchResponse.Content.ReadAsStringAsync(cancellationToken);
        Assert.True(searchResponse.IsSuccessStatusCode, searchBody);
        var search = await searchResponse.Content.ReadFromJsonAsync<SchemaSearchResponse>(cancellationToken);
        var table = await client.GetAsync("/api/v1/environments/xdr/tables/BehaviorInfo", cancellationToken);

        Assert.NotNull(search);
        Assert.Contains(search.Items, x => x.Name == "BehaviorInfo");
        Assert.Equal(HttpStatusCode.OK, table.StatusCode);
    }

    [Fact]
    public async Task Mcp_endpoint_accepts_stateless_initialize()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = JsonContent.Create(new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "initialize",
                @params = new
                {
                    protocolVersion = "2025-06-18",
                    capabilities = new { },
                    clientInfo = new { name = "test", version = "1.0" }
                }
            })
        };
        request.Headers.Accept.ParseAdd("application/json, text/event-stream");
        var response = await client.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("kql-validator", body, StringComparison.Ordinal);
        Assert.Contains("protocolVersion", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Mcp-Session-Id", response.Headers.Select(x => x.Key), StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Open_api_document_is_exposed()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var response = await client.GetAsync("/openapi/v1.json", cancellationToken);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStreamAsync(cancellationToken));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(document.RootElement.GetProperty("paths").TryGetProperty("/api/v1/validate", out _));
    }
}
