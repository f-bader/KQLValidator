using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using KqlValidator.Contracts;
using KqlValidator.Validation;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace KqlValidator.Tests;

public sealed class ApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient client;
    private readonly WebApplicationFactory<Program> factory;

    public ApiTests(WebApplicationFactory<Program> factory)
    {
        this.factory = factory;
        client = factory.CreateClient();
    }

    [Fact]
    public async Task Discovery_and_health_are_public()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/", cancellationToken)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/live", cancellationToken)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/ready", cancellationToken)).StatusCode);
    }

    [Fact]
    public async Task Discovery_documentation_links_to_the_public_repository()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        using var document = JsonDocument.Parse(await client.GetStringAsync("/", cancellationToken));

        Assert.Contains("github.com/f-bader/KQLValidator", document.RootElement.GetProperty("documentation").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Status_site_is_public_and_requests_crawler_exclusion()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var response = await client.GetAsync("/status", cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        var styles = await client.GetStringAsync("/status/site.css", cancellationToken);
        var robots = await client.GetStringAsync("/robots.txt", cancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("KQL Validator", body, StringComparison.Ordinal);
        Assert.Contains("Validate detections and transformations", body, StringComparison.Ordinal);
        Assert.Contains("Static KQL analysis for Defender XDR, Sentinel, and Azure Monitor transformations.", body, StringComparison.Ordinal);
        Assert.Contains("claude mcp add --transport http kql-validator", body, StringComparison.Ordinal);
        Assert.Contains("codex mcp add kql-validator --url", body, StringComparison.Ordinal);
        Assert.Contains("opencode mcp add kql-validator --url", body, StringComparison.Ordinal);
        Assert.Equal(3, body.Split("data-copy-target=", StringSplitOptions.None).Length - 1);
        Assert.Contains("copy-icon", body, StringComparison.Ordinal);
        Assert.DoesNotContain("<span class=\"copy-label\">Copy</span>", body, StringComparison.Ordinal);
        Assert.Contains("overflow-x: auto", styles, StringComparison.Ordinal);
        Assert.Contains("href=\"#schema-environments\"", body, StringComparison.Ordinal);
        Assert.Contains("href=\"#lint-catalog\"", body, StringComparison.Ordinal);
        Assert.Contains("kql-validator made with", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Public · no sign-in", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Manual refresh · no polling", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Content-derived versions, public sources", body, StringComparison.Ordinal);
        Assert.DoesNotContain("static analysis only · no query execution", body, StringComparison.Ordinal);
        Assert.Contains("noindex", body, StringComparison.Ordinal);
        Assert.Contains("/api/v1/environments", body, StringComparison.Ordinal);
        Assert.Equal("noindex, nofollow, noarchive", response.Headers.GetValues("X-Robots-Tag").Single());
        Assert.True(response.Headers.CacheControl?.NoStore == true);
        Assert.Contains("Disallow: /status", robots, StringComparison.Ordinal);
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
    public async Task Mounted_catalog_is_used_by_rest_and_mcp_discovery()
    {
        var path = Path.Combine(Path.GetTempPath(), $"kql-validator-catalog-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(path, """
            {"common":{"tables":[{"name":"MountedEvents","columns":[{"name":"Timestamp","type":"datetime"}]}],"functions":[{"name":"MountedName","parameters":[],"returns":{"kind":"scalar","type":"string"}}]},"environments":{}}
            """, TestContext.Current.CancellationToken);
        try
        {
            using var configured = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            {
                services.RemoveAll<SchemaCatalog>();
                services.AddSingleton(new SchemaCatalog(overlayPath: path));
            }));
            using var configuredClient = configured.CreateClient();
            var table = await configuredClient.GetAsync("/api/v1/environments/xdr/tables/MountedEvents", TestContext.Current.CancellationToken);
            var validation = await configuredClient.PostAsJsonAsync("/api/v1/validate", new ValidateRequest(
                "MountedEvents | project Timestamp", KqlEnvironment.Xdr, LintProfile.General), TestContext.Current.CancellationToken);
            using var mcpRequest = new HttpRequestMessage(HttpMethod.Post, "/mcp")
            {
                Content = JsonContent.Create(new
                {
                    jsonrpc = "2.0",
                    id = 7,
                    method = "tools/call",
                    @params = new { name = "get_kql_function", arguments = new { environment = "xdr", function = "MountedName" } },
                }),
            };
            mcpRequest.Headers.Accept.ParseAdd("application/json, text/event-stream");
            var mcp = await configuredClient.SendAsync(mcpRequest, TestContext.Current.CancellationToken);

            Assert.Equal(HttpStatusCode.OK, table.StatusCode);
            Assert.Equal(HttpStatusCode.OK, validation.StatusCode);
            Assert.Equal(HttpStatusCode.OK, mcp.StatusCode);
            Assert.Contains("MountedName", await mcp.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Sentinel_workspace_schema_remains_public()
    {
        var response = await client.GetAsync("/api/v1/environments/sentinel/schema?query=SigninLogs&kind=table", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("SigninLogs", await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Invalid_numeric_enum_and_null_nested_models_return_bad_request()
    {
        using var numeric = new StringContent(
            """{"query":"DeviceEvents","environment":99,"profile":"general"}""",
            System.Text.Encoding.UTF8,
            "application/json");
        var numericResponse = await client.PostAsync("/api/v1/validate", numeric, TestContext.Current.CancellationToken);
        using var nested = new StringContent(
            """{"query":"DeviceEvents","environment":"xdr","profile":"general","extensions":{"tables":[{"name":"Custom","columns":null}]}}""",
            System.Text.Encoding.UTF8,
            "application/json");
        var nestedResponse = await client.PostAsync("/api/v1/validate", nested, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, numericResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, nestedResponse.StatusCode);
    }

    [Fact]
    public async Task Rate_limit_uses_trusted_forwarded_client_and_exempts_health()
    {
        using var configured = factory.WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, configuration) =>
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ReverseProxy:TrustForwardedHeaders"] = "true",
                ["RateLimiting:TokenLimit"] = "2",
                ["RateLimiting:TokensPerSecond"] = "1",
                // A slow host startup must not replenish tokens mid-test.
                ["RateLimiting:ReplenishmentPeriodSeconds"] = "3600",
            })));
        using var limitedClient = configured.CreateClient();

        Assert.Equal(HttpStatusCode.OK, (await GetFromClient("203.0.113.10")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await GetFromClient("203.0.113.10")).StatusCode);
        var rejected = await GetFromClient("203.0.113.10");
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        Assert.True(rejected.Headers.Contains("Retry-After"));
        Assert.Equal(HttpStatusCode.OK, (await GetFromClient("203.0.113.11")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await limitedClient.GetAsync("/health/ready", TestContext.Current.CancellationToken)).StatusCode);

        async Task<HttpResponseMessage> GetFromClient(string address)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/environments");
            request.Headers.Add("X-Forwarded-For", address);
            return await limitedClient.SendAsync(request, TestContext.Current.CancellationToken);
        }
    }

    [Fact]
    public async Task Global_rate_limit_bounds_spoofed_partitions()
    {
        using var configured = factory.WithWebHostBuilder(builder => builder.ConfigureAppConfiguration((_, configuration) =>
            configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ReverseProxy:TrustForwardedHeaders"] = "true",
                ["RateLimiting:TokenLimit"] = "100",
                ["RateLimiting:GlobalTokenLimit"] = "2",
                ["RateLimiting:GlobalTokensPerSecond"] = "1",
                ["RateLimiting:ReplenishmentPeriodSeconds"] = "3600",
            })));
        using var limitedClient = configured.CreateClient();

        // Every request spoofs a different client address; the per-address buckets all have
        // room, so only the global bucket can stop the flood.
        Assert.Equal(HttpStatusCode.OK, (await GetFromClient("203.0.113.20")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await GetFromClient("203.0.113.21")).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await GetFromClient("203.0.113.22")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await limitedClient.GetAsync("/health/ready", TestContext.Current.CancellationToken)).StatusCode);

        async Task<HttpResponseMessage> GetFromClient(string address)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/environments");
            request.Headers.Add("X-Forwarded-For", address);
            return await limitedClient.SendAsync(request, TestContext.Current.CancellationToken);
        }
    }

    [Fact]
    public async Task Oversized_query_returns_problem_details_400()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var response = await client.PostAsJsonAsync("/api/v1/validate", new ValidateRequest(
            new string('a', 65_537), KqlEnvironment.Xdr, LintProfile.General), cancellationToken);
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("query", problem.RootElement.GetProperty("field").GetString());
    }

    [Fact]
    public async Task Schema_endpoints_return_problem_details_for_unknown_environment_and_table()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var badEnvironment = await client.GetAsync("/api/v1/environments/nope/schema?query=a", cancellationToken);
        var missingTable = await client.GetAsync("/api/v1/environments/xdr/tables/NotARealTable", cancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, badEnvironment.StatusCode);
        Assert.Equal("application/problem+json", badEnvironment.Content.Headers.ContentType?.MediaType);
        Assert.Equal(HttpStatusCode.NotFound, missingTable.StatusCode);
        Assert.Equal("application/problem+json", missingTable.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Discovery_reports_a_semantic_version()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        using var document = JsonDocument.Parse(await client.GetStringAsync("/", cancellationToken));

        Assert.Matches(@"^\d+\.\d+\.\d+", document.RootElement.GetProperty("version").GetString());
    }

    [Fact]
    public async Task Mcp_lists_every_tool_and_executes_validation()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var listBody = await SendMcp(new
        {
            jsonrpc = "2.0",
            id = 2,
            method = "tools/list",
            @params = new { },
        }, cancellationToken);
        foreach (var tool in new[] { "validate_kql", "validate_azure_monitor_transformation", "list_kql_lint_rules", "list_kql_environments", "search_kql_schema", "get_kql_table", "get_kql_function" })
            Assert.Contains(tool, listBody, StringComparison.Ordinal);

        var callBody = await SendMcp(new
        {
            jsonrpc = "2.0",
            id = 3,
            method = "tools/call",
            @params = new
            {
                name = "validate_kql",
                arguments = new
                {
                    query = "DeviceProcessEvents | where Timestamp > ago(1h) | project Timestamp, DeviceId, FileName",
                    environment = "xdr",
                    profile = "hunting",
                },
            },
        }, cancellationToken);
        Assert.Contains("\"valid\"", callBody, StringComparison.Ordinal);
        Assert.DoesNotContain("\"isError\":true", callBody.Replace(" ", string.Empty), StringComparison.Ordinal);

        var transformationBody = await SendMcp(new
        {
            jsonrpc = "2.0",
            id = 4,
            method = "tools/call",
            @params = new
            {
                name = "validate_azure_monitor_transformation",
                arguments = new
                {
                    query = "source | extend TimeGenerated = todatetime(Time) | project TimeGenerated, Message",
                    sourceColumns = new[]
                    {
                        new { name = "Time", type = "string" },
                        new { name = "Message", type = "string" },
                    },
                },
            },
        }, cancellationToken);
        Assert.Contains("\"valid\":true", transformationBody.Replace(" ", string.Empty), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Function_lookup_exposes_signature_and_input_requirements()
    {
        var token = TestContext.Current.CancellationToken;
        var function = await client.GetFromJsonAsync<SchemaFunction>(
            "/api/v1/environments/xdr/functions/FileProfile", token);

        Assert.NotNull(function);
        Assert.Equal("FileProfile", function.Name);
        Assert.Contains(function.Parameters, x => x.Name == "limit" && x.Type == "long" && x.Optional);
        Assert.Contains(function.OutputColumns!, x => x.Name == "GlobalPrevalence" && x.Type == "long");
        Assert.True(function.PreserveInput);
        Assert.True(function.RequiresTabularInput);

        var scalar = await client.GetFromJsonAsync<SchemaFunction>(
            "/api/v1/environments/sentinel/functions/_ASIM_GetUsernameType", token);
        Assert.NotNull(scalar);
        Assert.Equal("string", scalar.ScalarReturnType);
        Assert.Contains(scalar.Parameters, x => x.Name == "username" && !x.Optional);

        Assert.Equal(HttpStatusCode.NotFound,
            (await client.GetAsync("/api/v1/environments/xdr/functions/MissingFunction", token)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest,
            (await client.GetAsync("/api/v1/environments/missing/functions/FileProfile", token)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound,
            (await client.GetAsync("/api/v1/environments/xdr/functions/_ASIM_GetUsernameType", token)).StatusCode);
    }

    [Fact]
    public async Task Mcp_function_lookup_matches_rest_signature()
    {
        var body = await SendMcp(new
        {
            jsonrpc = "2.0",
            id = 5,
            method = "tools/call",
            @params = new
            {
                name = "get_kql_function",
                arguments = new { environment = "xdr", function = "FileProfile" },
            },
        }, TestContext.Current.CancellationToken);

        Assert.Contains("GlobalPrevalence", body, StringComparison.Ordinal);
        Assert.Contains("fileColumn", body, StringComparison.Ordinal);
        Assert.DoesNotContain("\"isError\":true", body.Replace(" ", string.Empty), StringComparison.Ordinal);
    }

    private async Task<string> SendMcp(object payload, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp") { Content = JsonContent.Create(payload) };
        request.Headers.Accept.ParseAdd("application/json, text/event-stream");
        var response = await client.SendAsync(request, cancellationToken);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return body;
    }

    [Fact]
    public async Task Lint_rule_catalog_is_public_and_filterable()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var response = await client.GetAsync("/api/v1/lint-rules?ruleSet=community-detection", cancellationToken);
        var result = await response.Content.ReadFromJsonAsync<LintRuleListResponse>(cancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(result);
        Assert.NotEmpty(result.Items);
        Assert.All(result.Items, rule => Assert.Equal("community-detection", rule.RuleSet));
        Assert.All(result.Items, rule => Assert.False(rule.DefaultEnabled));
    }

    [Fact]
    public async Task Unknown_lint_rule_returns_bad_request()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var response = await client.PostAsJsonAsync("/api/v1/validate", new ValidateRequest(
            "DeviceEvents | take 1",
            KqlEnvironment.Xdr,
            LintProfile.General,
            Lint: new LintOptions(EnableRules: ["NOT-A-RULE"])), cancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
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
        Assert.True(document.RootElement.GetProperty("paths").TryGetProperty("/api/v1/validate-transformation", out _));
        Assert.True(document.RootElement.GetProperty("paths").TryGetProperty("/api/v1/lint-rules", out _));
    }

    [Fact]
    public async Task Transformation_endpoint_returns_static_analysis_and_problem_details()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var response = await client.PostAsJsonAsync("/api/v1/validate-transformation", new TransformationValidationRequest(
            "source | extend TimeGenerated = todatetime(Time) | project TimeGenerated, Message",
            [new("Time", "string"), new("Message", "string")]), cancellationToken);
        var result = await response.Content.ReadFromJsonAsync<TransformationValidationResponse>(cancellationToken);
        var malformed = await client.PostAsJsonAsync("/api/v1/validate-transformation", new TransformationValidationRequest(
            "source", []), cancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(result);
        Assert.True(result.Valid);
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
        Assert.Equal("application/problem+json", malformed.Content.Headers.ContentType?.MediaType);
    }
}
