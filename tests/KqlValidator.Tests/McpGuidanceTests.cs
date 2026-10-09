using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using KqlValidator.Contracts;
using Microsoft.AspNetCore.Mvc.Testing;

namespace KqlValidator.Tests;

public sealed class McpGuidanceTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient client = factory.CreateClient();
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task Initialization_exposes_authoring_workflow_and_static_analysis_limits()
    {
        var result = await Request("initialize", new
        {
            protocolVersion = "2025-06-18",
            capabilities = new { },
            clientInfo = new { name = "guidance-tests", version = "1.0" },
        });

        Assert.Equal("kql-validator", result.GetProperty("serverInfo").GetProperty("name").GetString());
        var instructions = result.GetProperty("instructions").GetString();
        foreach (var cue in new[] { "writing", "revalidate", "static", "never executed", "validate_kql",
            "validate_azure_monitor_transformation", "NRT", "source", "valid=false", "custom" })
            Assert.Contains(cue, instructions, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Discovery_exposes_complete_inputs_and_distinct_tool_selection_cues()
    {
        var result = await Request("tools/list", new { });
        var tools = result.GetProperty("tools").EnumerateArray()
            .ToDictionary(tool => tool.GetProperty("name").GetString()!);
        var expected = new Dictionary<string, (string[] Required, string[] Cues)>
        {
            ["validate_kql"] = (["query", "environment", "profile"], ["hunting", "detection", "validate_azure_monitor_transformation", "valid=false", "output columns"]),
            ["validate_azure_monitor_transformation"] = (["query", "sourceColumns"], ["transformKql", "transform.KQL", "not a full DCR", "source", "destination", "validate_kql", "valid=false"]),
            ["list_kql_environments"] = ([], ["versions", "counts", "effective catalog", "search_kql_schema"]),
            ["search_kql_schema"] = (["environment"], ["unknown", "nextCursor", "get_kql_table", "get_kql_function"]),
            ["get_kql_table"] = (["environment", "table"], ["known", "columns", "types", "null", "search_kql_schema"]),
            ["get_kql_column_relations"] = (["environment", "table"], ["join keys", "families", "empty", "community-correlations", "effective schema"]),
            ["get_kql_function"] = (["environment", "function"], ["known", "parameters", "return schema", "tabular input", "null", "search_kql_schema"]),
            ["list_kql_lint_rules"] = ([], ["IDs", "applicability", "severities", "source", "does not validate"]),
        };

        Assert.Equal(expected.Keys.Order(), tools.Keys.Order());
        foreach (var (name, (required, cues)) in expected)
        {
            var tool = tools[name];
            foreach (var cue in cues)
                Assert.Contains(cue, tool.GetProperty("description").GetString(), StringComparison.OrdinalIgnoreCase);
            var schema = tool.GetProperty("inputSchema");
            var actualRequired = schema.TryGetProperty("required", out var values)
                ? values.EnumerateArray().Select(value => value.GetString()).ToArray() : [];
            Assert.Equal(required.Order(), actualRequired.Order());
            foreach (var property in schema.GetProperty("properties").EnumerateObject())
            {
                Assert.DoesNotContain(property.Name, new[] { "services", "executor", "schemas", "rules", "cancellationToken" });
                Assert.False(string.IsNullOrWhiteSpace(property.Value.GetProperty("description").GetString()), $"{name}.{property.Name} needs guidance.");
            }
            var annotations = tool.GetProperty("annotations");
            Assert.True(annotations.GetProperty("readOnlyHint").GetBoolean());
            Assert.True(annotations.GetProperty("idempotentHint").GetBoolean());
            Assert.False(annotations.GetProperty("destructiveHint").GetBoolean());
            Assert.False(annotations.GetProperty("openWorldHint").GetBoolean());
        }

        var validation = tools["validate_kql"].GetProperty("inputSchema").GetProperty("properties");
        var targetDescription = validation.GetProperty("target").GetProperty("description").GetString();
        foreach (var target in Enum.GetValues<KqlTarget>())
            Assert.Contains(JsonSerializer.Serialize(target).Trim('"'), targetDescription, StringComparison.Ordinal);
        foreach (var cue in new[] { "requires hunting", "require detection with sentinel", "require detection with xdr or unified", "If omitted", "explicit" })
            Assert.Contains(cue, targetDescription, StringComparison.Ordinal);
        var filters = tools["list_kql_lint_rules"].GetProperty("inputSchema").GetProperty("properties");
        Assert.Contains("transformation", filters.GetProperty("profile").GetProperty("description").GetString());
        Assert.Contains("azure-monitor-transformation", filters.GetProperty("target").GetProperty("description").GetString());
        Assert.Contains("azure-monitor", filters.GetProperty("environment").GetProperty("description").GetString());
    }

    [Theory]
    [InlineData("xdr", "hunting", null, "DeviceProcessEvents | project Timestamp, DeviceId, FileName")]
    [InlineData("xdr", "detection", "defender-scheduled", "DeviceProcessEvents | project Timestamp, DeviceId, ReportId")]
    [InlineData("unified", "detection", "defender-nrt", "DeviceProcessEvents | project Timestamp, DeviceId, ReportId")]
    [InlineData("sentinel", "detection", "sentinel-scheduled", "SigninLogs | project TimeGenerated, UserPrincipalName")]
    [InlineData("sentinel", "detection", "sentinel-nrt", "SigninLogs | project TimeGenerated, UserPrincipalName")]
    public async Task Documented_query_routes_accept_platform_profile_and_target(string environment, string profile, string? target, string query)
    {
        var result = await Call("validate_kql", new { query, environment, profile, target });
        var validation = result.Deserialize<ValidationResponse>(JsonOptions)!;
        Assert.True(validation.Valid, result.ToString());
        Assert.NotEmpty(validation.OutputColumns);
    }

    [Fact]
    public async Task Semantic_failure_is_a_successful_tool_call_with_invalid_result()
    {
        var result = await Call("validate_kql", new { query = "DeviceEvents | project MissingColumn", environment = "xdr", profile = "general" });
        var validation = result.Deserialize<ValidationResponse>(JsonOptions)!;
        Assert.False(validation.Valid);
        Assert.Contains(validation.Diagnostics, diagnostic => diagnostic.Severity == DiagnosticSeverity.Error);
    }

    [Fact]
    public async Task Transformation_checks_destination_and_explains_invalid_results()
    {
        var sourceColumns = new[] { new { name = "Time", type = "string" }, new { name = "Message", type = "string" } };
        foreach (var destinationType in new[] { "datetime", "string" })
        {
            var result = await Call("validate_azure_monitor_transformation", new
            {
                query = "source | extend TimeGenerated = todatetime(Time) | project TimeGenerated, Message",
                sourceColumns,
                destinationColumns = new[] { new { name = "TimeGenerated", type = destinationType }, new { name = "Message", type = "string" } },
            });
            var validation = result.Deserialize<TransformationValidationResponse>(JsonOptions)!;
            Assert.Equal(destinationType == "datetime", validation.Valid);
            Assert.Contains(validation.OutputColumns, column => column.Name == "TimeGenerated" && column.Type == "datetime");
            if (!validation.Valid)
                Assert.Contains(validation.Diagnostics, diagnostic => diagnostic.RuleId == "KQLT007");
        }
    }

    [Fact]
    public async Task Schema_discovery_supports_search_pagination_and_known_name_lookup()
    {
        var environments = await Call("list_kql_environments", new { });
        Assert.Contains("xdr", environments.ToString(), StringComparison.OrdinalIgnoreCase);
        var first = await Call("search_kql_schema", new { environment = "xdr", query = "Device", kind = "table", limit = 1 });
        var search = first.Deserialize<SchemaSearchResponse>(JsonOptions)!;
        var table = Assert.Single(search.Items);
        Assert.NotNull(search.NextCursor);
        var second = await Call("search_kql_schema", new { environment = "xdr", query = "Device", kind = "table", limit = 1, cursor = search.NextCursor });
        Assert.NotEqual(table.Name, Assert.Single(second.Deserialize<SchemaSearchResponse>(JsonOptions)!.Items).Name);
        var definition = await Call("get_kql_table", new { environment = "xdr", table = table.Name });
        Assert.Equal(table.Name, definition.GetProperty("name").GetString());
        Assert.NotEmpty(definition.GetProperty("columns").EnumerateArray());

        var functions = await Call("search_kql_schema", new { environment = "xdr", query = "FileProfile", kind = "function" });
        var function = Assert.Single(functions.Deserialize<SchemaSearchResponse>(JsonOptions)!.Items);
        var signature = await Call("get_kql_function", new { environment = "xdr", function = function.Name });
        Assert.Equal("FileProfile", signature.GetProperty("name").GetString());
        Assert.True(signature.GetProperty("requiresTabularInput").GetBoolean());
        Assert.NotEmpty(signature.GetProperty("parameters").EnumerateArray());
    }

    [Fact]
    public async Task Relation_discovery_returns_guidance_without_executing_queries()
    {
        var result = await Call("get_kql_column_relations", new { environment = "xdr", table = "EntraIdSignInEvents", column = "UniqueTokenId" });
        var relations = result.Deserialize<KqlValidator.Validation.ColumnRelationResponse>(JsonOptions)!;
        Assert.NotEmpty(relations.Items);
        Assert.Equal(1, relations.Version);
        Assert.Equal(64, relations.Sha256.Length);
        Assert.All(relations.Items, relation => Assert.Equal("entra-token", relation.Family));
        Assert.Contains(relations.Items, relation => relation.To.Path == "AppAccessContext.UniqueTokenId");
        var missing = await Call("get_kql_column_relations", new { environment = "xdr", table = "MissingCatalogTable" });
        Assert.Empty(missing.GetProperty("items").EnumerateArray());
    }

    [Theory]
    [InlineData("get_kql_table", "table")]
    [InlineData("get_kql_function", "function")]
    public async Task Missing_catalog_identifier_returns_empty_mcp_content(string tool, string parameter)
    {
        var result = await Request("tools/call", new
        {
            name = tool,
            arguments = new Dictionary<string, string> { ["environment"] = "xdr", [parameter] = "MissingCatalogIdentifier" },
        });
        Assert.False(result.TryGetProperty("isError", out var error) && error.GetBoolean());
        Assert.Empty(result.GetProperty("content").EnumerateArray());
        Assert.False(result.TryGetProperty("structuredContent", out var content) && content.ValueKind != JsonValueKind.Null);
    }

    [Fact]
    public async Task Lint_rule_discovery_without_inputs_returns_the_full_catalog()
    {
        var result = await Call("list_kql_lint_rules", new { });
        var rules = result.Deserialize<LintRuleListResponse>(JsonOptions)!.Items;
        var expected = new KqlValidator.Validation.LintRuleCatalog().List();

        Assert.Equal(expected.Select(rule => rule.RuleId), rules.Select(rule => rule.RuleId));
    }

    [Fact]
    public async Task Transformation_lint_filters_return_applicable_rules()
    {
        var result = await Call("list_kql_lint_rules", new
        {
            ruleSet = "azure-monitor-transformation",
            category = "transformation",
            profile = "transformation",
            target = "azure-monitor-transformation",
            environment = "azure-monitor",
        });
        var rules = result.Deserialize<LintRuleListResponse>(JsonOptions)!.Items;
        Assert.NotEmpty(rules);
        Assert.All(rules, rule =>
        {
            Assert.Equal("azure-monitor-transformation", rule.RuleSet);
            Assert.Contains("transformation", rule.Profiles);
            Assert.False(string.IsNullOrWhiteSpace(rule.DocumentationUrl));
        });
    }

    private async Task<JsonElement> Call(string name, object arguments)
    {
        var result = await Request("tools/call", new { name, arguments });
        Assert.False(result.TryGetProperty("isError", out var error) && error.GetBoolean(), result.ToString());
        if (result.TryGetProperty("structuredContent", out var structured))
            return structured;
        var text = Assert.Single(result.GetProperty("content").EnumerateArray()).GetProperty("text").GetString()!;
        using var document = JsonDocument.Parse(text);
        return document.RootElement.Clone();
    }

    private async Task<JsonElement> Request(string method, object parameters)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = JsonContent.Create(new { jsonrpc = "2.0", id = 1, method, @params = parameters }),
        };
        request.Headers.Accept.ParseAdd("application/json, text/event-stream");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var json = response.Content.Headers.ContentType?.MediaType == "text/event-stream"
            ? string.Join('\n', body.Split('\n').Where(line => line.StartsWith("data: ", StringComparison.Ordinal)).Select(line => line[6..]))
            : body;
        using var document = JsonDocument.Parse(json);
        Assert.False(document.RootElement.TryGetProperty("error", out _), json);
        return document.RootElement.GetProperty("result").Clone();
    }
}
