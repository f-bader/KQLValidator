using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using KqlValidator.Contracts;
using KqlValidator.SchemaSync;
using KqlValidator.Validation;
using Microsoft.AspNetCore.Mvc.Testing;

namespace KqlValidator.Tests;

public sealed class StructuredColumnTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly SchemaCatalog catalog = new();
    private static string SnapshotPath => Path.Combine(AppContext.BaseDirectory, "Schemas", "structured-columns.json");

    [Fact]
    public void Discovery_filters_effective_schema_and_paginates_columns()
    {
        var service = new SchemaQueryService(catalog);
        var first = service.ListStructures(KqlEnvironment.Unified, null, null, 1, null);
        Assert.Single(first.Items);
        Assert.NotNull(first.NextCursor);
        var second = service.ListStructures(KqlEnvironment.Unified, null, null, 1, first.NextCursor);
        Assert.NotEqual(first.Items[0], second.Items[0]);
        Assert.Equal(first.TotalCount, second.TotalCount);
        Assert.All(service.ListStructures(KqlEnvironment.Xdr, null, null, 100, null).Items,
            c => Assert.NotNull(service.GetTable(KqlEnvironment.Xdr, c.Table)));
        Assert.False(first.Coverage.Exhaustive);
        Assert.Contains("not an exhaustive vendor contract", first.Caveat);
    }

    [Fact]
    public void Variants_preserve_context_and_status_covers_all_pages()
    {
        var schema = catalog.Get(KqlEnvironment.Unified);
        var first = catalog.Structures.Get(schema, "AuditLogs", "AdditionalDetails", null, false, 1, null);
        var next = catalog.Structures.Get(schema, "AuditLogs", "AdditionalDetails", null, false, 1, first.NextCursor);
        Assert.NotNull(first.NextCursor);
        Assert.Equal(first.Status, next.Status);
        Assert.Equal(first.TotalCount, next.TotalCount);
        var all = catalog.Structures.Get(schema, "AuditLogs", "AdditionalDetails", null, false, 100, null);
        Assert.Contains(catalog.Structures.Get(schema, "DeviceEvents", "AdditionalFields", null, false, 100, null).Items,
            v => v.Status == "known-combination-without-shape");
        Assert.All(all.Items.SelectMany(v => v.Shapes), e => Assert.Null(e.Example));
        var filtered = catalog.Structures.Get(schema, "auditlogs", "additionaldetails",
            new Dictionary<string, string> { ["OperationName"] = "Add service principal" }, true, 100, null);
        Assert.NotEmpty(filtered.Items);
        Assert.All(filtered.Items, v => Assert.Equal("Add service principal", v.Discriminators["OperationName"]));
        Assert.Contains(filtered.Items.SelectMany(v => v.Shapes), e => e.Example is not null);
        Assert.Empty(catalog.Structures.Get(schema, "AuditLogs", "AdditionalDetails",
            new Dictionary<string, string> { ["OperationName"] = "add service principal" }, false, 10, null).Items);
        Assert.Empty(catalog.Structures.Get(schema, "AuditLogs", "AdditionalDetails",
            new Dictionary<string, string> { ["AbsentKey"] = "value" }, false, 10, null).Items);
    }

    [Fact]
    public void Empty_results_distinguish_missing_target_from_missing_evidence()
    {
        var schema = catalog.Get(KqlEnvironment.Xdr);
        var unavailable = catalog.Structures.Get(schema, "UnknownTable", "UnknownColumn", null, false, 10, null);
        var noEvidence = catalog.Structures.Get(schema, "DeviceEvents", "DeviceId", null, false, 10, null);
        Assert.Equal("target-unavailable", unavailable.Status);
        Assert.Equal("no-catalog-match", noEvidence.Status);
        foreach (var result in new[] { unavailable, noEvidence })
        {
            Assert.Empty(result.Items);
            Assert.False(result.Coverage.Exhaustive);
            Assert.False(result.Coverage.FieldPresenceGuaranteed);
            Assert.Contains("Missing fields or variants", result.Caveat);
        }
    }

    [Fact]
    public void Normalization_is_deterministic_and_preserves_encodings_types_and_values()
    {
        var raw = File.ReadAllText(SnapshotPath);
        var normalized = StructuredColumnNormalizer.Normalize(raw);
        Assert.Equal(normalized.ToJsonString(), StructuredColumnNormalizer.Normalize(normalized.ToJsonString()).ToJsonString());
        var entries = normalized["entries"]!.AsArray();
        Assert.Contains(entries, e => e!["encoding"]!.GetValue<string>() == "xml-string");
        Assert.Contains(entries, e => e!["encoding"]!.GetValue<string>() == "native-json");
        Assert.Contains(entries, e => e!["origin"]!.GetValue<string>() == "illustrative");
        Assert.Contains(entries, e => e!["fields"]!.AsArray().GroupBy(f => f!["path"]!.GetValue<string>()).Any(g => g.Count() > 1));
        var entry = entries[0]!;
        entry["discriminators"]!["OperationName"] = "Exact value  ";
        // This breaks associations and must be rejected, rather than silently trimmed or repaired.
        Assert.Throws<InvalidDataException>(() => StructuredColumnNormalizer.Normalize(normalized.ToJsonString()));
        var invalid = StructuredColumnNormalizer.Normalize(raw);
        invalid["combinations"]![0]!["observedShapes"] = new System.Text.Json.Nodes.JsonArray("missing");
        Assert.Throws<InvalidDataException>(() => StructuredColumnNormalizer.Normalize(invalid.ToJsonString()));
        var orphaned = StructuredColumnNormalizer.Normalize(raw);
        orphaned["combinations"] = new System.Text.Json.Nodes.JsonArray();
        Assert.Throws<InvalidDataException>(() => StructuredColumnNormalizer.Normalize(orphaned.ToJsonString()));
    }

    [Fact]
    public void Snapshot_digest_matches_manifest_and_exact_values_survive_normalization()
    {
        var normalized = StructuredColumnNormalizer.Normalize(File.ReadAllText(SnapshotPath));
        var digest = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(normalized.ToJsonString()))).ToLowerInvariant();
        using var manifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Schemas", "manifest.json")));
        var source = manifest.RootElement.GetProperty("sources").EnumerateArray()
            .Single(s => s.GetProperty("url").GetString() == StructuredColumnNormalizer.SourceUrl);
        Assert.Equal(digest, source.GetProperty("sha256").GetString());
        Assert.Equal(digest, catalog.Structures.List(catalog.Get(KqlEnvironment.Unified), null, null, 10, null).Sha256);
        var result = catalog.Structures.Get(catalog.Get(KqlEnvironment.Unified), "AuditLogs", "AdditionalDetails",
            new Dictionary<string, string> { ["OperationName"] = "Create application – Certificates and secrets management " }, false, 10, null);
        Assert.NotEmpty(result.Items);
        Assert.Empty(catalog.Structures.Get(catalog.Get(KqlEnvironment.Unified), "AuditLogs", "AdditionalDetails",
            new Dictionary<string, string> { ["OperationName"] = "Create application – Certificates and secrets management" }, false, 10, null).Items);
    }

    [Fact]
    public void Xml_and_illustrative_shapes_remain_explicit_and_missing_optional_snapshot_is_supported()
    {
        var xml = catalog.Structures.Get(catalog.Get(KqlEnvironment.Unified), "WindowsEvent", "RawEventData", null, true, 100, null);
        Assert.Contains(xml.Items.SelectMany(v => v.Shapes), e => e.Format == "xml" && e.Encoding == "xml-string" && e.Origin == "illustrative");
        Assert.Contains("XML", xml.Guidance);
        Assert.Contains("parse_json(tostring(value))", xml.Guidance);
        var missing = new StructuredColumnCatalog(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".json"), required: false);
        var result = missing.List(catalog.Get(KqlEnvironment.Unified), null, null, 10, null);
        Assert.Empty(result.Items);
        Assert.False(result.Coverage.Exhaustive);
    }

    [Fact]
    public async Task Rest_and_mcp_return_the_same_guidance_and_bad_filters_are_400()
    {
        using var client = factory.CreateClient();
        const string route = "/api/v1/environments/unified/tables/AuditLogs/columns/AdditionalDetails/structures";
        var rest = await client.GetFromJsonAsync<StructuredDetailResponse>(route, TestContext.Current.CancellationToken);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = JsonContent.Create(new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "tools/call",
                @params = new
                { name = "get_kql_structured_column", arguments = new { environment = "unified", table = "AuditLogs", column = "AdditionalDetails" } }
            })
        };
        request.Headers.Accept.ParseAdd("application/json, text/event-stream");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        if (response.Content.Headers.ContentType?.MediaType == "text/event-stream")
            body = string.Join('\n', body.Split('\n').Where(l => l.StartsWith("data: ")).Select(l => l[6..]));
        using var document = JsonDocument.Parse(body);
        var result = document.RootElement.GetProperty("result");
        Assert.False(result.TryGetProperty("isError", out var error) && error.GetBoolean());
        var mcp = result.GetProperty("structuredContent").Deserialize<StructuredDetailResponse>(new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.Equal(JsonSerializer.Serialize(rest), JsonSerializer.Serialize(mcp));
        Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync(route + "?discriminators=invalid", TestContext.Current.CancellationToken)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync(route + "?discriminators=" +
            Uri.EscapeDataString("{\"OperationName\":null}"), TestContext.Current.CancellationToken)).StatusCode);
        Assert.Throws<ArgumentException>(() => catalog.Structures.Get(catalog.Get(KqlEnvironment.Unified),
            "AuditLogs", "AdditionalDetails", new Dictionary<string, string> { ["OperationName"] = null! }, false, 10, null));
        var filtered = await client.GetFromJsonAsync<StructuredDetailResponse>(route + "?discriminators=" + Uri.EscapeDataString("{\"OperationName\":\"Add service principal\"}"), TestContext.Current.CancellationToken);
        Assert.NotEmpty(filtered!.Items);
    }

    [Fact]
    public async Task Mcp_rejects_null_discriminator_values()
    {
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = JsonContent.Create(new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "tools/call",
                @params = new
                {
                    name = "get_kql_structured_column",
                    arguments = new
                    {
                        environment = "unified",
                        table = "AuditLogs",
                        column = "AdditionalDetails",
                        discriminators = new Dictionary<string, string?> { ["OperationName"] = null }
                    }
                }
            })
        };
        request.Headers.Accept.ParseAdd("application/json, text/event-stream");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        if (response.Content.Headers.ContentType?.MediaType == "text/event-stream")
            body = string.Join('\n', body.Split('\n').Where(l => l.StartsWith("data: ")).Select(l => l[6..]));
        using var document = JsonDocument.Parse(body);
        Assert.True(document.RootElement.GetProperty("result").GetProperty("isError").GetBoolean());
    }

    [Fact]
    public async Task Unobserved_nested_fields_and_actions_do_not_invalidate_kql()
    {
        using var client = factory.CreateClient();
        using var response = await client.PostAsJsonAsync("/api/v1/validate", new ValidateRequest(
            "DeviceEvents | where ActionType == 'UnobservedAction' | extend Value=tostring(parse_json(AdditionalFields).UnobservedField)",
            KqlEnvironment.Xdr, LintProfile.General), TestContext.Current.CancellationToken);
        var result = await response.Content.ReadFromJsonAsync<ValidationResponse>(TestContext.Current.CancellationToken);
        Assert.True(result!.Valid);
    }
}
