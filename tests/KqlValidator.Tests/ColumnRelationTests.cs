using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using KqlValidator.Contracts;
using KqlValidator.SchemaSync;
using KqlValidator.Validation;
using Microsoft.AspNetCore.Mvc.Testing;

namespace KqlValidator.Tests;

public sealed class ColumnRelationTests
{
    private readonly SchemaCatalog catalog = new();

    private ValidationResponse Validate(string query, LintOptions? lint = null, KqlEnvironment environment = KqlEnvironment.Xdr,
        ValidationExtensions? extensions = null)
    {
        var rules = new LintRuleCatalog();
        var validator = new KqlValidationService(catalog, new GlobalStateFactory(), new RequestValidator(catalog, rules),
            new KqlLinter(catalog, rules), new DefenderNrtValidator(rules), rules);
        return validator.Validate(new(query, environment, LintProfile.General, extensions,
            Lint: lint ?? new(RuleSets: ["community-correlations"])), TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData("EntraIdSignInEvents | join kind=inner GraphAPIAuditEvents on $left.SessionId == $right.UniqueTokenIdentifier", "KQLR001")]
    [InlineData("DeviceInfo | join kind=inner DeviceProcessEvents on $left.AadDeviceId == $right.DeviceId", "KQLR001")]
    [InlineData("DeviceFileEvents | join kind=inner DeviceProcessEvents on $left.SHA256 == $right.SHA1", "KQLR001")]
    [InlineData("DeviceProcessEvents | join kind=inner DeviceNetworkEvents on $left.ProcessUniqueId == $right.InitiatingProcessUniqueId", "KQLR003")]
    [InlineData("let L = EntraIdSignInEvents | extend Key=tolower(UniqueTokenId); L | join kind=inner GraphAPIAuditEvents on $left.Key == $right.UniqueTokenIdentifier", "KQLR002")]
    [InlineData("let L = EntraIdSignInEvents | project-rename Key=SessionId; let R = GraphAPIAuditEvents | project Token=UniqueTokenIdentifier; L | join kind=inner R on $left.Key == $right.Token", "KQLR001")]
    [InlineData("EntraIdSignInEvents | join kind=inner (CloudAppEvents | extend Key=tostring(RawEventData.AppAccessContext.UniqueTokenId)) on $left.SessionId == $right.Key", "KQLR001")]
    [InlineData("EntraIdSignInEvents | join kind=inner (CloudAppEvents | extend Key=tostring(RawEventData['AppAccessContext']['UniqueTokenId'])) on $left.SessionId == $right.Key", "KQLR001")]
    [InlineData("EntraIdSignInEvents | join kind=inner (CloudAppEvents | extend Key=tolower(tostring(parse_json(RawEventData.claims).uti))) on $left.UniqueTokenId == $right.Key", "KQLR002")]
    public void Known_correlation_mistakes_emit_sourced_warnings(string query, string rule)
    {
        var result = Validate(query);
        Assert.True(result.Valid, string.Join("; ", result.Diagnostics.Select(d => d.Message)));
        var diagnostic = Assert.Single(result.Diagnostics, d => d.RuleId == rule);
        Assert.Equal(DiagnosticSeverity.Warning, diagnostic.Severity);
        Assert.Equal("community-correlations", diagnostic.RuleSet);
        Assert.Equal("community", diagnostic.SourceKind);
        Assert.Equal("XDRInternals", diagnostic.SourceName);
        Assert.Equal(ColumnRelationCatalog.SourceUrl, diagnostic.DocumentationUrl);
        Assert.InRange(diagnostic.Span.Start, 0, query.Length - 1);
        Assert.Contains("on", query[..diagnostic.Span.Start]);
    }

    [Theory]
    [InlineData("DeviceProcessEvents | join kind=inner DeviceNetworkEvents on DeviceId, $left.ProcessUniqueId == $right.InitiatingProcessUniqueId")]
    [InlineData("DeviceNetworkEvents | join kind=inner DeviceProcessEvents on $left.InitiatingProcessUniqueId == $right.ProcessUniqueId and $left.DeviceId == $right.DeviceId")]
    [InlineData("let L = DeviceProcessEvents | extend D=tolower(DeviceId); let R = DeviceNetworkEvents | extend D=tolower(DeviceId); L | join kind=inner R on D, $left.ProcessUniqueId == $right.InitiatingProcessUniqueId")]
    [InlineData("let L = DeviceProcessEvents | project P=ProcessUniqueId, D=DeviceId; let R = DeviceNetworkEvents | project P=InitiatingProcessUniqueId, D=DeviceId; L | join kind=inner R on P, D")]
    [InlineData("let L = DeviceProcessEvents | where DeviceId == 'one'; let R = DeviceNetworkEvents | where DeviceId == 'one'; L | join kind=inner R on $left.ProcessUniqueId == $right.InitiatingProcessUniqueId")]
    [InlineData("let L = EntraIdSignInEvents | project K=tostring(UniqueTokenId); L | join kind=inner GraphAPIAuditEvents on $left.K == $right.UniqueTokenIdentifier")]
    [InlineData("EntraIdSignInEvents | join kind=inner GraphAPIAuditEvents on $left.AccountObjectId == $right.AccountObjectId")]
    [InlineData("DeviceFileEvents | extend K=tolower(SHA1) | join kind=inner DeviceProcessEvents on $left.K == $right.SHA1")]
    [InlineData("EntraIdSignInEvents | join kind=inner (CloudAppEvents | extend K=tostring(RawEventData.AppAccessContext.uniqueTokenId)) on $left.SessionId == $right.K")]
    [InlineData("let L = EntraIdSignInEvents | extend K=strcat(UniqueTokenId, 'suffix'); L | join kind=inner GraphAPIAuditEvents on $left.K == $right.UniqueTokenIdentifier")]
    [InlineData("let L = union (EntraIdSignInEvents | project K=UniqueTokenId), (EntraIdSignInEvents | project K=SessionId); L | join kind=inner GraphAPIAuditEvents on $left.K == $right.UniqueTokenIdentifier")]
    [InlineData("// tolower(UniqueTokenId)\nEntraIdSignInEvents | extend Example='tolower(UniqueTokenId)' | join kind=inner GraphAPIAuditEvents on $left.UniqueTokenId == $right.UniqueTokenIdentifier")]
    public void Compatible_scoped_unknown_and_ambiguous_correlations_stay_silent(string query)
    {
        var result = Validate(query);
        Assert.True(result.Valid, string.Join("; ", result.Diagnostics.Select(d => d.Message)));
        Assert.DoesNotContain(result.Diagnostics, d => d.RuleId.StartsWith("KQLR", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("DeviceProcessEvents | where DeviceId == 'one' | join kind=inner (DeviceNetworkEvents | where DeviceId == 'two') on $left.ProcessUniqueId == $right.InitiatingProcessUniqueId")]
    [InlineData("DeviceProcessEvents | where DeviceId == 'one' or DeviceId == 'two' | join kind=inner (DeviceNetworkEvents | where DeviceId == 'one') on $left.ProcessUniqueId == $right.InitiatingProcessUniqueId")]
    [InlineData("DeviceProcessEvents | join kind=inner DeviceNetworkEvents on $left.ProcessUniqueId == $right.InitiatingProcessUniqueId | where DeviceId == 'one'")]
    public void Different_partial_or_late_device_filters_do_not_suppress_scope_warning(string query) =>
        Assert.Contains(Validate(query).Diagnostics, d => d.RuleId == "KQLR003");

    [Fact]
    public void Rule_selection_and_semantic_validation_remain_independent()
    {
        const string query = "DeviceProcessEvents | join kind=inner DeviceNetworkEvents on $left.ProcessUniqueId == $right.InitiatingProcessUniqueId";
        foreach (var options in new[] { new LintOptions(), new LintOptions(Enabled: false),
            new LintOptions(RuleSets: ["community-correlations"], MinimumSeverity: DiagnosticSeverity.Error),
            new LintOptions(RuleSets: ["community-correlations"], DisableRules: ["KQLR003"]) })
            Assert.DoesNotContain(Validate(query, options).Diagnostics, d => d.RuleId.StartsWith("KQLR", StringComparison.Ordinal));
        Assert.Contains(Validate(query, new(EnableRules: ["KQLR003"])).Diagnostics, d => d.RuleId == "KQLR003");
        Assert.False(Validate("DeviceProcessEvents | project Missing", new(Enabled: false)).Valid);
    }

    [Theory]
    [InlineData("AwsResourceName")]
    [InlineData("GcpFullResourceName")]
    public void Cloud_resource_case_folding_is_detected(string column)
    {
        var result = Validate($"CloudProcessEvents | extend K=tolower({column}) | join kind=inner CloudDnsEvents on $left.K == $right.{column}");
        Assert.True(result.Valid);
        Assert.Single(result.Diagnostics, d => d.RuleId == "KQLR002");
    }

    [Fact]
    public void Normalized_azure_resource_ids_are_not_case_preservation_errors()
    {
        var result = Validate("CloudProcessEvents | extend K=tolower(AzureResourceId) | join kind=inner (CloudDnsEvents | extend K=tolower(AzureResourceId)) on K");
        Assert.True(result.Valid);
        Assert.Empty(result.Diagnostics);
    }

    [Fact]
    public void Catalog_digest_matches_tracked_manifest()
    {
        var response = new SchemaQueryService(catalog).GetRelations(KqlEnvironment.Xdr, "DeviceProcessEvents");
        using var manifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Schemas", "manifest.json")));
        var source = Assert.Single(manifest.RootElement.GetProperty("sources").EnumerateArray(),
            s => s.GetProperty("url").GetString() == ColumnRelationCatalog.SourceUrl);
        Assert.Equal(source.GetProperty("sha256").GetString(), response.Sha256);
    }

    [Fact]
    public void Catalog_discovery_preserves_paths_guidance_and_environment_boundaries()
    {
        var service = new SchemaQueryService(catalog);
        var result = service.GetRelations(KqlEnvironment.Xdr, "entraidSignInEvents", "UniqueTokenId");
        Assert.NotEmpty(result.Items);
        Assert.Equal(1, result.Version);
        Assert.Equal(64, result.Sha256.Length);
        Assert.All(result.Items, r => Assert.Equal("entra-token", r.Family));
        Assert.Contains(result.Items, r => r.To.Path == "AppAccessContext.UniqueTokenId");
        Assert.DoesNotContain(result.Items, r => r.To.Table == "MicrosoftGraphActivityLogs");
        Assert.Contains(service.GetRelations(KqlEnvironment.Unified, "EntraIdSignInEvents").Items,
            r => r.To.Table == "MicrosoftGraphActivityLogs");
        Assert.Empty(service.GetRelations(KqlEnvironment.Xdr, "NotATable").Items);
        Assert.Empty(service.GetRelations(KqlEnvironment.Xdr, "EntraIdSignInEvents", "NotAColumn").Items);
        Assert.Contains(service.GetRelations(KqlEnvironment.Unified, "AADGraphActivityLogs").Items,
            r => r.Guidance.Contains("padding", StringComparison.Ordinal));
    }

    [Fact]
    public void Normalizer_rejects_duplicates_unknown_families_and_bad_endpoints()
    {
        var snapshotPath = Path.Combine(AppContext.BaseDirectory, "Schemas", "column-relations.json");
        var raw = File.ReadAllText(snapshotPath);
        var normalized = ColumnRelationNormalizer.Normalize(raw);
        Assert.Equal(ColumnRelationCatalog.SourceUrl, normalized["source"]!.GetValue<string>());
        Assert.Equal(catalog.Relations.Relations.Count, normalized["relations"]!.AsArray().Count);
        foreach (var mutate in new Action<System.Text.Json.Nodes.JsonObject>[] {
            root => root["relations"]!.AsArray().Add(root["relations"]![0]!.DeepClone()),
            root => root["relations"]![0]!["family"] = "unknown-family",
            root => root["relations"]![0]!["from"]!["column"] = "",
            root => root["relations"]![0]!["tags"] = null,
            root => root["relations"]![0]!["otherNotes"] = "invalid", })
        {
            var copy = normalized.DeepClone().AsObject();
            mutate(copy);
            Assert.Throws<InvalidDataException>(() => ColumnRelationNormalizer.Normalize(copy.ToJsonString()));
        }
    }
}

public sealed class ColumnRelationApiTests(WebApplicationFactory<Program> factory) : IClassFixture<WebApplicationFactory<Program>>
{
    [Fact]
    public async Task Rest_discovery_filters_columns_and_rejects_unknown_environments()
    {
        using var client = factory.CreateClient();
        var result = await client.GetFromJsonAsync<ColumnRelationResponse>(
            "/api/v1/environments/xdr/tables/EntraIdSignInEvents/relations?column=UniqueTokenId", TestContext.Current.CancellationToken);
        Assert.NotNull(result);
        Assert.NotEmpty(result.Items);
        Assert.All(result.Items, r => Assert.Equal("entra-token", r.Family));
        using var invalid = await client.GetAsync("/api/v1/environments/unknown/tables/DeviceInfo/relations", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
    }
}
