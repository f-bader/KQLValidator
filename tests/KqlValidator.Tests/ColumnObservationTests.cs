using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using KqlValidator.Contracts;
using KqlValidator.SchemaSync;
using KqlValidator.Validation;
using Microsoft.AspNetCore.Mvc.Testing;

namespace KqlValidator.Tests;

public sealed class ColumnObservationTests
{
    private readonly SchemaCatalog catalog = TestSchemaCatalog.Bundled;
    private ValidationResponse Validate(string query, LintOptions? lint = null)
    {
        var rules = new LintRuleCatalog();
        var service = new KqlValidationService(catalog, new GlobalStateFactory(), new RequestValidator(catalog, rules),
            new KqlLinter(catalog, rules), new DefenderNrtValidator(rules), rules);
        return service.Validate(new(query, KqlEnvironment.Xdr, LintProfile.Detection,
            Lint: lint ?? new(RuleSets: ["community-observations"])), TestContext.Current.CancellationToken);
    }

    [Fact]
    public void Discovery_preserves_credits_and_filters_against_the_effective_environment()
    {
        var service = new SchemaQueryService(catalog);
        var result = service.GetObservations(KqlEnvironment.Xdr, "deviceprocessevents", "filename");
        var item = Assert.Single(result.Items);
        Assert.Equal("value-case-variation", item.Kind);
        var source = Assert.Single(item.Sources);
        Assert.Equal("Olaf Hartong", source.Name);
        Assert.Equal("https://github.com/olafhartong", source.Url);
        Assert.Equal("CaseInconsistentFields.json", source.Dataset);
        Assert.NotEmpty(service.GetObservations(KqlEnvironment.Unified, "AADGraphActivityLogs", "SignInActivityId").Items);
        Assert.Empty(service.GetObservations(KqlEnvironment.Xdr, "AADGraphActivityLogs").Items);
        Assert.Empty(service.GetObservations(KqlEnvironment.Unified, "MissingTable").Items);
        Assert.Empty(service.GetObservations(KqlEnvironment.Xdr, "DeviceProcessEvents", "MissingColumn").Items);
        Assert.Empty(service.GetObservations(KqlEnvironment.Xdr, "DeviceProcessEvents", "FileName", "nested").Items);
        Assert.Single(service.GetObservations(KqlEnvironment.Xdr, "DeviceProcessEvents", "FileName", "").Items);
        Assert.NotNull(service.GetTable(KqlEnvironment.Xdr, "DeviceProcessEvents")!.Columns.Single(c => c.Name == "FileName").Observations);
        Assert.All(service.GetObservations(KqlEnvironment.Xdr).Items, e => Assert.Contains(
            catalog.Get(KqlEnvironment.Xdr).Tables[e.Table].Columns, c => c.Name == e.Column));
    }

    [Fact]
    public void Snapshot_and_manifest_agree_and_keep_all_imported_pairs()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Schemas", "column-observations.json");
        var raw = JsonNode.Parse(File.ReadAllText(path))!;
        Assert.Equal(252, raw["observations"]!.AsArray().Count(e => e!["kind"]!.GetValue<string>() == "value-case-variation"));
        var response = new SchemaQueryService(catalog).GetObservations(KqlEnvironment.Unified);
        using var manifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Schemas", "manifest.json")));
        var source = Assert.Single(manifest.RootElement.GetProperty("sources").EnumerateArray(),
            e => e.GetProperty("url").GetString() == ColumnObservationCatalog.SourceUrl);
        Assert.Equal(source.GetProperty("sha256").GetString(), response.Sha256);
        Assert.Equal(64, response.Sha256.Length);
    }

    [Theory]
    [InlineData("duplicate")]
    [InlineData("source")]
    [InlineData("eligibility")]
    [InlineData("path")]
    [InlineData("version")]
    public void Normalizer_rejects_malformed_observations(string defect)
    {
        var root = JsonNode.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Schemas", "column-observations.json")))!;
        var entries = root["observations"]!.AsArray();
        if (defect == "duplicate") entries.Add(entries[0]!.DeepClone());
        if (defect == "source") entries[0]!["sourceIds"] = new JsonArray("unknown");
        if (defect == "eligibility") entries[0]!["diagnosticEligibility"] = "fold-all-values";
        if (defect == "path") entries[0]!["path"] = "a..b";
        if (defect == "version") root["version"] = 2;
        Assert.Throws<InvalidDataException>(() => ColumnObservationNormalizer.Normalize(root.ToJsonString()));
    }

    [Theory]
    [InlineData("DeviceProcessEvents | where FolderPath == @'C:\\Windows'")]
    [InlineData("DeviceFileEvents | where FolderPath startswith @'C:\\' and FileName != 'cmd.exe'")]
    [InlineData("DeviceImageLoadEvents | where FolderPath startswith @'C:\\' | where FileName in ('cmd.exe', 'powershell.exe')")]
    [InlineData("let T = DeviceProcessEvents | project Name=FileName, FolderPath; T | where FolderPath startswith @'C:\\' and Name !in ('cmd.exe')")]
    [InlineData("DeviceProcessEvents | where @'C:\\Windows' == FolderPath")]
    public void Reviewed_windows_comparisons_emit_an_opt_in_information_diagnostic(string query)
    {
        var result = Validate(query);
        Assert.True(result.Valid);
        var diagnostic = Assert.Single(result.Diagnostics, d => d.RuleId == "KQLO001");
        Assert.Equal(DiagnosticSeverity.Information, diagnostic.Severity);
        Assert.Contains("Olaf Hartong", diagnostic.Message);
        Assert.Equal(ColumnObservationCatalog.SourceUrl, diagnostic.DocumentationUrl);
        Assert.DoesNotContain(Validate(query, new()).Diagnostics, d => d.RuleId == "KQLO001");
        Assert.DoesNotContain(Validate(query, new(Enabled: false)).Diagnostics, d => d.RuleId == "KQLO001");
        Assert.DoesNotContain(Validate(query, new(RuleSets: ["community-observations"], DisableRules: ["KQLO001"])).Diagnostics,
            d => d.RuleId == "KQLO001");
        Assert.Contains(Validate(query, new(EnableRules: ["KQLO001"])).Diagnostics, d => d.RuleId == "KQLO001");
    }

    [Theory]
    [InlineData("DeviceProcessEvents | where FileName == 'cmd.exe'")]
    [InlineData("DeviceProcessEvents | where FolderPath == '/usr/bin'")]
    [InlineData("DeviceProcessEvents | where FolderPath =~ @'C:\\Windows'")]
    [InlineData("DeviceProcessEvents | where FolderPath startswith @'C:\\' and FileName in~ ('cmd.exe')")]
    [InlineData("DeviceProcessEvents | where FolderPath startswith @'C:\\' or FileName == 'cmd.exe'")]
    [InlineData("DeviceProcessEvents | where FolderPath startswith @'C:\\' and tolower(FileName) == 'cmd.exe'")]
    [InlineData("DeviceProcessEvents | where FolderPath startswith @'C:\\' and FileName == InitiatingProcessFileName")]
    [InlineData("DeviceProcessEvents | where FolderPath startswith @'C:\\' and FileName == ''")]
    [InlineData("DeviceProcessEvents | where tostring(AdditionalFields.Name) == 'cmd.exe'")]
    [InlineData("EntraIdSignInEvents | where UniqueTokenId == 'AbCd'")]
    [InlineData("DeviceNetworkEvents | where RemoteUrl == 'Example.org/A'")]
    [InlineData("DeviceProcessEvents | extend FileName=tolower(FileName) | where FolderPath startswith @'C:\\' and FileName == 'cmd.exe'")]
    [InlineData("DeviceProcessEvents | join kind=inner DeviceFileEvents on FileName")]
    [InlineData("let L=DeviceProcessEvents | project LeftFolder=FolderPath, DeviceId; let R=DeviceFileEvents | project RightName=FileName, DeviceId; L | join kind=inner R on DeviceId | where LeftFolder startswith @'C:\\' and RightName == 'bash'")]
    [InlineData("let L=DeviceProcessEvents | project LeftFolder=FolderPath, DeviceId; let R=DeviceProcessEvents | project RightName=FileName, DeviceId; L | join kind=inner R on DeviceId | where LeftFolder startswith @'C:\\' and RightName == 'bash'")]
    public void Advisory_skips_unreviewed_context_and_unsupported_expressions(string query)
    {
        Assert.DoesNotContain(Validate(query).Diagnostics, d => d.RuleId == "KQLO001");
    }

    [Fact]
    public void Observation_rule_takes_precedence_only_when_both_rules_emit()
    {
        const string query = "DeviceProcessEvents | where FolderPath == @'C:\\Windows'";
        var both = Validate(query, new(RuleSets: ["community-observations", "community-detection"]));
        Assert.Contains(both.Diagnostics, d => d.RuleId == "KQLO001");
        Assert.DoesNotContain(both.Diagnostics, d => d.RuleId == "KQLD007");
        Assert.Contains(Validate(query, new(EnableRules: ["KQLD007"])).Diagnostics, d => d.RuleId == "KQLD007");
    }

    [Fact]
    public async Task Rest_exposes_observations_and_rejects_unknown_environments()
    {
        await using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();
        var token = TestContext.Current.CancellationToken;
        var result = await client.GetFromJsonAsync<ColumnObservationResponse>(
            "/api/v1/environments/xdr/column-observations?table=DeviceProcessEvents&column=FileName", token);
        Assert.Single(result!.Items);
        var table = await client.GetFromJsonAsync<SchemaTable>("/api/v1/environments/xdr/tables/DeviceProcessEvents", token);
        Assert.Single(table!.Columns.Single(c => c.Name == "FileName").Observations!);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/api/v1/environments/unknown/column-observations", token)).StatusCode);
    }
}
