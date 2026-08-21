using KqlValidator.Contracts;
using KqlValidator.Validation;

namespace KqlValidator.Tests;

/// <summary>Coverage for lint rules, limits, cancellation, and schema search paths.</summary>
public sealed class ValidationCoverageTests
{
    private static readonly SchemaCatalog Catalog = new();
    private static readonly LintRuleCatalog LintRules = new();

    private readonly KqlValidationService validator = new(
        Catalog,
        new GlobalStateFactory(),
        new RequestValidator(Catalog, LintRules),
        new KqlLinter(Catalog, LintRules),
        new DefenderNrtValidator(LintRules),
        LintRules);

    private readonly SchemaQueryService schemas = new(Catalog);

    [Theory]
    [InlineData("""DeviceEvents | where * contains "mimikatz" | take 1""", "KQLH002")]
    [InlineData("""union withsource=Source DeviceEvents, DeviceInfo | take 1""", "KQLH003")]
    [InlineData("""DeviceProcessEvents | where tolower(FileName) == "cmd.exe" | take 1""", "KQLH004")]
    [InlineData("""DeviceProcessEvents | where FileName matches regex "cmd.*" | take 1""", "KQLH005")]
    [InlineData("""DeviceProcessEvents | where ProcessCommandLine has "cmd" | take 1""", "KQLH006")]
    [InlineData("""DeviceProcessEvents | extend Lowered = tolower(FileName) | where Lowered == "cmd.exe" | take 1""", "KQLH007")]
    [InlineData("""DeviceProcessEvents | where ProcessCommandLine == "evil.exe -x" | take 1""", "KQLH008")]
    [InlineData("""DeviceProcessEvents | where Timestamp > ago(1h) | join kind=inner (DeviceInfo) on DeviceId | take 1""", "KQLH011")]
    [InlineData("""DeviceEvents | extend Parsed = parse_json(AdditionalFields) | where Timestamp > ago(1h) | take 1""", "KQLH012")]
    [InlineData("""DeviceProcessEvents | where Timestamp > ago(1h) and ProcessId == 4 | take 1""", "KQLH014")]
    [InlineData("""DeviceEvents | evaluate bag_unpack(AdditionalFields) | take 1""", "KQLP003")]
    [InlineData("""DeviceEvents | where format_datetime(Timestamp, "yyyy-MM-dd") == "2024-01-01" | take 1""", "KQLP004")]
    [InlineData("""DeviceEvents | where AdditionalFields has "192.0.2.4" | take 1""", "KQLP006")]
    [InlineData("""DeviceEvents | where ActionType == "NotARealActionType" | take 1""", "KQLX001")]
    public void Hunting_rules_fire_on_their_documented_patterns(string query, string expectedRule)
    {
        var result = validator.Validate(new ValidateRequest(query, KqlEnvironment.Xdr, LintProfile.Hunting),
            TestContext.Current.CancellationToken);

        Assert.Contains(result.Diagnostics, x => x.RuleId == expectedRule);
    }

    [Theory]
    [InlineData("""DeviceProcessEvents | where AccountName == "admin" | project Timestamp, DeviceId, ReportId""", KqlEnvironment.Xdr, KqlTarget.DefenderScheduled, "KQLQ001")]
    [InlineData("""DeviceProcessEvents | where FileName != "explorer.exe" | project Timestamp, DeviceId""", KqlEnvironment.Xdr, KqlTarget.DefenderScheduled, "KQLQ003")]
    [InlineData("""union SigninLogs, AuditLogs | project TimeGenerated""", KqlEnvironment.Sentinel, KqlTarget.SentinelNrt, "KQLQ004")]
    public void Community_rules_fire_when_their_rule_set_is_selected(
        string query, KqlEnvironment environment, KqlTarget target, string expectedRule)
    {
        var result = validator.Validate(new ValidateRequest(
            query, environment, LintProfile.Detection,
            Target: target,
            Lint: new LintOptions(RuleSets: ["community-detection"])), TestContext.Current.CancellationToken);

        Assert.Contains(result.Diagnostics, x => x.RuleId == expectedRule);
    }

    [Fact]
    public void Url_literal_no_longer_hides_the_rest_of_the_line_from_lint()
    {
        var result = validator.Validate(new ValidateRequest(
            """DeviceNetworkEvents | where RemoteUrl == "http://evil.example" | take 5""",
            KqlEnvironment.Xdr, LintProfile.Hunting), TestContext.Current.CancellationToken);

        // The // inside the URL literal used to be masked as a comment, blanking "| take 5"
        // and producing a false unbounded-result warning.
        Assert.DoesNotContain(result.Diagnostics, x => x.RuleId == "KQLH013");
    }

    [Fact]
    public void Comment_content_is_still_ignored_by_lint()
    {
        var result = validator.Validate(new ValidateRequest(
            "DeviceEvents | where ActionType == \"ProcessCreated\" // take 1",
            KqlEnvironment.Xdr, LintProfile.Hunting), TestContext.Current.CancellationToken);

        // "take 1" only appears inside a comment, so the unbounded-result warning applies.
        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLH013");
    }

    [Fact]
    public void Pre_cancelled_token_aborts_validation()
    {
        Assert.ThrowsAny<OperationCanceledException>(() => validator.Validate(new ValidateRequest(
            "DeviceEvents | take 1", KqlEnvironment.Xdr, LintProfile.General),
            new CancellationToken(canceled: true)));
    }

    [Fact]
    public void Diagnostics_are_capped_with_a_truncation_marker()
    {
        var query = "DeviceEvents\n"
            + string.Join('\n', Enumerable.Range(0, 600).Select(i => $"| where ActionType == \"NotReal{i}\""))
            + "\n| where NotAColumn == 1 | take 1";
        var result = validator.Validate(new ValidateRequest(query, KqlEnvironment.Xdr, LintProfile.General),
            TestContext.Current.CancellationToken);

        Assert.Equal(501, result.Diagnostics.Count);
        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLV001");
    }

    [Fact]
    public void Extension_limits_are_enforced()
    {
        var column = new ColumnDeclaration("Value", "string");

        var tooManyTables = new ValidationExtensions(
            Tables: Enumerable.Range(0, 101).Select(i => new TableDeclaration($"Custom{i}", [column])).ToArray());
        var tooManyColumns = new ValidationExtensions(
            Tables: Enumerable.Range(0, 100).Select(i => new TableDeclaration(
                $"Custom{i}",
                Enumerable.Range(0, 51).Select(c => new ColumnDeclaration($"Column{c}", "string")).ToArray())).ToArray());
        var tooManyParameters = new ValidationExtensions(
            Functions: Enumerable.Range(0, 100).Select(i => new FunctionDeclaration(
                $"CustomFunction{i}",
                Enumerable.Range(0, 11).Select(p => new ParameterDeclaration($"parameter{p}", "string")).ToArray(),
                new FunctionReturnDeclaration("scalar", "string"))).ToArray());

        AssertRejected("tables", tooManyTables);
        AssertRejected("columns", tooManyColumns);
        AssertRejected("function parameters", tooManyParameters);

        void AssertRejected(string expectedFragment, ValidationExtensions extensions)
        {
            var exception = Assert.Throws<RequestValidationException>(() => validator.Validate(new ValidateRequest(
                "DeviceEvents | take 1", KqlEnvironment.Xdr, LintProfile.General, extensions),
                TestContext.Current.CancellationToken));
            Assert.Contains(expectedFragment, exception.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Lint_selection_lists_are_limited()
    {
        var exception = Assert.Throws<RequestValidationException>(() => validator.Validate(new ValidateRequest(
            "DeviceEvents | take 1", KqlEnvironment.Xdr, LintProfile.General,
            Lint: new LintOptions(DisableRules: Enumerable.Repeat("KQLH001", 101).ToArray())),
            TestContext.Current.CancellationToken));

        Assert.Contains("limited to 100", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Schema_search_clamps_the_page_size()
    {
        var result = schemas.Search(KqlEnvironment.Unified, null, null, 1_000, null);

        Assert.Equal(100, result.Items.Count);
        Assert.NotNull(result.NextCursor);
    }

    [Fact]
    public void Schema_search_cursor_round_trip_matches_a_larger_page()
    {
        var combined = schemas.Search(KqlEnvironment.Xdr, "Device", "table", 10, null);
        var first = schemas.Search(KqlEnvironment.Xdr, "Device", "table", 5, null);
        Assert.NotNull(first.NextCursor);
        var second = schemas.Search(KqlEnvironment.Xdr, "Device", "table", 5, first.NextCursor);

        Assert.Equal(
            combined.Items.Select(x => x.Name),
            first.Items.Concat(second.Items).Select(x => x.Name));
    }

    [Fact]
    public void Schema_search_treats_a_malformed_cursor_as_the_first_page()
    {
        var expected = schemas.Search(KqlEnvironment.Xdr, "Device", "table", 5, null);
        var malformed = schemas.Search(KqlEnvironment.Xdr, "Device", "table", 5, "!!not-base64!!");

        Assert.Equal(expected.Items.Select(x => x.Name), malformed.Items.Select(x => x.Name));
    }

    [Theory]
    [InlineData("category", "performance")]
    [InlineData("profile", "detection")]
    [InlineData("target", "defender-nrt")]
    [InlineData("environment", "sentinel")]
    public void Lint_rule_catalog_filters_apply(string filter, string value)
    {
        var rules = filter switch
        {
            "category" => LintRules.List(category: value),
            "profile" => LintRules.List(profile: value),
            "target" => LintRules.List(target: value),
            _ => LintRules.List(environment: value),
        };

        Assert.NotEmpty(rules);
        Assert.All(rules, rule => Assert.True(filter switch
        {
            "category" => rule.Category.Equals(value, StringComparison.OrdinalIgnoreCase),
            "profile" => rule.Profiles.Contains(value, StringComparer.OrdinalIgnoreCase),
            "target" => rule.Targets.Count == 0 || rule.Targets.Contains(value, StringComparer.OrdinalIgnoreCase),
            _ => rule.Environments.Count == 0 || rule.Environments.Contains(value, StringComparer.OrdinalIgnoreCase),
        }));
    }
}
