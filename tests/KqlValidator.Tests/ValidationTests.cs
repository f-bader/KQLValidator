using KqlValidator.Contracts;
using KqlValidator.Validation;

namespace KqlValidator.Tests;

public sealed class ValidationTests
{
    private readonly KqlValidationService validator;
    private readonly LintRuleCatalog lintRules;

    public ValidationTests()
    {
        var catalog = new SchemaCatalog();
        lintRules = new LintRuleCatalog();
        validator = new KqlValidationService(
            catalog,
            new GlobalStateFactory(),
            new RequestValidator(catalog, lintRules),
            new KqlLinter(catalog, lintRules),
            lintRules);
    }

    [Fact]
    public void Valid_xdr_query_reports_shape_and_references()
    {
        var result = Validate("DeviceProcessEvents | where Timestamp > ago(1h) | project Timestamp, DeviceId, FileName");

        Assert.True(result.Valid, Messages(result));
        Assert.Contains("DeviceProcessEvents", result.ReferencedTables);
        Assert.Contains(result.OutputColumns, x => x.Name == "FileName" && x.Type == "string");
    }

    [Fact]
    public void Semantic_error_invalidates_query()
    {
        var result = Validate("DeviceEvents | project DoesNotExist");

        Assert.False(result.Valid);
        Assert.Contains(result.Diagnostics, x => x.Severity == DiagnosticSeverity.Error);
    }

    [Fact]
    public void Assigned_ip_addresses_has_documented_output()
    {
        var result = Validate("AssignedIPAddresses('device-id')");

        Assert.True(result.Valid, Messages(result));
        Assert.Contains(result.OutputColumns, x => x.Name == "ConnectedNetworks" && x.Type == "dynamic");
    }

    [Theory]
    [InlineData("GetFirstSeenBehaviors")]
    [InlineData("GetUncommonValueBehaviors")]
    [InlineData("GetHighVolumeAnomalyBehaviors")]
    public void Parameterless_behavior_functions_preserve_row_scope(string function)
    {
        var result = Validate($"BehaviorInfo | invoke {function}() | project BehaviorId, Insights");

        Assert.True(result.Valid, Messages(result));
        Assert.Contains(result.OutputColumns, x => x.Name == "BehaviorId");
    }

    [Fact]
    public void Behavior_function_requires_insights_string()
    {
        var result = Validate("DeviceEvents | invoke GetFirstSeenBehaviors()");

        Assert.False(result.Valid);
    }

    [Theory]
    [InlineData("GetAnomalousBehaviorsByKind('Account')")]
    [InlineData("GetAnomalousBehaviorsByKind('Account', 'FirstSeen')")]
    [InlineData("GetAnomalousBehaviorsByValue('alice@example.test')")]
    [InlineData("GetAnomalousBehaviorsByValue('alice@example.test', 'UncommonValue')")]
    public void Behavior_selector_overloads_validate(string invocation)
    {
        var result = Validate($"BehaviorInfo | invoke {invocation}");
        Assert.True(result.Valid, Messages(result));
    }

    [Fact]
    public void About_function_rejects_invalid_constant_structure()
    {
        var result = Validate("BehaviorInfo | invoke GetAnomalousBehaviorsAbout(dynamic([]))");

        Assert.False(result.Valid);
        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLX002" && x.Severity == DiagnosticSeverity.Error);
    }

    [Fact]
    public void About_function_accepts_valid_constant_structure()
    {
        var result = Validate("BehaviorInfo | invoke GetAnomalousBehaviorsAbout(dynamic([{\"Kind\":\"Account\",\"Value\":\"alice\"}]))");

        Assert.True(result.Valid, Messages(result));
    }

    [Fact]
    public void Hunting_profile_reports_unscoped_search_without_invalidating_query()
    {
        var result = Validate("search \"powershell\" | take 10", profile: LintProfile.Hunting);

        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLH001" && x.Severity == DiagnosticSeverity.Warning);
    }

    [Fact]
    public void Hunting_only_bounds_do_not_leak_into_detection_profile()
    {
        var result = Validate(
            "DeviceEvents | where ActionType == 'ProcessCreated' | project Timestamp, ReportId, DeviceId",
            profile: LintProfile.Detection);

        Assert.DoesNotContain(result.Diagnostics, x => x.RuleId is "KQLH010" or "KQLH013");
    }

    [Fact]
    public void Detection_row_limit_is_distinct_from_hunting_result_bound()
    {
        var result = Validate(
            "DeviceEvents | where ActionType == 'ProcessCreated' | take 10 | project Timestamp, ReportId, DeviceId",
            profile: LintProfile.Detection);

        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLD006");
        Assert.DoesNotContain(result.Diagnostics, x => x.RuleId == "KQLH013");
    }

    [Fact]
    public void Lint_can_be_disabled_without_disabling_semantic_validation()
    {
        var request = new ValidateRequest(
            "search 'powershell' | project MissingColumn",
            KqlEnvironment.Xdr,
            LintProfile.Hunting,
            Lint: new LintOptions(Enabled: false));

        var result = validator.Validate(request);

        Assert.DoesNotContain(result.Diagnostics, x => x.RuleId.StartsWith("KQL", StringComparison.Ordinal));
        Assert.Contains(result.Diagnostics, x => x.Severity == DiagnosticSeverity.Error);
    }

    [Fact]
    public void Caller_can_select_community_rules_without_default_rule_sets()
    {
        var result = validator.Validate(new ValidateRequest(
            "DeviceProcessEvents | where FileName =~ 'powershell.exe' | project Timestamp, DeviceId, FileName",
            KqlEnvironment.Xdr,
            LintProfile.Detection,
            Target: KqlTarget.DefenderScheduled,
            Lint: new LintOptions(RuleSets: ["community-detection"])));

        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLQ002" && x.RuleSet == "community-detection" && x.SourceKind == "community");
        Assert.DoesNotContain(result.Diagnostics, x => x.RuleId == "KQLD003");
    }

    [Fact]
    public void Disable_rule_wins_over_selected_rule_set()
    {
        var result = validator.Validate(new ValidateRequest(
            "DeviceEvents | where ActionType contains 'ProcessCreated' | take 10",
            KqlEnvironment.Xdr,
            LintProfile.Hunting,
            Lint: new LintOptions(RuleSets: ["microsoft-kusto"], DisableRules: ["KQLP001"])));

        Assert.DoesNotContain(result.Diagnostics, x => x.RuleId == "KQLP001");
    }

    [Fact]
    public void Unknown_lint_rule_is_rejected()
    {
        var request = new ValidateRequest(
            "DeviceEvents | take 1",
            KqlEnvironment.Xdr,
            LintProfile.General,
            Lint: new LintOptions(EnableRules: ["NOT-A-RULE"]));

        Assert.Throws<RequestValidationException>(() => validator.Validate(request));
    }

    [Fact]
    public void Rule_catalog_has_unique_ids_metadata_and_documentation_entries()
    {
        var rules = lintRules.List();
        var docsPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../docs/lint-rules.md"));
        var documentation = File.ReadAllText(docsPath);

        Assert.Equal(rules.Count, rules.Select(x => x.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(rules, rule =>
        {
            Assert.False(string.IsNullOrWhiteSpace(rule.DocumentationUrl));
            Assert.Contains($"`{rule.RuleId}`", documentation, StringComparison.Ordinal);
        });
    }

    [Theory]
    [InlineData("DeviceEvents | where ActionType contains 'ProcessCreated' | take 1", "KQLP001")]
    [InlineData("DeviceEvents | where ActionType =~ 'A' or ActionType =~ 'B' | take 1", "KQLP002")]
    [InlineData("DeviceEvents | where AdditionalFields != '' | take 1", "KQLP005")]
    public void Microsoft_kusto_pack_reports_high_confidence_patterns(string query, string ruleId)
    {
        var result = Validate(query, profile: LintProfile.Hunting);
        Assert.Contains(result.Diagnostics, x => x.RuleId == ruleId && x.RuleSet == "microsoft-kusto");
    }

    [Fact]
    public void Defender_nrt_rejects_multi_input_operators_and_comments()
    {
        var result = validator.Validate(new ValidateRequest(
            "// explanation\nDeviceEvents | join kind=inner (DeviceInfo) on DeviceId | project Timestamp, DeviceId",
            KqlEnvironment.Xdr,
            LintProfile.Detection,
            Target: KqlTarget.DefenderNrt));

        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLN001" && x.Severity == DiagnosticSeverity.Error);
        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLN002" && x.Severity == DiagnosticSeverity.Error);
    }

    [Fact]
    public void Native_xdr_accepts_time_generated_but_prefers_timestamp()
    {
        var result = Validate(
            "DeviceEvents | extend TimeGenerated = Timestamp | project TimeGenerated, DeviceId, ReportId",
            profile: LintProfile.Detection);

        Assert.DoesNotContain(result.Diagnostics, x => x.RuleId == "KQLD002");
        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLX003" && x.Severity == DiagnosticSeverity.Information);
    }

    [Fact]
    public void Sentinel_detection_requires_time_generated()
    {
        var result = Validate("SecurityAlert | project DisplayName", KqlEnvironment.Sentinel, LintProfile.Detection);

        Assert.False(result.Valid);
        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLD001");
    }

    [Fact]
    public void Sentinel_detection_requires_time_generated_in_output_not_only_filter()
    {
        var result = Validate("SecurityAlert | where TimeGenerated > ago(1h) | project DisplayName", KqlEnvironment.Sentinel, LintProfile.Detection);

        Assert.False(result.Valid);
        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLD001");
    }

    [Fact]
    public void Seen_by_preserves_device_row_scope()
    {
        var result = Validate("DeviceInfo | invoke SeenBy() | project DeviceId, DeviceName");

        Assert.True(result.Valid, Messages(result));
    }

    [Fact]
    public void Request_scoped_watchlist_columns_are_available()
    {
        var extensions = new ValidationExtensions(Watchlists:
        [
            new WatchlistDeclaration("high_value", [new ColumnDeclaration("AccountUpn", "string")])
        ]);

        var result = Validate("_GetWatchlist('high_value') | project SearchKey, AccountUpn", KqlEnvironment.Sentinel, extensions: extensions);
        Assert.True(result.Valid, Messages(result));
    }

    [Fact]
    public void Request_scoped_table_is_available_only_to_that_validation()
    {
        var extensions = new ValidationExtensions(Tables:
        [
            new TableDeclaration("MyEvents", [new ColumnDeclaration("TimeGenerated", "datetime"), new ColumnDeclaration("Value", "string")])
        ]);
        var custom = Validate("MyEvents | project Value", extensions: extensions);
        var builtInOnly = Validate("MyEvents | project Value");

        Assert.True(custom.Valid, Messages(custom));
        Assert.False(builtInOnly.Valid);
    }

    [Fact]
    public void Extension_cannot_shadow_builtin()
    {
        var extensions = new ValidationExtensions(Tables:
        [
            new TableDeclaration("DeviceEvents", [new ColumnDeclaration("Other", "string")])
        ]);

        Assert.Throws<RequestValidationException>(() => Validate("DeviceEvents", extensions: extensions));
    }

    private ValidationResponse Validate(
        string query,
        KqlEnvironment environment = KqlEnvironment.Xdr,
        LintProfile profile = LintProfile.General,
        ValidationExtensions? extensions = null) =>
        validator.Validate(new ValidateRequest(query, environment, profile, extensions));

    private static string Messages(ValidationResponse response) =>
        string.Join(Environment.NewLine, response.Diagnostics.Select(x => $"{x.RuleId}: {x.Message}"));
}
