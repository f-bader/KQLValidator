using KqlValidator.Contracts;
using KqlValidator.Validation;

namespace KqlValidator.Tests;

public sealed class ValidationTests
{
    private readonly KqlValidationService validator;

    public ValidationTests()
    {
        var catalog = new SchemaCatalog();
        validator = new KqlValidationService(
            catalog,
            new GlobalStateFactory(),
            new RequestValidator(catalog),
            new KqlLinter());
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
    public void Sentinel_detection_requires_time_generated()
    {
        var result = Validate("SecurityAlert | project DisplayName", KqlEnvironment.Sentinel, LintProfile.Detection);

        Assert.False(result.Valid);
        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLD001");
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
