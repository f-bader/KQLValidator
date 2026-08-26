using KqlValidator.Contracts;
using KqlValidator.Validation;

namespace KqlValidator.Tests;

public sealed class TransformationValidationTests
{
    private static readonly AzureMonitorTransformationValidationService Validator = new(
        new GlobalStateFactory(), new LintRuleCatalog());

    [Fact]
    public void Valid_transformation_binds_source_and_destination_schemas()
    {
        var result = Validate(
            "source | where Message != '' | extend TimeGenerated = todatetime(Time) | project TimeGenerated, Message",
            [new("Time", "string"), new("Message", "string")],
            [new("TimeGenerated", "datetime"), new("Message", "string")]);

        Assert.True(result.Valid, Messages(result));
        Assert.Contains(result.OutputColumns, x => x.Name == "TimeGenerated" && x.Type == "datetime");
        Assert.Contains("Message", result.ReferencedColumns);
        Assert.Contains("todatetime", result.ReferencedFunctions);
    }

    [Fact]
    public void Transformation_supports_special_functions_and_quoted_source_columns()
    {
        var result = Validate(
            "source | extend TimeGenerated = now(), Parsed = parse_cef_dictionary(['CEF Message']), Geo = geo_location(IP) | project TimeGenerated, Parsed, Geo",
            [new("CEF Message", "string"), new("IP", "string")]);

        Assert.True(result.Valid, Messages(result));
        Assert.Contains(result.OutputColumns, x => x.Name == "Parsed" && x.Type == "dynamic");
        Assert.Contains(result.OutputColumns, x => x.Name == "Geo" && x.Type == "dynamic");
    }

    [Fact]
    public void Unsupported_operator_and_multirow_datatable_are_blocking()
    {
        var summarize = Validate("source | summarize count() | extend TimeGenerated = now()", [new("Message", "string")]);
        var datatable = Validate(
            "datatable(TimeGenerated:datetime)[datetime(2024-01-01), datetime(2024-01-02)]",
            [new("Message", "string")]);

        Assert.Contains(summarize.Diagnostics, x => x.RuleId == "KQLT002" && x.Severity == DiagnosticSeverity.Error);
        Assert.Contains(datatable.Diagnostics, x => x.RuleId == "KQLT001" && x.Severity == DiagnosticSeverity.Error);
    }

    [Fact]
    public void Parse_extraction_boundaries_warn_then_fail()
    {
        var five = Validate(ParseQuery(5), [new("Message", "string")]);
        var six = Validate(ParseQuery(6), [new("Message", "string")]);
        var ten = Validate(ParseQuery(10), [new("Message", "string")]);
        var eleven = Validate(ParseQuery(11), [new("Message", "string")]);

        Assert.DoesNotContain(five.Diagnostics, x => x.RuleId is "KQLP007" or "KQLT004");
        Assert.Contains(six.Diagnostics, x => x.RuleId == "KQLP007");
        Assert.Contains(ten.Diagnostics, x => x.RuleId == "KQLP007");
        Assert.Contains(eleven.Diagnostics, x => x.RuleId == "KQLT004" && x.Severity == DiagnosticSeverity.Error);
        Assert.DoesNotContain(eleven.Diagnostics, x => x.RuleId == "KQLP007");
    }

    [Fact]
    public void Destination_checks_types_and_discarded_columns_but_allow_omissions()
    {
        var result = Validate(
            "source | extend TimeGenerated = now(), Extra = Message | project TimeGenerated, Message, Extra",
            [new("Message", "string")],
            [new("TimeGenerated", "string"), new("Message", "string"), new("Unused", "long")]);

        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLT007" && x.Severity == DiagnosticSeverity.Error);
        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLT008" && x.Severity == DiagnosticSeverity.Warning);
        Assert.DoesNotContain(result.Diagnostics, x => x.Message.Contains("Unused", StringComparison.Ordinal));
    }

    [Fact]
    public void Missing_timestamp_and_malformed_contract_are_rejected_at_the_right_layer()
    {
        var analyzed = Validate("source | project Message", [new("Message", "string")]);
        Assert.Contains(analyzed.Diagnostics, x => x.RuleId == "KQLT006");

        var exception = Assert.Throws<RequestValidationException>(() => Validator.Validate(
            new TransformationValidationRequest("source", []), TestContext.Current.CancellationToken));
        Assert.Equal("sourceColumns", exception.Field);
    }

    [Fact]
    public void Regex_parse_advisory_and_unsupported_string_operator_are_reported()
    {
        var regex = Validate(
            "source | parse kind  =  regex Message with '(.*)' Value:string | extend TimeGenerated = now()",
            [new("Message", "string")]);
        var unsupported = Validate(
            "source | where Message has_any ('a', 'b') | extend TimeGenerated = now()",
            [new("Message", "string")]);

        Assert.Contains(regex.Diagnostics, x => x.RuleId == "KQLT005" && x.Severity == DiagnosticSeverity.Warning);
        Assert.Contains(unsupported.Diagnostics, x => x.RuleId == "KQLT003" && x.Severity == DiagnosticSeverity.Error);
    }

    private static TransformationValidationResponse Validate(
        string query,
        IReadOnlyList<ColumnDeclaration> source,
        IReadOnlyList<ColumnDeclaration>? destination = null) =>
        Validator.Validate(new(query, source, destination), TestContext.Current.CancellationToken);

    private static string ParseQuery(int count) =>
        "source | parse Message with " +
        string.Join(' ', Enumerable.Range(1, count).Select(i => $"' f{i}=' Field{i}:string")) +
        " | extend TimeGenerated = now() | project TimeGenerated";

    private static string Messages(TransformationValidationResponse response) =>
        string.Join(Environment.NewLine, response.Diagnostics.Select(x => $"{x.RuleId}: {x.Message}"));
}
