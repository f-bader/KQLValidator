using KqlValidator.Contracts;
using KqlValidator.Validation;

namespace KqlValidator.Tests;

public sealed class ColumnWildcardTests
{
    private const string Input = "print Keep=0, Name1=1, Other1=2, Name2=3, N1ame=4";
    private readonly KqlValidationService validator;

    public ColumnWildcardTests()
    {
        var catalog = TestSchemaCatalog.Bundled;
        var rules = new LintRuleCatalog();
        validator = new(catalog, new GlobalStateFactory(), new RequestValidator(catalog, rules),
            new KqlLinter(catalog, rules), new DefenderNrtValidator(rules), rules);
    }

    // Expected schemas were checked through Graph advanced hunting on 2026-10-17.
    public static IEnumerable<object[]> RuntimeSelections()
    {
        (string Selection, string Columns)[] cases =
        [
            ("project-away Name*", "Keep,Other1,N1ame"),
            ("project-away *1", "Keep,Name2,N1ame"),
            ("project-away N*1", "Keep,Other1,Name2,N1ame"),
            ("project-away *1*", "Keep,Name2"),
            ("project-keep Name*", "Name1,Name2"),
            ("project-keep *1", "Name1,Other1"),
            ("project-keep N*1", "Name1"),
            ("project-keep *1*", "Name1,Other1,N1ame"),
            ("project-reorder Name*", "Name1,Name2,Keep,Other1,N1ame"),
            ("project-reorder *1", "Name1,Other1,Keep,Name2,N1ame"),
            ("project-reorder N*1", "Name1,Keep,Other1,Name2,N1ame"),
            ("project-reorder *1*", "Name1,Other1,N1ame,Keep,Name2"),
            ("project-reorder *1 desc", "Other1,Name1,Keep,Name2,N1ame"),
            ("project-by-names \"Name*\"", "Name1,Name2"),
            ("project-by-names \"*1\"", "Name1,Other1"),
            ("project-by-names \"N*1\"", "Name1"),
            ("project-by-names \"*1*\"", "Name1,Other1,N1ame"),
            ("project-away Missing*", "Keep,Name1,Other1,Name2,N1ame"),
            ("project-away *9", "Keep,Name1,Other1,Name2,N1ame"),
            ("project-away Missing*, Name1", "Keep,Other1,Name2,N1ame"),
            ("project-keep Keep, Missing*", "Keep"),
            ("project-keep Missing*, Keep", "Keep"),
            ("project-reorder Missing*", "Keep,Name1,Other1,Name2,N1ame"),
            ("project-reorder *9", "Keep,Name1,Other1,Name2,N1ame"),
            ("project-reorder Missing*, Name1", "Name1,Keep,Other1,Name2,N1ame"),
            ("project-by-names \"Missing*\", \"Keep\"", "Keep"),
            ("project-by-names \"Missing\", \"Keep\"", "Keep"),
            ("project-by-names dynamic([\"*1\", \"Keep\", \"Missing\"])", "Name1,Other1,Keep"),
        ];
        foreach (var environment in Enum.GetValues<KqlEnvironment>())
            foreach (var (selection, columns) in cases)
                yield return [environment, selection, columns];
    }

    [Theory]
    [MemberData(nameof(RuntimeSelections))]
    public void Selections_match_runtime_schemas(KqlEnvironment environment, string selection, string expected)
    {
        var result = Validate($"{Input} | {selection}", environment);
        Assert.True(result.Valid, Messages(result));
        Assert.Empty(result.Diagnostics);
        Assert.Equal(expected.Split(','), result.OutputColumns.Select(column => column.Name));
        Assert.All(result.OutputColumns, column => Assert.Equal("long", column.Type));
    }

    [Theory]
    [InlineData("project-away Missing")]
    [InlineData("project-keep Missing")]
    [InlineData("project-reorder Missing")]
    [InlineData("project-away ['Missing*']")]
    [InlineData("project-away Missing*, Missing")]
    [InlineData("project-away Missing*, | take 1")]
    [InlineData("project-reorder Missing*, | take 1")]
    [InlineData("project-by-names *1")]
    public void Missing_literal_names_and_malformed_selections_remain_invalid(string selection)
    {
        Assert.False(Validate($"{Input} | {selection}").Valid);
    }

    [Theory]
    [InlineData("project-keep Missing*")]
    [InlineData("project-keep *9")]
    [InlineData("project-keep Missing* | count")]
    [InlineData("project-by-names \"Missing*\"")]
    [InlineData("project-by-names \"Missing\"")]
    [InlineData("project-by-names dynamic([\"Missing*\"])")]
    [InlineData("project-by-names \"Missing*\" | count")]
    [InlineData("project-away *")]
    public void Projections_must_retain_a_column_even_before_count(string selection)
    {
        var result = Validate($"{Input} | {selection}");
        Assert.False(result.Valid);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.RuleId == "KQLV003" && diagnostic.Category == "semantic");
    }

    [Theory]
    [InlineData("project-away Missing*, Keep, Unknown*, Name1, Absent*")]
    [InlineData("project-reorder Missing* desc, Keep, Unknown* asc, Name1, Absent*")]
    [InlineData("project-keep Missing*, Keep, Unknown*, Name1, Absent*")]
    public void Multiple_unmatched_selections_preserve_valid_selections(string selection)
    {
        var result = Validate($"print Keep=0, Name1=1 | {selection}");
        if (selection.StartsWith("project-away", StringComparison.Ordinal))
            Assert.Contains(result.Diagnostics, diagnostic => diagnostic.RuleId == "KQLV003");
        else
        {
            Assert.True(result.Valid, Messages(result));
            Assert.Equal(new[] { "Keep", "Name1" }, result.OutputColumns.Select(column => column.Name));
        }
    }

    [Fact]
    public void Unmatched_suffix_is_ignored_on_a_real_table_schema()
    {
        var result = Validate("DeviceInfo | take 0 | project-away *1");
        Assert.True(result.Valid, Messages(result));
        Assert.Contains(result.OutputColumns, column => column.Name == "DeviceId");
    }

    [Fact]
    public void Join_suffix_cleanup_retains_original_columns()
    {
        var result = Validate("(print Key=1, Value=2) | join kind=inner (print Key=1, Value=3) on Key | project-away *1");
        Assert.True(result.Valid, Messages(result));
        Assert.Equal(new[] { "Key", "Value" }, result.OutputColumns.Select(column => column.Name));
    }

    [Theory]
    [InlineData("print Keep=0 | project-away *1 | project Missing")]
    [InlineData("print Keep=0 | project-reorder Missing* | project ['Missing*']")]
    [InlineData("print Keep=0 | project-reorder Missing* | project-keep Missing*, Keep | project ['Missing*']")]
    public void Downstream_binding_uses_corrected_schema(string query)
    {
        var result = Validate(query);
        Assert.False(result.Valid);
        var diagnostic = Assert.Single(result.Diagnostics, diagnostic => diagnostic.RuleId == "KS142");
        Assert.Equal(query.LastIndexOf("Missing", StringComparison.Ordinal) - (query.EndsWith("']", StringComparison.Ordinal) ? 2 : 0), diagnostic.Span.Start);
    }

    [Fact]
    public void Source_spans_preserve_comments_crlf_and_removed_selections()
    {
        const string query = "print Keep=0\r\n| project-reorder Missing* desc, // comment\r\n Keep, Other*\r\n| project Absent";
        var result = Validate(query);
        var diagnostic = Assert.Single(result.Diagnostics, diagnostic => diagnostic.RuleId == "KS142");
        Assert.Equal(query.IndexOf("Absent", StringComparison.Ordinal), diagnostic.Span.Start);
        Assert.Equal(4, diagnostic.Span.Line);
        Assert.Equal(11, diagnostic.Span.Column);
    }

    [Theory]
    [InlineData("let f=(){print Keep=0 | project-reorder Missing*}; f() | project Keep")]
    [InlineData("let f=(T:(*), names:dynamic){T | project-by-names names}; print Keep=0 | invoke f(dynamic(['Keep']))")]
    public void Local_function_schemas_remain_usable(string query)
    {
        var result = Validate(query);
        Assert.True(result.Valid, Messages(result));
        Assert.Equal("Keep", Assert.Single(result.OutputColumns).Name);
    }

    [Theory]
    [InlineData("project-away Name*", "Keep")]
    [InlineData("project-keep Name*", "Name1")]
    [InlineData("project-reorder Name*", "Name1,Keep")]
    public void Generic_function_selectors_preserve_invocation_schemas(string selection, string expected)
    {
        var result = Validate($"let f=(T:(*)){{T | {selection}}}; print Keep=0, Name1=1 | invoke f()");
        // Kusto still reports unresolved names in the generic declaration. Preserve its
        // invocation schema and avoid an additional empty-selection error on that declaration.
        Assert.Equal(expected.Split(','), result.OutputColumns.Select(column => column.Name));
        Assert.DoesNotContain(result.Diagnostics, diagnostic => diagnostic.RuleId == "KQLV003");
    }

    [Theory]
    [InlineData("let f=(T:(*)){let g=(){T | project-away Name*}; g()}; print Keep=0, Name1=1 | invoke f()", "Keep")]
    [InlineData("let f=(T:(Keep:long)){let g=(){T | project-away Keep}; g()}; print Keep=0, Name1=1 | invoke f()", "Name1")]
    public void Nested_functions_preserve_captured_tabular_schemas(string query, string expected)
    {
        var result = Validate(query);
        Assert.Equal(expected, Assert.Single(result.OutputColumns).Name);
        Assert.DoesNotContain(result.Diagnostics, diagnostic => diagnostic.RuleId == "KQLV003");
    }

    [Theory]
    [InlineData("let f=(T:(*)){T | project-away *}; print Keep=0 | invoke f() | count")]
    [InlineData("let f=(T:(*), names:dynamic){T | project-by-names names}; print Keep=0 | invoke f(dynamic(['Missing'])) | count")]
    public void Invocation_expansions_report_empty_intermediate_projections(string query)
    {
        var result = Validate(query);
        Assert.False(result.Valid);
        var diagnostic = Assert.Single(result.Diagnostics, diagnostic => diagnostic.RuleId == "KQLV003");
        Assert.Equal(query.IndexOf("project-", StringComparison.Ordinal), diagnostic.Span.Start);
    }

    [Fact]
    public void Chained_reorders_do_not_propagate_phantom_columns()
    {
        var query = "print Keep=0" + string.Concat(Enumerable.Repeat(" | project-reorder Missing*", 200)) + " | project Keep";
        var result = Validate(query);
        Assert.True(result.Valid, Messages(result));
        Assert.Equal("Keep", Assert.Single(result.OutputColumns).Name);
    }

    [Fact]
    public void Real_column_names_containing_asterisks_remain_selectable()
    {
        var result = Validate("print Keep=0, ['Missing*']=1 | project-reorder Missing* | project-keep Missing*");
        Assert.True(result.Valid, Messages(result));
        Assert.Equal("Missing*", Assert.Single(result.OutputColumns).Name);
    }

    [Fact]
    public void Lint_can_be_disabled_without_disabling_projection_checks()
    {
        var result = validator.Validate(new ValidateRequest($"{Input} | project-away *", KqlEnvironment.Sentinel,
            LintProfile.General, Lint: new LintOptions(Enabled: false)), TestContext.Current.CancellationToken);
        Assert.False(result.Valid);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.RuleId == "KQLV003");
    }

    private ValidationResponse Validate(string query, KqlEnvironment environment = KqlEnvironment.Xdr) =>
        validator.Validate(new ValidateRequest(query, environment, LintProfile.General), TestContext.Current.CancellationToken);

    private static string Messages(ValidationResponse result) =>
        string.Join("; ", result.Diagnostics.Select(diagnostic => diagnostic.Message));
}
