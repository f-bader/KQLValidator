using KqlValidator.Contracts;
using KqlValidator.Validation;

namespace KqlValidator.Tests;

public sealed class SemanticLintTests
{
    private readonly KqlValidationService validator;

    public SemanticLintTests()
    {
        var catalog = TestSchemaCatalog.Bundled;
        var rules = new LintRuleCatalog();
        validator = new(catalog, new GlobalStateFactory(), new RequestValidator(catalog, rules), new KqlLinter(catalog, rules), new DefenderNrtValidator(rules), rules);
    }

    private ValidationResponse Check(string query, string rule, LintProfile profile = LintProfile.Hunting, KqlEnvironment environment = KqlEnvironment.Xdr,
        KqlTarget? target = null, bool enabled = true, DiagnosticSeverity? minimum = null) => validator.Validate(
        new(query, environment, profile, Target: target,
            Lint: new(EnableRules: enabled ? [rule] : [], DisableRules: enabled ? [] : [rule], MinimumSeverity: minimum)),
        TestContext.Current.CancellationToken);

    [Theory]
    [InlineData("DeviceEvents | where ActionType has 'ab'", "KQLH006")]
    [InlineData("DeviceEvents | where ActionType has_any ('a', 'abc')", "KQLH006")]
    [InlineData("DeviceEvents | where ActionType hasprefix 'ab'", "KQLH006")]
    [InlineData("DeviceEvents | where 'abc' == tolower(ActionType)", "KQLH004")]
    [InlineData("DeviceEvents | where '' == ActionType", "KQLP005")]
    [InlineData("DeviceEvents | summarize count_distinct(ActionType)", "KQLP008")]
    [InlineData("DeviceEvents | summarize make_set(ActionType)", "KQLP009")]
    [InlineData("DeviceEvents | summarize make_list_if(ActionType, ReportId > 0)", "KQLP009")]
    [InlineData("DeviceEvents | where ActionType matches regex 'ProcessCreated'", "KQLP010")]
    [InlineData("DeviceEvents | where ReportId == long(null)", "KQLP011")]
    [InlineData("DeviceEvents | where long(null) == ReportId", "KQLP011")]
    [InlineData("DeviceEvents | where isnull(ActionType)", "KQLP011")]
    [InlineData("DeviceEvents | extend j=parse_json(AdditionalFields) | project parse_json(j.Nested).Field", "KQLP012")]
    [InlineData("DeviceEvents | extend j=parse_json(AdditionalFields) | extend n=j.Nested | project parse_json(n).Field", "KQLP012")]
    [InlineData("DeviceEvents | extend j=parse_json(AdditionalFields) | project parse_json(j.Nested.Inner).Field", "KQLP012")]
    [InlineData("DeviceEvents | where ActionType in~ ('ÅNGSTRÖM')", "KQLP015")]
    [InlineData("DeviceEvents | where ActionType in~ (dynamic(['𐐀']))", "KQLP015")]
    [InlineData("DeviceEvents | where ActionType !in~ ('ÅNGSTRÖM')", "KQLP015")]
    [InlineData("DeviceEvents | where DeviceId in (DeviceInfo | project DeviceName, DeviceId)", "KQLP016")]
    [InlineData("DeviceEvents | where ActionType has_any (DeviceInfo | project DeviceName, DeviceId)", "KQLP016")]
    [InlineData("let r=rand(); DeviceEvents | extend X=r, Y=r", "KQLP017")]
    [InlineData("let s=DeviceEvents | extend Random=rand(); s | join kind=inner (s) on DeviceId", "KQLP017")]
    [InlineData("DeviceEvents | sample 10 | as s | join kind=inner (s) on DeviceId | join kind=inner (s) on DeviceId", "KQLP017")]
    [InlineData("DeviceEvents | sample 10 | as s | join kind=inner (s) on DeviceId", "KQLP017")]
    [InlineData("let s=DeviceEvents | sample 10; s | join kind=inner (s) on DeviceId", "KQLP017")]
    [InlineData("let s=DeviceEvents | take 10; s | join kind=inner (s) on DeviceId", "KQLP017")]
    [InlineData("DeviceEvents | join kind=leftsemi (DeviceInfo) on DeviceId", "KQLP018")]
    public void Bound_patterns_emit_advisories(string query, string rule)
    {
        var result = Check(query, rule);
        Assert.True(result.Valid, string.Join('\n', result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error).Select(d => d.Message)));
        var diagnostic = Assert.Single(result.Diagnostics, d => d.RuleId == rule);
        Assert.InRange(diagnostic.Span.Start, 0, query.Length - 1);
        Assert.InRange(diagnostic.Span.Length, 1, query.Length - diagnostic.Span.Start);
        Assert.NotNull(diagnostic.DocumentationUrl);
    }

    [Theory]
    [InlineData("let isnull=(s:string){ s == '' }; DeviceEvents | where isnull(ActionType)", "KQLP011")]
    [InlineData("let tolower=(s:string){ s }; DeviceEvents | where tolower(ActionType) == 'abc'", "KQLH004")]
    [InlineData("let rand=(){ 1.0 }; let r=rand(); DeviceEvents | extend X=r,Y=r", "KQLP017")]
    public void Bound_builtin_precedence_is_preserved(string query, string rule)
    {
        Assert.Contains(Check(query, rule).Diagnostics, d => d.RuleId == rule);
    }

    [Theory]
    [InlineData("DeviceEvents | where ActionType has 'abc'", "KQLH006")]
    [InlineData("DeviceEvents | where ActionType has_any ('abc', 'abcd')", "KQLH006")]
    [InlineData("DeviceEvents | where ActionType hasprefix 'abc'", "KQLH006")]
    [InlineData("let count_distinct=(s:string){ 1 }; DeviceEvents | extend x=count_distinct(ActionType)", "KQLP008")]
    [InlineData("let s=DeviceEvents | sample 10 | as hint.materialized=true S; s | join kind=inner (s) on DeviceId", "KQLP017")]
    [InlineData("DeviceEvents | where ActionType == 'ab'", "KQLH006")]
    [InlineData("DeviceEvents | where ActionType contains 'ab'", "KQLH006")]
    [InlineData("DeviceEvents | where ActionType == ' '", "KQLP005")]
    [InlineData("DeviceEvents | where ActionType == '\\t'", "KQLP005")]
    [InlineData("DeviceEvents | where ReportId == 0", "KQLP005")]
    [InlineData("DeviceEvents | summarize make_set(ActionType, 100)", "KQLP009")]
    [InlineData("DeviceEvents | summarize make_list_if(ActionType, ReportId > 0, 100)", "KQLP009")]
    [InlineData("DeviceEvents | where ActionType matches regex '^ProcessCreated$'", "KQLP010")]
    [InlineData("DeviceEvents | where ActionType matches regex 'cmd.exe'", "KQLP010")]
    [InlineData("DeviceEvents | where ReportId != long(null)", "KQLP011")]
    [InlineData("DeviceEvents | where isnull(ReportId)", "KQLP011")]
    [InlineData("DeviceEvents | extend j=parse_json(AdditionalFields) | project parse_json(tostring(j.Nested)).Field", "KQLP012")]
    [InlineData("DeviceEvents | where ActionType in~ ('ASCII')", "KQLP015")]
    [InlineData("DeviceEvents | where DeviceId in (DeviceInfo | project DeviceId)", "KQLP016")]
    [InlineData("let s=materialize(DeviceEvents | sample 10); s | join kind=inner (s) on DeviceId", "KQLP017")]
    [InlineData("let r=toscalar(print rand()); DeviceEvents | extend X=r, Y=r", "KQLP017")]
    [InlineData("DeviceEvents | sample 10 | as hint.materialized=true s | join kind=inner (s) on DeviceId | join kind=inner (s) on DeviceId", "KQLP017")]
    [InlineData("let s=DeviceEvents | sort by Timestamp asc | take 10; s | join kind=inner (s) on DeviceId", "KQLP017")]
    [InlineData("DeviceEvents | join kind=leftsemi (DeviceInfo) on DeviceId, DeviceName", "KQLP018")]
    [InlineData("DeviceEvents | join kind=leftsemi hint.strategy=broadcast (DeviceInfo) on DeviceId", "KQLP018")]
    public void Valid_counterexamples_do_not_emit(string query, string rule)
    {
        var result = Check(query, rule);
        Assert.True(result.Valid, string.Join('\n', result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error).Select(d => d.Message)));
        Assert.DoesNotContain(result.Diagnostics, d => d.RuleId == rule);
    }

    [Theory]
    [InlineData("DeviceEvents | project Timestamp, DeviceName", "KQLD003")]
    [InlineData("let f=(){ DeviceEvents }; f() | project Timestamp, DeviceName", "KQLD003")]
    [InlineData("let s=materialize(DeviceEvents); s | project Timestamp, DeviceName", "KQLD003")]
    [InlineData("let f=(T:(*)){ DeviceEvents }; EmailEvents | invoke f() | project Timestamp, DeviceName", "KQLD003")]
    [InlineData("let f=(T:(*)){ T }; DeviceEvents | invoke f() | project Timestamp, DeviceName", "KQLD003")]
    [InlineData("let f=(){ EmailEvents }; f() | project Timestamp, RecipientEmailAddress", "KQLD003")]
    [InlineData("let f=(T:(Timestamp:datetime,ReportId:long,DeviceId:string)){ T }; f(DeviceEvents) | project Timestamp, DeviceName='example'", "KQLD003")]
    [InlineData("DeviceEvents | project Timestamp, ReportId", "KQLD003")]
    [InlineData("DeviceEvents | project Timestamp, SHA256=tostring(AdditionalFields)", "KQLD004")]
    [InlineData("DeviceEvents | summarize Timestamp=max(Timestamp), ReportId=take_any(ReportId) by DeviceId", "KQLD009")]
    [InlineData("DeviceEvents | summarize Timestamp=min(Timestamp), ReportId=take_any(ReportId) by DeviceId", "KQLD009")]
    [InlineData("DeviceEvents | extend T=Timestamp, R=ReportId | summarize t=max(T), r=take_any(R) by DeviceId | project Timestamp=t, ReportId=r, DeviceId", "KQLD009")]
    [InlineData("DeviceEvents | summarize Timestamp=max(Timestamp), ReportId=max(ReportId) by DeviceId", "KQLD009")]
    [InlineData("DeviceEvents | join kind=inner (DeviceNetworkEvents) on $left.ReportId == $right.RemotePort", "KQLQ005")]
    [InlineData("DeviceEvents | summarize Timestamp=take_any(Timestamp), ReportId=take_any(ReportId) by DeviceId", "KQLD009")]
    [InlineData("DeviceProcessEvents | where FolderPath == @'C:\\Windows'", "KQLD007")]
    [InlineData("DeviceProcessEvents | where FolderPath startswith @'C:\\' and FileName == 'cmd.exe'", "KQLD007")]
    [InlineData("DeviceEvents | join kind=inner (DeviceNetworkEvents) on ActionType", "KQLH015")]
    [InlineData("DeviceEvents | join kind=inner (DeviceNetworkEvents) on DeviceId", "KQLQ005")]
    [InlineData("DeviceEvents | join kind=inner (DeviceNetworkEvents) on DeviceId | where abs(Timestamp-Timestamp1) > 10m", "KQLQ005")]
    [InlineData("DeviceEvents | join kind=inner (DeviceNetworkEvents) on ReportId", "KQLQ005")]
    [InlineData("DeviceEvents | join kind=inner (DeviceNetworkEvents) on DeviceId | where Timestamp > Timestamp1", "KQLQ005")]
    public void Detection_patterns_emit(string query, string rule)
    {
        var result = Check(query, rule, LintProfile.Detection);
        Assert.True(result.Valid, string.Join('\n', result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error).Select(d => d.Message)));
        Assert.Contains(result.Diagnostics, d => d.RuleId == rule);
    }

    [Theory]
    [InlineData("DeviceEvents | project Timestamp, DeviceId, ReportId", "KQLD003")]
    [InlineData("let unused=DeviceEvents; print Timestamp=now(), DeviceName='example'", "KQLD003")]
    [InlineData("let unused=(){ DeviceEvents }; EmailEvents | project Timestamp, ReportId, RecipientEmailAddress", "KQLD003")]
    [InlineData("let f=(T:(*)){ EmailEvents }; DeviceEvents | invoke f() | project Timestamp, ReportId, RecipientEmailAddress", "KQLD003")]
    [InlineData("let n=toscalar(DeviceEvents | count); EmailEvents | where n>0 | project Timestamp, ReportId, RecipientEmailAddress", "KQLD003")]
    [InlineData("EmailEvents | where RecipientEmailAddress in (DeviceEvents | project DeviceName) | project Timestamp, ReportId, RecipientEmailAddress", "KQLD003")]
    [InlineData("EmailEvents | join kind=leftsemi (DeviceEvents) on $left.RecipientEmailAddress == $right.DeviceName | project Timestamp, ReportId, RecipientEmailAddress", "KQLD003")]
    [InlineData("EmailEvents | project Timestamp, RecipientEmailAddress", "KQLD004")]
    [InlineData("DeviceEvents | summarize arg_max(Timestamp, ReportId) by DeviceId", "KQLD009")]
    [InlineData("DeviceEvents | summarize arg_max(Timestamp,*), Latest=max(Timestamp), AnyReport=take_any(ReportId) by DeviceId", "KQLD009")]
    [InlineData("DeviceEvents | summarize A=max(Timestamp), B=take_any(ReportId) by DeviceId | project Timestamp=now(), ReportId=1, DeviceId, A, B", "KQLD009")]
    [InlineData("DeviceEvents | summarize take_any(Timestamp, ReportId) by DeviceId", "KQLD009")]
    [InlineData("DeviceEvents | summarize T=max(Timestamp), ReportId=take_any(ReportId) by DeviceId, Timestamp", "KQLD009")]
    [InlineData("let s=materialize(DeviceEvents | summarize count() by ActionType); s | join kind=inner (DeviceNetworkEvents) on ActionType", "KQLH015")]
    [InlineData("let s=materialize(DeviceEvents | summarize count() by DeviceId, Timestamp); s | join kind=inner (DeviceNetworkEvents) on DeviceId", "KQLQ005")]
    [InlineData("DeviceEvents | summarize Timestamp=max(Timestamp), ReportId=take_any(ReportId) by DeviceId | project DeviceId", "KQLD009")]
    [InlineData("DeviceProcessEvents | where FileName == 'cmd.exe'", "KQLD007")]
    [InlineData("DeviceProcessEvents | where FolderPath == '/usr/bin'", "KQLD007")]
    [InlineData("DeviceProcessEvents | where FolderPath startswith @'C:\\' or FileName == 'cmd.exe'", "KQLD007")]
    [InlineData("DeviceEvents | join kind=inner (DeviceNetworkEvents) on ActionType, DeviceId", "KQLH015")]
    [InlineData("DeviceEvents | join kind=leftsemi (DeviceNetworkEvents) on ActionType", "KQLH015")]
    [InlineData("DeviceEvents | join kind=inner (DeviceInfo) on DeviceId", "KQLQ005")]
    [InlineData("DeviceEvents | join kind=inner (DeviceNetworkEvents) on DeviceId | where abs(Timestamp-Timestamp1) <= 10m", "KQLQ005")]
    [InlineData("DeviceEvents | join kind=inner (DeviceNetworkEvents) on DeviceId | where abs(datetime_diff('minute', Timestamp, Timestamp1)) <= 10", "KQLQ005")]
    [InlineData("DeviceEvents | join kind=inner (DeviceNetworkEvents) on DeviceId | where Timestamp between (Timestamp1-10m .. Timestamp1+10m)", "KQLQ005")]
    [InlineData("DeviceEvents | join kind=inner (DeviceNetworkEvents) on DeviceId, ReportId", "KQLQ005")]
    [InlineData("DeviceEvents | join kind=inner (DeviceNetworkEvents) on DeviceId | where Timestamp >= Timestamp1-10m and Timestamp <= Timestamp1+10m", "KQLQ005")]
    [InlineData("DeviceEvents | join kind=inner (DeviceNetworkEvents) on DeviceId | extend Delta=Timestamp-Timestamp1 | where Delta between (-10m .. 10m)", "KQLQ005")]
    [InlineData("DeviceEvents | join kind=inner (DeviceNetworkEvents) on DeviceId | where Timestamp >= Timestamp1-10m | where Timestamp <= Timestamp1+10m", "KQLQ005")]
    public void Detection_counterexamples_do_not_emit(string query, string rule)
    {
        var result = Check(query, rule, LintProfile.Detection);
        Assert.True(result.Valid, string.Join('\n', result.Diagnostics.Where(d => d.Severity == DiagnosticSeverity.Error).Select(d => d.Message)));
        Assert.DoesNotContain(result.Diagnostics, d => d.RuleId == rule);
    }

    private static string Base36(int value)
    {
        const string digits = "0123456789abcdefghijklmnopqrstuvwxyz";
        return new string([digits[value / 1296], digits[value / 36 % 36], digits[value % 36]]);
    }

    [Theory]
    [InlineData(128, false)]
    [InlineData(129, true)]
    public void Search_index_boundary_and_let_arrays(int count, bool expected)
    {
        var query = "let terms=dynamic([" + string.Join(',', Enumerable.Range(0, count).Select(i => $"'term{i}'")) + "]); DeviceEvents | where ActionType has_any(terms)";
        Assert.Equal(expected, Check(query, "KQLP013").Diagnostics.Any(d => d.RuleId == "KQLP013"));
    }

    [Theory]
    [InlineData(10_000, false)]
    [InlineData(10_001, true)]
    public void Has_any_distinct_limit(int count, bool expected)
    {
        var query = "DeviceEvents | where ActionType has_any (dynamic([" + string.Join(',', Enumerable.Range(0, count).Select(i => $"'{Base36(i)}'")) + "]))";
        var result = Check(query, "KQLP014");
        Assert.Equal(expected, result.Diagnostics.Any(d => d.RuleId == "KQLP014"));
        if (expected) Assert.DoesNotContain(result.Diagnostics, d => d.RuleId == "KQLP013");
    }

    [Fact]
    public void Distinct_limit_deduplicates_literals()
    {
        var query = "DeviceEvents | where ActionType has_any(dynamic([" + string.Join(',', Enumerable.Repeat("'same'", 10_001)) + "]))";
        // Stay below the API's 65,536-character query cap.
        query = query.Replace("'same'", "'x'", StringComparison.Ordinal);
        Assert.DoesNotContain(Check(query, "KQLP014").Diagnostics, d => d.RuleId == "KQLP014");
    }

    [Theory]
    [InlineData(10, false)]
    [InlineData(11, true)]
    public void Indicator_heuristic_boundary(int count, bool expected)
    {
        var query = "DeviceNetworkEvents | where RemoteIP in (" + string.Join(',', Enumerable.Range(1, count).Select(i => $"'192.0.2.{i}'")) + ")";
        Assert.Equal(expected, Check(query, "KQLD008", LintProfile.Detection).Diagnostics.Any(d => d.RuleId == "KQLD008"));
    }

    [Fact]
    public void Opt_in_rules_and_array_bounds_are_not_default()
    {
        var result = validator.Validate(new("DeviceEvents | summarize make_set(ActionType)", KqlEnvironment.Xdr, LintProfile.Hunting), TestContext.Current.CancellationToken);
        Assert.DoesNotContain(result.Diagnostics, d => d.RuleId == "KQLP009");
        result = validator.Validate(new("DeviceEvents | join kind=inner (DeviceNetworkEvents) on ActionType", KqlEnvironment.Xdr, LintProfile.Detection), TestContext.Current.CancellationToken);
        Assert.DoesNotContain(result.Diagnostics, d => d.RuleId is "KQLH015" or "KQLQ005");
    }

    [Fact]
    public void Informational_rules_respect_filtering_and_disabling()
    {
        const string query = "DeviceEvents | summarize count_distinct(ActionType)";
        Assert.DoesNotContain(Check(query, "KQLP008", minimum: DiagnosticSeverity.Warning).Diagnostics, d => d.RuleId == "KQLP008");
        Assert.DoesNotContain(Check(query, "KQLP008", enabled: false).Diagnostics, d => d.RuleId == "KQLP008");
    }

    [Fact]
    public void Unicode_normalization_does_not_get_conflicting_case_advice()
    {
        var result = Check("DeviceEvents | where tolower(ActionType) in ('ångström')", "KQLH004");
        Assert.DoesNotContain(result.Diagnostics, d => d.RuleId == "KQLH004");
    }

    [Fact]
    public void Static_nested_encoded_json_upgrades_to_warning()
    {
        const string query = """let payload=@'{"Nested":"{\"Field\":1}"}'; print parse_json(parse_json(payload).Nested).Field""";
        var diagnostic = Assert.Single(Check(query, "KQLP012", minimum: DiagnosticSeverity.Warning).Diagnostics, d => d.RuleId == "KQLP012");
        Assert.Equal(DiagnosticSeverity.Warning, diagnostic.Severity);
    }

    [Fact]
    public void Query_text_in_comments_and_strings_is_not_analyzed()
    {
        var result = Check("DeviceEvents | project Text='count_distinct(x) matches regex literal', ActionType // where ReportId == long(null)", "KQLP008");
        Assert.DoesNotContain(result.Diagnostics, d => d.RuleId is "KQLP008" or "KQLP010" or "KQLP011");
    }

    [Fact]
    public void Nrt_indicator_advice_avoids_unsupported_sources()
    {
        var query = "DeviceNetworkEvents | where RemoteIP in (" + string.Join(',', Enumerable.Range(1, 11).Select(i => $"'192.0.2.{i}'")) + ")";
        var diagnostic = Assert.Single(Check(query, "KQLD008", LintProfile.Detection, target: KqlTarget.DefenderNrt).Diagnostics, d => d.RuleId == "KQLD008");
        Assert.Contains("does not support", diagnostic.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("watchlist", diagnostic.Message, StringComparison.OrdinalIgnoreCase);
    }
}
