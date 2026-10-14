using System.Security.Cryptography;
using System.Text;
using KqlValidator.Contracts;
using KqlValidator.Validation;
using Kusto.Language;
using Kusto.Language.Symbols;
using Kusto.Language.Syntax;

namespace KqlValidator.NrtProbe;

public sealed record ProbeFixture(string Id, string Query, string QueryHash, NrtFeatureUse? Feature, bool? ExpectedStreaming = null);
public sealed record ProbeExclusion(string Kind, string Name, string Reason);
public sealed record ProbeManifest(int Version, string ParserVersion, IReadOnlyList<ProbeFixture> Fixtures, IReadOnlyList<ProbeExclusion> Exclusions);

public static class ProbeInventory
{
    private const string Source = "DeviceProcessEvents";
    private const string Projection = "\n| project Timestamp, DeviceId, ReportId";
    private static readonly HashSet<OperatorKind> NonComparison =
    [OperatorKind.And, OperatorKind.Or, OperatorKind.Add, OperatorKind.Subtract, OperatorKind.Multiply,
        OperatorKind.Divide, OperatorKind.Modulo, OperatorKind.UnaryMinus, OperatorKind.UnaryPlus];

    public static IReadOnlyList<(string Text, OperatorKind Kind)> ComparisonTokens() => Enum.GetValues<SyntaxKind>()
        .Select(kind => (Text: SyntaxFacts.GetText(kind), Kind: SyntaxFacts.GetOperatorKind(kind)))
        .Where(x => x.Kind != OperatorKind.None && !NonComparison.Contains(x.Kind) && !string.IsNullOrEmpty(x.Text))
        .Distinct().OrderBy(x => x.Text, StringComparer.Ordinal).ToArray();

    public static bool ComparisonFunction(string name) => name is "strcmp" or "set_has_element" or "set_equals" ||
        name.StartsWith("ipv4_is_", StringComparison.Ordinal) || name.StartsWith("ipv6_is_", StringComparison.Ordinal) ||
        name is "ipv4_compare" or "ipv6_compare" or "has_ipv4" or "has_ipv4_prefix" or "has_any_ipv4" or "has_any_ipv4_prefix" ||
        name.StartsWith("series_greater", StringComparison.Ordinal) || name.StartsWith("series_less", StringComparison.Ordinal) ||
        name is "series_equals" or "series_not_equals";

    public static ProbeManifest Prepare() => Prepare(followUp: false);

    public static ProbeManifest PrepareFollowUp() => Prepare(followUp: true);

    private static ProbeManifest Prepare(bool followUp)
    {
        var schema = new SchemaCatalog().Get(KqlEnvironment.Xdr);
        var globals = new GlobalStateFactory().Create(schema, null);
        var fixtures = new List<ProbeFixture>();
        var exclusions = new List<ProbeExclusion>();

        void Add(string id, string query, string? kind = null, string? name = null, bool? expected = null)
        {
            var code = KustoCode.ParseAndAnalyze(query, globals);
            var errors = code.GetDiagnostics().Where(d => d.Severity == Kusto.Language.DiagnosticSeverity.Error).ToArray();
            if (errors.Length > 0)
                throw new InvalidDataException($"Fixture {id} failed preflight: {string.Join("; ", errors.Select(d => d.Description))}");
            NrtFeatureUse? feature = null;
            SyntaxElement.WalkNodes(code.Syntax, node =>
            {
                var use = DefenderNrtFeatures.GetUse(node);
                if (use is not null && use.Kind == kind && use.Name == name) feature = use;
            });
            if (kind is not null && feature is null)
                throw new InvalidDataException($"Fixture {id} does not contain its declared feature {name}: {query}");
            fixtures.Add(new(id, query, Hash(query), feature, expected));
        }

        Add("control-positive", Source + "\n| where DeviceName == \"test\"" + Projection, expected: true);
        Add("control-positive-dynamic", Source + "\n| extend __nrtarray = parse_json(AdditionalFields)" + Projection + ", __nrtarray", expected: true);
        Add("control-negative", Source + "\n| join kind=leftouter (DeviceProcessEvents | project DeviceId) on DeviceId" + Projection, expected: false);
        if (followUp)
        {
            Add("control-positive-projection", Source + "\n| extend __nrtprobe = DeviceName == \"test\"" + Projection + ", __nrtprobe", expected: true);
            Add("control-positive-tolower", Source + "\n| extend __nrtlower = tolower(DeviceName)" + Projection + ", __nrtlower", expected: true);
            Add("control-positive-udf", "let matchesTerm = (s:string, term:string) { s == term };\n" + Source + "\n| where matchesTerm(DeviceName, \"test\")" + Projection, expected: true);

            Add("follow-up-has-any-projection", Source + "\n| extend __nrtprobe = DeviceName has_any (\"test\", \"example\")" + Projection + ", __nrtprobe", "operator", "has_any");
            Add("follow-up-in-tilde-projection", Source + "\n| extend __nrtprobe = DeviceName in~ (\"test\", \"example\")" + Projection + ", __nrtprobe", "operator", "in~");
            Add("follow-up-strcmp-predicate", Source + "\n| where strcmp(DeviceName, \"test\") == 0" + Projection, "function", "strcmp");
            Add("follow-up-ipv4-private-predicate", Source + "\n| where ipv4_is_private(DeviceName)" + Projection, "function", "ipv4_is_private");
            Add("follow-up-has-ipv4-predicate", Source + "\n| where has_ipv4(DeviceName, \"10.0.0.1\")" + Projection, "function", "has_ipv4");
            Add("follow-up-set-membership-predicate", Source + "\n| extend __nrtarray = parse_json(AdditionalFields)\n| where set_has_element(__nrtarray, \"test\")" + Projection, "function", "set_has_element");
            Add("follow-up-has-any-computed-left", Source + "\n| where tolower(DeviceName) has_any (\"test\", \"example\")" + Projection, "operator", "has_any");
            Add("follow-up-has-any-string-variable", "let term = \"test\";\n" + Source + "\n| where DeviceName has_any (term)" + Projection, "operator", "has_any");
            Add("follow-up-has-any-mixed-list", "let term = \"test\";\n" + Source + "\n| where DeviceName has_any (term, \"example\")" + Projection, "operator", "has_any");
            Add("follow-up-has-any-variable-list", "let firstTerm = \"test\";\nlet secondTerm = \"example\";\n" + Source + "\n| where DeviceName has_any (firstTerm, secondTerm)" + Projection, "operator", "has_any");
            Add("follow-up-has-any-udf-parameter", "let matchesTerm = (s:string, term:string) { s has_any (term) };\n" + Source + "\n| where matchesTerm(DeviceName, \"test\")" + Projection, "operator", "has_any");
            Add("follow-up-has-any-empty-array", Source + "\n| where DeviceName has_any (dynamic([]))" + Projection, "operator", "has_any");
            return new(1, typeof(KustoCode).Assembly.GetName().Version!.ToString(), fixtures, exclusions);
        }
        Add("issue-50", Source + "\n| where DeviceName has_any (\"test\")", "operator", "has_any");

        var index = 0;
        foreach (var (text, op) in ComparisonTokens())
        {
            var name = DefenderNrtFeatures.CanonicalOperator(text);
            var list = op is OperatorKind.In or OperatorKind.InCs or OperatorKind.NotIn or OperatorKind.NotInCs or OperatorKind.HasAny or OperatorKind.HasAll;
            var range = op is OperatorKind.Between or OperatorKind.NotBetween;
            var ordered = op is OperatorKind.LessThan or OperatorKind.LessThanOrEqual or OperatorKind.GreaterThan or OperatorKind.GreaterThanOrEqual;
            var lhs = range || ordered ? "ReportId" : "DeviceName";
            var rhs = list ? "(\"test\", \"example\")" : range ? "(1 .. 100)" : ordered ? "100" : op == OperatorKind.MatchRegex ? "@'^test\\w*'" : "\"test\"";
            var prefix = $"operator-{++index:D3}";
            Add(prefix + "-literal", Source + $"\n| where {lhs} {text} {rhs}" + Projection, "operator", name);
            if (range)
            {
                Add(prefix + "-variable", "let lower = 1; let upper = 100;\n" + Source + $"\n| where ReportId {text} (lower .. upper)" + Projection, "operator", name);
                Add(prefix + "-datetime", Source + $"\n| where Timestamp {text} (datetime(2026-01-01) .. datetime(2026-01-02))" + Projection, "operator", name);
                continue;
            }
            var variable = list ? "(terms)" : "term";
            var declaration = list ? "let terms = dynamic([\"test\", \"example\"]);\n" : ordered ? "let term = 100;\n" : "let term = \"test\";\n";
            Add(prefix + "-variable", declaration + Source + $"\n| where {lhs} {text} {variable}" + Projection, "operator", name);
            Add(prefix + "-column", Source + $"\n| where {lhs} {text} {(list ? "(FileName)" : ordered ? "ProcessId" : "FileName")}" + Projection, "operator", name);
            if (list)
                Add(prefix + "-dynamic", Source + $"\n| where DeviceName {text} (dynamic([\"test\", \"example\"]))" + Projection, "operator", name);
            if (op is OperatorKind.Equal or OperatorKind.NotEqual or OperatorKind.LessThan or OperatorKind.LessThanOrEqual or OperatorKind.GreaterThan or OperatorKind.GreaterThanOrEqual)
            {
                Add(prefix + "-long", Source + $"\n| where ReportId {text} 100" + Projection, "operator", name);
                Add(prefix + "-datetime", Source + $"\n| where Timestamp {text} datetime(2026-01-01)" + Projection, "operator", name);
            }
        }

        foreach (var function in GlobalState.Default.Functions.Where(f => ComparisonFunction(f.Name)).OrderBy(f => f.Name, StringComparer.Ordinal))
        {
            var name = function.Name;
            var args = name switch
            {
                "strcmp" => "DeviceName, \"test\"",
                "ipv4_is_private" => "DeviceName",
                "ipv4_is_in_range" => "DeviceName, \"10.0.0.0/8\"",
                "ipv6_is_in_range" => "DeviceName, \"2001:db8::/32\"",
                "ipv4_is_in_any_range" => "DeviceName, dynamic([\"10.0.0.0/8\"])",
                "ipv6_is_in_any_range" => "DeviceName, dynamic([\"2001:db8::/32\"])",
                "ipv4_compare" or "ipv4_is_match" or "has_ipv4" => "DeviceName, \"10.0.0.1\"",
                "ipv6_compare" or "ipv6_is_match" => "DeviceName, \"2001:db8::1\"",
                "has_ipv4_prefix" => "DeviceName, \"10.0.\"",
                "has_any_ipv4" => "DeviceName, dynamic([\"10.0.0.1\"])",
                "has_any_ipv4_prefix" => "DeviceName, dynamic([\"10.0.\"])",
                "set_has_element" => "__nrtarray, \"test\"",
                "set_equals" => "__nrtarray, dynamic([\"test\"])",
                _ when name.StartsWith("series_", StringComparison.Ordinal) => "__nrtarray, dynamic([1, 2])",
                _ => throw new InvalidDataException($"Add a comparison fixture for {name}."),
            };
            var source = args.StartsWith("__nrtarray", StringComparison.Ordinal) ? Source + "\n| extend __nrtarray = parse_json(AdditionalFields)" : Source;
            Add("function-" + name, source + $"\n| extend __nrtprobe = {name}({args})" + Projection + ", __nrtprobe", "function", name);
            var comma = args.IndexOf(',');
            if (comma > 0)
            {
                var rhs = args[(comma + 1)..].Trim();
                var lhs = args[..comma];
                Add("function-" + name + "-variable", $"let compare_value = {rhs};\n" + source + $"\n| extend __nrtprobe = {name}({lhs}, compare_value)" + Projection + ", __nrtprobe", "function", name);
                if (lhs == "DeviceName" && rhs.StartsWith('"'))
                    Add("function-" + name + "-column", Source + $"\n| extend __nrtprobe = {name}(DeviceName, FileName)" + Projection + ", __nrtprobe", "function", name);
            }
            if (name is "ipv4_compare" or "ipv4_is_match" or "ipv6_compare" or "ipv6_is_match")
                Add("function-" + name + "-prefix", Source + $"\n| extend __nrtprobe = {name}({args}, 16)" + Projection + ", __nrtprobe", "function", name);
        }

        foreach (var op in GlobalState.Default.Operators)
            if (!ComparisonTokens().Any(t => t.Kind.ToString() == op.Name))
                exclusions.Add(new("operator", op.Name, NonComparison.Any(k => k.ToString() == op.Name)
                    ? "Arithmetic or logical operator; comparison probes cover its predicate operands."
                    : "Search-expression operator; requires a search context outside the single-feature where fixtures."));
        exclusions.Add(new("function", "current_principal_is_member_of", "Session identity function; a constant session result cannot establish row-dependent comparison support."));
        return new(1, typeof(KustoCode).Assembly.GetName().Version!.ToString(), fixtures, exclusions);
    }

    public static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
}
