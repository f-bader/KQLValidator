using System.Diagnostics;
using System.Text.RegularExpressions;
using KqlValidator.Contracts;
using Kusto.Language;
using Kusto.Language.Symbols;
using Kusto.Language.Syntax;

namespace KqlValidator.Validation;

public sealed partial class KqlValidationService(
    SchemaCatalog catalog,
    GlobalStateFactory globalStateFactory,
    RequestValidator requestValidator,
    KqlLinter linter,
    LintRuleCatalog lintRules)
{
    private const int MaxDiagnostics = 500;
    private const int RegexTimeoutMilliseconds = 250;

    public ValidationResponse Validate(ValidateRequest request) => Validate(request, CancellationToken.None);

    public ValidationResponse Validate(ValidateRequest request, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        requestValidator.Validate(request);
        var schema = catalog.Get(request.Environment);
        var globals = globalStateFactory.Create(schema, request.Extensions);
        var normalized = NormalizeFileProfileColumnArguments(request.Query);
        Kusto.Language.Utils.CancellationToken kustoCancellation = cancellationToken;
        var code = KustoCode.ParseAndAnalyze(normalized.Query, globals, kustoCancellation);

        var outputColumns = code.ResultType?.Members.OfType<ColumnSymbol>()
            .GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Select(x => new ColumnDeclaration(x.Key, x.First().Type.Name))
            .ToArray() ?? [];

        cancellationToken.ThrowIfCancellationRequested();
        var fileProfileDiagnostics = ValidateFileProfileColumns(request.Query, code, normalized.Columns, kustoCancellation);
        var references = GatherReferences(code, normalized.Columns.Select(x => x.Name), cancellationToken);
        var lintPolicy = lintRules.CreatePolicy(request);

        var candidates = code.GetDiagnostics(kustoCancellation)
            .Select(diagnostic => new ValidationDiagnostic(
                diagnostic.Code,
                diagnostic.Severity == Kusto.Language.DiagnosticSeverity.Error
                    ? Contracts.DiagnosticSeverity.Error
                    : Contracts.DiagnosticSeverity.Warning,
                diagnostic.Description,
                KqlLinter.Span(request.Query, diagnostic.Start, diagnostic.Length),
                "https://learn.microsoft.com/en-us/kusto/query/",
                diagnostic.Code.StartsWith("KS", StringComparison.Ordinal) ? "syntax" : "semantic"))
            .Concat(fileProfileDiagnostics)
            .Concat(linter.Analyze(request, lintPolicy, cancellationToken))
            .Concat(DetectionOutputDiagnostics(request, outputColumns, references.Tables, schema, lintPolicy))
            .Take(MaxDiagnostics + 1)
            .ToArray();
        var truncated = candidates.Length > MaxDiagnostics;
        var diagnostics = candidates
            .Take(MaxDiagnostics)
            .AppendIf(truncated, new ValidationDiagnostic(
                "KQLV001",
                Contracts.DiagnosticSeverity.Warning,
                $"Diagnostics were truncated after {MaxDiagnostics} results.",
                KqlLinter.Span(request.Query, Math.Max(0, request.Query.Length - 1), 1),
                Category: "service"))
            .OrderBy(x => x.Span.Start)
            .ThenBy(x => x.Severity)
            .ToArray();

        stopwatch.Stop();
        return new ValidationResponse(
            !diagnostics.Any(x => x.Severity == Contracts.DiagnosticSeverity.Error),
            ThisAssembly.Version,
            schema.Version,
            diagnostics,
            outputColumns,
            references.Tables,
            references.Columns,
            references.Functions,
            stopwatch.ElapsedMilliseconds);
    }

    private IEnumerable<ValidationDiagnostic> DetectionOutputDiagnostics(
        ValidateRequest request,
        IReadOnlyList<ColumnDeclaration> outputColumns,
        IReadOnlyList<string> referencedTables,
        EnvironmentSchema schema,
        LintPolicy policy)
    {
        var names = outputColumns.Select(x => x.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!names.Contains("TimeGenerated") && Enabled(policy, "KQLD001"))
            yield return lintRules.CreateDiagnostic(
                request.Query, "KQLD001",
                "Sentinel detection queries must retain TimeGenerated in their output.",
                Math.Max(0, request.Query.Length - 1));

        if (!names.Contains("Timestamp") && !names.Contains("TimeGenerated") && Enabled(policy, "KQLD002"))
            yield return lintRules.CreateDiagnostic(
                request.Query, "KQLD002",
                "Retain Timestamp or TimeGenerated when available so XDR detection results identify event time.",
                Math.Max(0, request.Query.Length - 1));

        if (!names.Contains("Timestamp") && names.Contains("TimeGenerated") && Enabled(policy, "KQLX003"))
            yield return lintRules.CreateDiagnostic(
                request.Query, "KQLX003",
                "TimeGenerated is accepted, but prefer Timestamp for native Defender XDR table output.",
                Math.Max(0, request.Query.Length - 1));

        var reportIdAvailable = referencedTables.Any(table =>
            schema.Tables.TryGetValue(table, out var definition) &&
            definition.Columns.Any(column => column.Name.Equals("ReportId", StringComparison.OrdinalIgnoreCase)) &&
            !table.StartsWith("Device", StringComparison.OrdinalIgnoreCase));
        if (reportIdAvailable && !names.Contains("ReportId") && Enabled(policy, "KQLD003"))
            yield return lintRules.CreateDiagnostic(
                request.Query, "KQLD003",
                "Retain ReportId for this non-endpoint Defender event so the source event can be identified.",
                Math.Max(0, request.Query.Length - 1));

        if (!names.Overlaps(["DeviceId", "DeviceName", "AccountObjectId", "AccountSid", "AccountUpn", "RemoteIP", "IPAddress", "SHA256"]) &&
            Enabled(policy, "KQLD004"))
            yield return lintRules.CreateDiagnostic(
                request.Query, "KQLD004",
                "Retain at least one useful device, account, IP, or file entity column for XDR detection results.",
                Math.Max(0, request.Query.Length - 1));
    }

    private bool Enabled(LintPolicy policy, string ruleId) =>
        policy.IsEnabled(ruleId, lintRules.Get(ruleId).DefaultSeverity);

    private static IReadOnlyList<ValidationDiagnostic> ValidateFileProfileColumns(
        string originalQuery,
        KustoCode code,
        IReadOnlyList<FileProfileColumn> columns,
        Kusto.Language.Utils.CancellationToken cancellationToken)
    {
        var diagnostics = new List<ValidationDiagnostic>();
        foreach (var column in columns)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var scope = code.GetColumnsInScope(column.ScopePosition, cancellationToken);
            var symbol = scope?.Members.OfType<ColumnSymbol>()
                .FirstOrDefault(candidate => candidate.Name.Equals(column.Name, StringComparison.OrdinalIgnoreCase));
            if (symbol?.Type == ScalarTypes.String) continue;

            diagnostics.Add(new ValidationDiagnostic(
                "KS142",
                Contracts.DiagnosticSeverity.Error,
                symbol is null
                    ? $"The name '{column.Name}' does not refer to a column in the FileProfile input."
                    : $"FileProfile column '{column.Name}' has an incompatible type. Expected: string.",
                KqlLinter.Span(originalQuery, column.Position, column.Name.Length),
                "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-fileprofile-function",
                "semantic"));
        }
        return diagnostics;
    }

    private static NormalizedQuery NormalizeFileProfileColumnArguments(string query)
    {
        var columns = new List<FileProfileColumn>();
        var normalized = BareFileProfileColumn().Replace(query, match =>
        {
            var column = match.Groups["column"];
            if (column.Length < 2) return match.Value;
            columns.Add(new FileProfileColumn(column.Value, column.Index, match.Index));
            return match.Groups["prefix"].Value + $"\"{column.Value[1..^1]}\"";
        });
        return new NormalizedQuery(normalized, columns);
    }

    private static References GatherReferences(
        KustoCode code,
        IEnumerable<string> additionalColumns,
        CancellationToken cancellationToken)
    {
        var tables = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var functions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        SyntaxElement.WalkNodes(code.Syntax, node =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            switch (node.ReferencedSymbol)
            {
                case TableSymbol table when code.Globals.IsDatabaseTable(table):
                    tables.Add(table.Name);
                    break;
                case ColumnSymbol column when code.Globals.GetTable(column) is not null:
                    columns.Add(column.Name);
                    break;
                case FunctionSymbol function:
                    functions.Add(function.Name);
                    break;
            }

            if (node is FunctionCallExpression call && call.ReferencedSymbol is FunctionSymbol called)
                functions.Add(called.Name);
        });

        columns.UnionWith(additionalColumns);

        return new References(
            tables.Order(StringComparer.OrdinalIgnoreCase).ToArray(),
            columns.Order(StringComparer.OrdinalIgnoreCase).ToArray(),
            functions.Order(StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private sealed record References(IReadOnlyList<string> Tables, IReadOnlyList<string> Columns, IReadOnlyList<string> Functions);
    private sealed record FileProfileColumn(string Name, int Position, int ScopePosition);
    private sealed record NormalizedQuery(string Query, IReadOnlyList<FileProfileColumn> Columns);

    [GeneratedRegex(@"(?i)(?<prefix>\binvoke\s+FileProfile\s*\(\s*)(?<column>[A-Za-z_]\w*)(?=\s*(?:,|\)))", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex BareFileProfileColumn();
}

internal static class EnumerableExtensions
{
    public static IEnumerable<T> AppendIf<T>(this IEnumerable<T> source, bool condition, T value) =>
        condition ? source.Append(value) : source;
}

internal static class ThisAssembly
{
    public static string Version =>
        typeof(ThisAssembly).Assembly
            .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
            .SingleOrDefault()?.InformationalVersion
        ?? typeof(ThisAssembly).Assembly.GetName().Version?.ToString(3)
        ?? "0.0.0";
}
