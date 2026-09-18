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
    DefenderNrtValidator defenderNrtValidator,
    LintRuleCatalog lintRules)
{
    private const int MaxDiagnostics = 500;
    private const int RegexTimeoutMilliseconds = 250;

    public ValidationResponse Validate(ValidateRequest request, CancellationToken cancellationToken = default)
    {
        try
        {
            return ValidateCore(request, cancellationToken);
        }
        catch (RegexMatchTimeoutException)
        {
            throw new RequestValidationException("query", "Query exceeds the static analysis complexity limit.");
        }
    }

    private ValidationResponse ValidateCore(ValidateRequest request, CancellationToken cancellationToken)
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
        var watchlistPipelines = CollectWatchlistPipelines(normalized.Query);

        var candidates = code.GetDiagnostics(kustoCancellation)
            .Select(diagnostic => new ValidationDiagnostic(
                diagnostic.Code,
                diagnostic.Severity == Kusto.Language.DiagnosticSeverity.Error
                    ? Contracts.DiagnosticSeverity.Error
                    : Contracts.DiagnosticSeverity.Warning,
                DiagnosticGuidance(watchlistPipelines, diagnostic.Code, diagnostic.Start, diagnostic.Description),
                KqlLinter.Span(request.Query, diagnostic.Start, diagnostic.Length),
                "https://learn.microsoft.com/en-us/kusto/query/",
                diagnostic.Code.StartsWith("KS", StringComparison.Ordinal) ? "syntax" : "semantic"))
            .Concat(fileProfileDiagnostics)
            .Concat(linter.Analyze(request, lintPolicy, code, cancellationToken))
            .Concat(defenderNrtValidator.Analyze(request, lintPolicy, references.Tables, references.Columns, cancellationToken))
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
                "Sentinel scheduled and NRT detections must retain TimeGenerated in the final output; filtering on it alone is insufficient. Add it to the final projection, for example: | project TimeGenerated, AlertName, AccountCustomEntity.",
                Math.Max(0, request.Query.Length - 1));

        if (!names.Contains("Timestamp") && !names.Contains("TimeGenerated") && Enabled(policy, "KQLD002"))
            yield return lintRules.CreateDiagnostic(
                request.Query, "KQLD002",
                "Defender detections must retain Timestamp or TimeGenerated in the final output so each result has an event time. Add one to the final projection, for example: | project Timestamp, DeviceId, ReportId.",
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
                "This non-endpoint Defender event exposes ReportId, but the final output drops it. Retain it so the source event can be identified, for example: | project Timestamp, ReportId, DeviceId.",
                Math.Max(0, request.Query.Length - 1));

        if (!names.Overlaps(["DeviceId", "DeviceName", "AccountObjectId", "AccountSid", "AccountUpn", "RemoteIP", "IPAddress", "SHA256"]) &&
            Enabled(policy, "KQLD004"))
            yield return lintRules.CreateDiagnostic(
                request.Query, "KQLD004",
                "Defender detection output has no strong entity column. Retain at least one useful identifier such as DeviceId, AccountObjectId, IPAddress, or SHA256 in the final projection.",
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

    private static IReadOnlyList<WatchlistPipelineSpan> CollectWatchlistPipelines(string query)
    {
        if (!query.Contains("_GetWatchlist", StringComparison.OrdinalIgnoreCase))
            return [];

        var pipelines = new List<WatchlistPipelineSpan>();
        foreach (System.Text.RegularExpressions.Match watchlist in WatchlistPipeline().Matches(query))
        {
            var pipeline = watchlist.Groups["pipeline"];
            var alias = watchlist.Groups["alias"].Value.Trim();
            if (alias.Length >= 2 && ((alias[0] == '\'' && alias[^1] == '\'') || (alias[0] == '"' && alias[^1] == '"')))
                alias = alias[1..^1];
            if (string.IsNullOrWhiteSpace(alias) || alias.Contains(')'))
                alias = "example_alias";
            pipelines.Add(new WatchlistPipelineSpan(pipeline.Index, pipeline.Index + pipeline.Length, alias));
        }
        return pipelines;
    }

    private static string? WatchlistColumnGuidance(
        IReadOnlyList<WatchlistPipelineSpan> pipelines, int diagnosticPosition, string description)
    {
        var unknownName = UnknownColumnName().Match(description);
        if (!unknownName.Success) return null;

        foreach (var pipeline in pipelines)
        {
            if (diagnosticPosition < pipeline.Start || diagnosticPosition > pipeline.End)
                continue;

            var column = unknownName.Groups["column"].Value;
            return $"The name '{column}' is not a known built-in watchlist column. If it is a workspace-specific field, declare it in the request's extensions.watchlists using its actual KQL type (for example, string): " +
                $"{{ \"extensions\": {{ \"watchlists\": [{{ \"name\": \"{pipeline.Alias}\", \"columns\": [{{ \"name\": \"{column}\", \"type\": \"string\" }}] }}] }} }}";
        }

        return null;
    }

    private static string DiagnosticGuidance(
        IReadOnlyList<WatchlistPipelineSpan> watchlistPipelines, string code, int diagnosticPosition, string description)
    {
        if (code == "KS142")
            return WatchlistColumnGuidance(watchlistPipelines, diagnosticPosition, description)
                ?? GenericUnknownColumnGuidance(description);

        if (code == "KS204")
            return UnknownTableGuidance(description);

        if (code == "KS211")
            return UnknownFunctionGuidance(description);

        return description;
    }

    private static string GenericUnknownColumnGuidance(string description)
    {
        var match = UnknownColumnName().Match(description);
        if (!match.Success) return description;

        var column = match.Groups["column"].Value;
        return $"{description} Check the selected environment's table schema and verify the spelling and scope of '{column}'. If it is a workspace-specific table, function, or watchlist field, declare it through the request's extensions.";
    }

    private static string UnknownTableGuidance(string description)
    {
        var match = UnknownColumnName().Match(description);
        if (!match.Success) return description;

        var name = match.Groups["column"].Value;
        return $"{description} Verify that '{name}' exists in the selected environment and search the environment schema. If it is workspace-specific, declare it under extensions.tables (or extensions.functions when it is a tabular function).";
    }

    private static string UnknownFunctionGuidance(string description)
    {
        var match = UnknownColumnName().Match(description);
        if (!match.Success) return description;

        var name = match.Groups["column"].Value;
        return $"{description} Verify the function name and signature in the selected environment schema. If it is workspace-specific, declare its parameters and return schema under extensions.functions.";
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
    private sealed record WatchlistPipelineSpan(int Start, int End, string Alias);
    private sealed record FileProfileColumn(string Name, int Position, int ScopePosition);
    private sealed record NormalizedQuery(string Query, IReadOnlyList<FileProfileColumn> Columns);

    [GeneratedRegex(@"(?i)(?<prefix>\binvoke\s+FileProfile\s*\(\s*)(?<column>[A-Za-z_]\w*)(?=\s*(?:,|\)))", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex BareFileProfileColumn();

    [GeneratedRegex(@"(?i)The name '(?<column>[^']+)'", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex UnknownColumnName();

    [GeneratedRegex(@"(?is)_GetWatchlist\s*\(\s*(?<alias>[^)]*)\)\s*(?<pipeline>.*?)(?=;|$)", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex WatchlistPipeline();
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
