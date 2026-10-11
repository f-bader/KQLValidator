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
        Kusto.Language.Utils.CancellationToken kustoCancellation = cancellationToken;
        var code = KustoCode.ParseAndAnalyze(request.Query, globals, kustoCancellation);
        var fileProfileColumns = CollectFileProfileColumns(code, cancellationToken);

        var outputColumns = code.ResultType?.Members.OfType<ColumnSymbol>()
            .GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Select(x => new ColumnDeclaration(x.Key, x.First().Type.Name))
            .ToArray() ?? [];

        cancellationToken.ThrowIfCancellationRequested();
        var fileProfileDiagnostics = ValidateFileProfileColumns(request.Query, code, fileProfileColumns, kustoCancellation);
        var references = GatherReferences(code, fileProfileColumns.Select(x => x.Name), cancellationToken);
        var lintPolicy = lintRules.CreatePolicy(request);
        var watchlistPipelines = CollectWatchlistPipelines(request.Query);
        var fileProfilePositions = fileProfileColumns.Select(x => x.Position).ToHashSet();

        var candidates = code.GetDiagnostics(kustoCancellation)
            // Kusto clears row scope inside invoke arguments. FileProfile's column
            // selector is checked against the input scope separately below.
            .Where(diagnostic => diagnostic.Code != "KS142" || !fileProfilePositions.Contains(diagnostic.Start))
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
            .Concat(ValidateFileProfileLimits(request.Query, code, cancellationToken))
            .Concat(linter.Analyze(request, lintPolicy, code, cancellationToken))
            .Concat(defenderNrtValidator.Analyze(request, lintPolicy, references.Tables, references.Columns, cancellationToken))
            .Concat(DetectionOutputDiagnostics(request, outputColumns, code, schema, lintPolicy))
            .ToArray();
        var truncated = candidates.Length > MaxDiagnostics;
        var diagnostics = candidates
            .OrderBy(x => x.Severity)
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
            !candidates.Any(x => x.Severity == Contracts.DiagnosticSeverity.Error),
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
        KustoCode code,
        EnvironmentSchema schema,
        LintPolicy policy)
    {
        var names = outputColumns.Select(x => x.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (!names.Contains("TimeGenerated") && Enabled(policy, "KQLD001"))
            yield return lintRules.CreateDiagnostic(
                request.Query, "KQLD001",
                "Sentinel scheduled and NRT detections must retain TimeGenerated in the final output; filtering on it alone is insufficient. Add it to the final projection, for example: | project TimeGenerated, AlertName, AccountUpn.",
                Math.Max(0, request.Query.Length - 1));

        if (!names.Contains("Timestamp") && !names.Contains("TimeGenerated") && Enabled(policy, "KQLD002"))
            yield return lintRules.CreateDiagnostic(
                request.Query, "KQLD002",
                "Prefer Timestamp or TimeGenerated in the final output so each result identifies its event time; otherwise alert time is derived from the lookback period. Add one to the final projection, for example: | project Timestamp, DeviceId, ReportId.",
                Math.Max(0, request.Query.Length - 1));

        if (!names.Contains("Timestamp") && names.Contains("TimeGenerated") && Enabled(policy, "KQLX003"))
            yield return lintRules.CreateDiagnostic(
                request.Query, "KQLX003",
                "TimeGenerated is accepted, but prefer Timestamp for native Defender XDR table output.",
                Math.Max(0, request.Query.Length - 1));

        var eventTables = ActiveOutputTables(code).Where(table => schema.Tables.TryGetValue(table, out var definition) &&
            definition.Columns.Any(column => column.Name == "ReportId")).ToArray();
        var endpointEvents = eventTables.Where(table => table.StartsWith("Device", StringComparison.Ordinal) &&
            schema.Tables[table].Columns.Any(column => column.Name == "DeviceId")).ToArray();
        if (eventTables.Length > 0 && (!names.Contains("ReportId") || endpointEvents.Length > 0 && !names.Contains("DeviceId")) &&
            Enabled(policy, "KQLD003"))
            yield return lintRules.CreateDiagnostic(
                request.Query, "KQLD003",
                "The final output drops recommended event identifiers. Retain ReportId for applicable Defender events and DeviceId for endpoint events, " +
                "for example: | project Timestamp, ReportId, DeviceId. These fields preserve event identity, device scope, and process-tree context.",
                Math.Max(0, request.Query.Length - 1));

        if (!names.Overlaps(["DeviceId", "DeviceName", "RemoteDeviceName", "RecipientEmailAddress", "AccountObjectId", "AccountSid", "AccountUpn", "InitiatingProcessAccountObjectId", "InitiatingProcessAccountSid", "InitiatingProcessAccountUpn"]) &&
            Enabled(policy, "KQLD004"))
            yield return lintRules.CreateDiagnostic(
                request.Query, "KQLD004",
                "Defender detection output has no supported automatic impacted-asset identifier. Retain a device, mailbox, or account field such as " +
                "DeviceId, RecipientEmailAddress, or AccountObjectId. IP addresses and hashes can provide evidence but do not satisfy this automatic mapping check.",
                Math.Max(0, request.Query.Length - 1));

    }

    private static IReadOnlySet<string> ActiveOutputTables(KustoCode code)
    {
        var tables = new HashSet<string>(StringComparer.Ordinal);
        var visiting = new HashSet<Symbol>();
        if (code.Syntax is QueryBlock block && block.Statements.LastOrDefault()?.Element is ExpressionStatement statement)
            Collect(statement.Expression, 0, new Dictionary<string, SourceArgument>());
        return tables;

        // Follow row-producing inputs, not scalar or membership subqueries in predicates.
        void Collect(Expression expression, int depth, IReadOnlyDictionary<string, SourceArgument> arguments)
        {
            if (depth > 64) return;
            switch (expression)
            {
                case ParenthesizedExpression parenthesized:
                    Collect(parenthesized.Expression, depth + 1, arguments); break;
                case SimpleNamedExpression named:
                    Collect(named.Expression, depth + 1, arguments); break;
                case MaterializeExpression materialized:
                    Collect(materialized.Expression, depth + 1, arguments); break;
                case NameReference { ReferencedSymbol: ParameterSymbol parameter } when arguments.TryGetValue(parameter.Name, out var argument):
                    Collect(argument.Expression, depth + 1, argument.Context); break;
                case NameReference { ReferencedSymbol: TableSymbol table }:
                    tables.Add(table.Name); break;
                case NameReference { ReferencedSymbol: VariableSymbol { Source: { } source } variable } when visiting.Add(variable):
                    Collect(source, depth + 1, arguments);
                    visiting.Remove(variable); break;
                case PipeExpression { Operator: InvokeOperator { Function: FunctionCallExpression { ReferencedSignature.Declaration: { } } call } } pipe:
                    CollectCall(call, depth, arguments, pipe.Expression); break;
                case PipeExpression { Operator: JoinOperator join } pipe:
                    var kind = join.Parameters.FirstOrDefault(p => p.Name.SimpleName == "kind")?.Expression.ToString().Trim();
                    if (kind is not ("rightsemi" or "rightanti" or "rightantisemi")) Collect(pipe.Expression, depth + 1, arguments);
                    if (kind is not ("leftsemi" or "leftanti" or "leftantisemi" or "anti")) Collect(join.Expression, depth + 1, arguments);
                    break;
                case PipeExpression { Operator: LookupOperator lookup } pipe:
                    Collect(pipe.Expression, depth + 1, arguments);
                    Collect(lookup.Expression, depth + 1, arguments); break;
                case PipeExpression { Operator: UnionOperator union } pipe:
                    Collect(pipe.Expression, depth + 1, arguments);
                    Collect(union, depth + 1, arguments); break;
                case PipeExpression pipe:
                    Collect(pipe.Expression, depth + 1, arguments); break;
                case UnionOperator union:
                    foreach (var input in union.Expressions) Collect(input.Element, depth + 1, arguments);
                    break;
                case FunctionCallExpression { ReferencedSignature.Declaration: { } } call:
                    CollectCall(call, depth, arguments); break;
            }
        }

        void CollectCall(FunctionCallExpression call, int depth, IReadOnlyDictionary<string, SourceArgument> arguments, Expression? implicitInput = null)
        {
            if (call.ResultType is not TableSymbol || call.ReferencedSignature?.Declaration?.Expression is not { } body ||
                call.ReferencedSymbol is not { } function || !visiting.Add(function)) return;
            var bindings = new Dictionary<string, SourceArgument>();
            var offset = implicitInput is null ? 0 : 1;
            if (implicitInput is not null && call.ReferencedSignature.Parameters.Count > 0)
                bindings[call.ReferencedSignature.Parameters[0].Name] = new(implicitInput, arguments);
            for (var i = 0; i < Math.Min(call.ReferencedSignature.Parameters.Count - offset, call.ArgumentList.Expressions.Count); i++)
                bindings[call.ReferencedSignature.Parameters[i + offset].Name] = new(call.ArgumentList.Expressions[i].Element, arguments);
            Collect(body, depth + 1, bindings);
            visiting.Remove(function);
        }

    }

    private sealed record SourceArgument(Expression Expression, IReadOnlyDictionary<string, SourceArgument> Context);

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
                KqlLinter.Span(originalQuery, column.Position, column.Length),
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

    private static IReadOnlyList<ValidationDiagnostic> ValidateFileProfileLimits(
        string query, KustoCode code, CancellationToken cancellationToken)
    {
        var diagnostics = new List<ValidationDiagnostic>();
        SyntaxElement.WalkNodes(code.Syntax, node =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (node is not FunctionCallExpression call || call.Parent is not InvokeOperator ||
                call.ReferencedSymbol is not FunctionSymbol { Name: "FileProfile" } ||
                !code.Globals.Database.Members.Contains(call.ReferencedSymbol) ||
                call.ArgumentList.Expressions.Count != 2)
                return;
            var limit = call.ArgumentList.Expressions[1].Element;
            var value = GetIntegerConstant(limit, cancellationToken);
            if (value is < 1 or > 1000)
                diagnostics.Add(new ValidationDiagnostic(
                    "KQLV002", Contracts.DiagnosticSeverity.Error,
                    "FileProfile enrichment limit must be between 1 and 1000.",
                    KqlLinter.Span(query, limit.TextStart, limit.Width),
                    "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-fileprofile-function",
                    "semantic"));
        });
        return diagnostics;
    }

    private static decimal? GetIntegerConstant(Expression expression, CancellationToken cancellationToken)
    {
        var negate = false;
        var visited = new HashSet<Expression>();
        while (visited.Add(expression))
        {
            cancellationToken.ThrowIfCancellationRequested();
            decimal? value = expression.ConstantValue switch
            {
                long number => number,
                int number => number,
                _ => null,
            };
            if (value is not null) return negate ? -value : value;
            switch (expression)
            {
                case ParenthesizedExpression parenthesized:
                    expression = parenthesized.Expression;
                    break;
                case PrefixUnaryExpression unary when unary.Kind is SyntaxKind.UnaryMinusExpression or SyntaxKind.UnaryPlusExpression:
                    negate ^= unary.Kind == SyntaxKind.UnaryMinusExpression;
                    expression = unary.Expression;
                    break;
                case NameReference { ReferencedSymbol: VariableSymbol { Source: { } source } }:
                    expression = source;
                    break;
                default:
                    return null;
            }
        }
        return null;
    }

    private static IReadOnlyList<FileProfileColumn> CollectFileProfileColumns(KustoCode code, CancellationToken cancellationToken)
    {
        var columns = new List<FileProfileColumn>();
        SyntaxElement.WalkNodes(code.Syntax, node =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (node is not FunctionCallExpression call || call.Parent is not InvokeOperator invoke ||
                call.ReferencedSymbol is not FunctionSymbol { Name: "FileProfile" } || call.ArgumentList.Expressions.Count == 0 ||
                !code.Globals.Database.Members.Contains(call.ReferencedSymbol) ||
                call.ArgumentList.Expressions[0].Element is not NameReference column)
                return;
            columns.Add(new FileProfileColumn(column.SimpleName, column.TextStart, column.Width, invoke.TextStart));
        });
        return columns;
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
    private sealed record FileProfileColumn(string Name, int Position, int Length, int ScopePosition);

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
