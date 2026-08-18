using System.Diagnostics;
using KqlValidator.Contracts;
using Kusto.Language;
using Kusto.Language.Symbols;
using Kusto.Language.Syntax;

namespace KqlValidator.Validation;

public sealed class KqlValidationService(
    SchemaCatalog catalog,
    GlobalStateFactory globalStateFactory,
    RequestValidator requestValidator,
    KqlLinter linter,
    LintRuleCatalog lintRules)
{
    public ValidationResponse Validate(ValidateRequest request)
    {
        var stopwatch = Stopwatch.StartNew();
        requestValidator.Validate(request);
        var schema = catalog.Get(request.Environment);
        var globals = globalStateFactory.Create(schema, request.Extensions);
        var code = KustoCode.ParseAndAnalyze(request.Query, globals);

        var outputColumns = code.ResultType?.Members.OfType<ColumnSymbol>()
            .GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Select(x => new ColumnDeclaration(x.Key, x.First().Type.Name))
            .ToArray() ?? [];

        var references = GatherReferences(code);
        var lintPolicy = lintRules.CreatePolicy(request);

        var diagnostics = code.GetDiagnostics()
            .Select(diagnostic => new ValidationDiagnostic(
                diagnostic.Code,
                diagnostic.Severity == Kusto.Language.DiagnosticSeverity.Error
                    ? Contracts.DiagnosticSeverity.Error
                    : Contracts.DiagnosticSeverity.Warning,
                diagnostic.Description,
                KqlLinter.Span(request.Query, diagnostic.Start, diagnostic.Length),
                "https://learn.microsoft.com/en-us/kusto/query/",
                diagnostic.Code.StartsWith("KS", StringComparison.Ordinal) ? "syntax" : "semantic"))
            .Concat(linter.Analyze(request, lintPolicy))
            .Concat(DetectionOutputDiagnostics(request, outputColumns, references.Tables, schema, lintPolicy))
            .OrderBy(x => x.Span.Start)
            .ThenByDescending(x => x.Severity)
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

    private static References GatherReferences(KustoCode code)
    {
        var tables = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var functions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        SyntaxElement.WalkNodes(code.Syntax, node =>
        {
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

        return new References(
            tables.Order(StringComparer.OrdinalIgnoreCase).ToArray(),
            columns.Order(StringComparer.OrdinalIgnoreCase).ToArray(),
            functions.Order(StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private sealed record References(IReadOnlyList<string> Tables, IReadOnlyList<string> Columns, IReadOnlyList<string> Functions);
}

internal static class ThisAssembly
{
    public static string Version => typeof(ThisAssembly).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
}
