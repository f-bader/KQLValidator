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
    KqlLinter linter)
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
            .Concat(linter.Analyze(request.Query, request.Environment, request.Profile))
            .Concat(DetectionOutputDiagnostics(request, outputColumns))
            .OrderBy(x => x.Span.Start)
            .ThenByDescending(x => x.Severity)
            .ToArray();

        var references = GatherReferences(code);
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

    private static IEnumerable<ValidationDiagnostic> DetectionOutputDiagnostics(
        ValidateRequest request,
        IReadOnlyList<ColumnDeclaration> outputColumns)
    {
        if (request.Profile != LintProfile.Detection) yield break;
        var names = outputColumns.Select(x => x.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (request.Environment == KqlEnvironment.Sentinel && !names.Contains("TimeGenerated"))
            yield return new ValidationDiagnostic(
                "KQLD001", Contracts.DiagnosticSeverity.Error,
                "Sentinel detection queries must retain TimeGenerated in their output.",
                KqlLinter.Span(request.Query, Math.Max(0, request.Query.Length - 1), 1),
                "https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview", "detection");

        if (request.Environment != KqlEnvironment.Xdr) yield break;
        foreach (var column in new[] { "Timestamp", "ReportId" })
            if (!names.Contains(column))
                yield return new ValidationDiagnostic(
                    column == "Timestamp" ? "KQLD002" : "KQLD003", Contracts.DiagnosticSeverity.Warning,
                    $"Retain {column} when available so XDR detection results can identify the source event.",
                    KqlLinter.Span(request.Query, Math.Max(0, request.Query.Length - 1), 1), Category: "detection");

        if (!names.Overlaps(["DeviceId", "DeviceName", "AccountObjectId", "AccountSid", "RemoteIP", "SHA256"]))
            yield return new ValidationDiagnostic(
                "KQLD004", Contracts.DiagnosticSeverity.Warning,
                "Retain at least one useful device, account, IP, or file entity column for XDR detection results.",
                KqlLinter.Span(request.Query, Math.Max(0, request.Query.Length - 1), 1), Category: "detection");
    }

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
