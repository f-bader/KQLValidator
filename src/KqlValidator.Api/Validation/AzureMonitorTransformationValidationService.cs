using System.Diagnostics;
using System.Text.RegularExpressions;
using KqlValidator.Contracts;
using Kusto.Language;
using Kusto.Language.Symbols;
using Kusto.Language.Syntax;
using ContractSeverity = KqlValidator.Contracts.DiagnosticSeverity;

namespace KqlValidator.Validation;

public sealed partial class AzureMonitorTransformationValidationService(
    GlobalStateFactory globalStateFactory,
    LintRuleCatalog lintRules)
{
    private const int MaxColumns = 5_000;
    private const int MaxDiagnostics = 500;
    private const int MaxIdentifierLength = 128;
    private const int RegexTimeoutMilliseconds = 250;

    public TransformationValidationResponse Validate(
        TransformationValidationRequest request,
        CancellationToken cancellationToken = default)
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

    private TransformationValidationResponse ValidateCore(
        TransformationValidationRequest request,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        ValidateRequest(request);
        var globals = globalStateFactory.CreateTransformation(request.SourceColumns);
        Kusto.Language.Utils.CancellationToken kustoCancellation = cancellationToken;
        var code = KustoCode.ParseAndAnalyze(request.Query, globals, kustoCancellation);
        var outputColumns = code.ResultType?.Members.OfType<ColumnSymbol>()
            .GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .Select(x => new ColumnDeclaration(x.Key, x.First().Type.Name))
            .ToArray() ?? [];

        var references = GatherReferences(code, cancellationToken);
        var kustoDiagnostics = code.GetDiagnostics(kustoCancellation)
            .Select(diagnostic => new ValidationDiagnostic(
                diagnostic.Code,
                diagnostic.Severity == Kusto.Language.DiagnosticSeverity.Error
                    ? ContractSeverity.Error
                    : ContractSeverity.Warning,
                diagnostic.Description,
                KqlLinter.Span(request.Query, diagnostic.Start, diagnostic.Length),
                "https://learn.microsoft.com/en-us/kusto/query/",
                diagnostic.Code.StartsWith("KS", StringComparison.Ordinal) ? "syntax" : "semantic"))
            .ToArray();
        var blockingKustoDiagnostic = kustoDiagnostics.Any(x => x.Severity == ContractSeverity.Error);

        var candidates = kustoDiagnostics
            .Concat(FeatureDiagnostics(request.Query, code, cancellationToken))
            .Concat(blockingKustoDiagnostic
                ? []
                : OutputDiagnostics(request, outputColumns, code.ResultType is TableSymbol))
            .ToArray();
        var truncated = candidates.Length > MaxDiagnostics;
        var diagnostics = candidates
            .OrderBy(x => x.Severity)
            .Take(MaxDiagnostics)
            .AppendIf(truncated, new ValidationDiagnostic(
                "KQLV001",
                ContractSeverity.Warning,
                $"Diagnostics were truncated after {MaxDiagnostics} results.",
                KqlLinter.Span(request.Query, Math.Max(0, request.Query.Length - 1), 1),
                Category: "service"))
            .OrderBy(x => x.Span.Start)
            .ThenBy(x => x.Severity)
            .ToArray();

        stopwatch.Stop();
        return new(
            !candidates.Any(x => x.Severity == ContractSeverity.Error),
            ThisAssembly.Version,
            diagnostics,
            outputColumns,
            references.Columns,
            references.Functions,
            stopwatch.ElapsedMilliseconds);
    }

    private IReadOnlyList<ValidationDiagnostic> FeatureDiagnostics(
        string query,
        KustoCode code,
        CancellationToken cancellationToken)
    {
        var diagnostics = new List<ValidationDiagnostic>();
        var searchable = MaskCommentsAndStrings(query);

        SyntaxElement.WalkNodes(code.Syntax, node =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (node is QueryOperator && !AllowedQueryOperatorKinds.Contains(node.Kind))
                Add(diagnostics, query, "KQLT002",
                    $"'{node.Kind.ToString().Replace("Operator", string.Empty, StringComparison.Ordinal)}' is not a supported Azure Monitor transformation tabular operator.",
                    node.TextStart, node.Width);
        });

        foreach (Match match in UnsupportedStringOperator().Matches(searchable))
            Add(diagnostics, query, "KQLT003",
                $"'{match.Value}' is not a supported Azure Monitor transformation string operator.",
                match.Index, match.Length);

        var localFunctions = CollectLocalScalarFunctions(diagnostics, query, searchable);
        foreach (Match match in FunctionCall().Matches(searchable))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var function = match.Groups["function"].Value;
            if (AzureMonitorTransformationFeatures.AllowedFunctions.Contains(function) ||
                AzureMonitorTransformationFeatures.ParenthesizedOperators.Contains(function) ||
                localFunctions.Contains(function))
                continue;
            Add(diagnostics, query, "KQLT003",
                $"'{function}()' is not a supported Azure Monitor transformation scalar function.",
                match.Index, match.Length);
        }

        foreach (var parse in ParseStatementInspector.Find(code.Syntax, cancellationToken))
        {
            if (parse.ExtractionCount > 10)
                Add(diagnostics, query, "KQLT004",
                    $"This parse statement extracts {parse.ExtractionCount} columns; Azure Monitor transformations allow at most ten per statement.",
                    parse.Start, parse.Length);
            else if (parse.ExtractionCount > 5)
                Add(diagnostics, query, "KQLP007",
                    $"This parse statement extracts {parse.ExtractionCount} columns. Split it into statements of no more than five extractions to reduce processing time.",
                    parse.Start, parse.Length);

            if (parse.IsRegex)
                Add(diagnostics, query, "KQLT005",
                    "In Azure Monitor transformations, parse kind=regex must match the entire input value for parsed columns to be populated.",
                    parse.Start, parse.Length);
        }

        SyntaxElement.WalkNodes(code.Syntax, node =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (node is not DataTableExpression dataTable)
                return;
            var columnCount = 0;
            SyntaxElement.WalkNodes(dataTable.Schema, child =>
            {
                if (child.Kind == SyntaxKind.NameAndTypeDeclaration)
                    columnCount++;
            });
            if (columnCount > 0 && dataTable.Values.Count > columnCount)
                Add(diagnostics, query, "KQLT001",
                    "A transformation datatable must contain at most one row so each input record produces no more than one output record.",
                    dataTable.TextStart, dataTable.Width);
        });

        return diagnostics;
    }

    private HashSet<string> CollectLocalScalarFunctions(
        List<ValidationDiagnostic> diagnostics,
        string query,
        string searchable)
    {
        var functions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in LocalFunction().Matches(searchable))
        {
            var scalar = match.Groups["parameters"].Value
                .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .All(parameter => parameter.Split(':', 2) is [_, var type] &&
                    AzureMonitorTransformationFeatures.ScalarTypes.Contains(type.Trim()));
            if (scalar)
                functions.Add(match.Groups["name"].Value);
            else
                Add(diagnostics, query, "KQLT003",
                    "Azure Monitor transformations support user-defined functions only when every argument is scalar.",
                    match.Index, match.Length);
        }
        return functions;
    }

    private IEnumerable<ValidationDiagnostic> OutputDiagnostics(
        TransformationValidationRequest request,
        IReadOnlyList<ColumnDeclaration> outputColumns,
        bool tabularResult)
    {
        var end = Math.Max(0, request.Query.Length - 1);
        if (!tabularResult)
        {
            yield return Create(request.Query, "KQLT001",
                "An Azure Monitor transformation must return a tabular result.", end);
            yield break;
        }

        var timeGenerated = outputColumns.FirstOrDefault(x => x.Name.Equals("TimeGenerated", StringComparison.OrdinalIgnoreCase));
        if (timeGenerated is null || !timeGenerated.Type.Equals("datetime", StringComparison.OrdinalIgnoreCase))
            yield return Create(request.Query, "KQLT006",
                "An Azure Monitor transformation must return TimeGenerated with the datetime type.", end);

        if (request.DestinationColumns is null)
            yield break;

        var destination = request.DestinationColumns.ToDictionary(x => x.Name, StringComparer.OrdinalIgnoreCase);
        foreach (var output in outputColumns)
        {
            if (!destination.TryGetValue(output.Name, out var expected))
            {
                yield return Create(request.Query, "KQLT008",
                    $"Output column '{output.Name}' is absent from the destination schema and will be discarded after ingestion.", end);
                continue;
            }
            if (GlobalStateFactory.ResolveType(output.Type) != GlobalStateFactory.ResolveType(expected.Type))
                yield return Create(request.Query, "KQLT007",
                    $"Output column '{output.Name}' has type '{output.Type}', but the destination requires '{expected.Type}'.", end);
        }
    }

    private static References GatherReferences(KustoCode code, CancellationToken cancellationToken)
    {
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var functions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        SyntaxElement.WalkNodes(code.Syntax, node =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (node.ReferencedSymbol is ColumnSymbol column &&
                code.Globals.GetTable(column)?.Name.Equals("source", StringComparison.OrdinalIgnoreCase) == true)
                columns.Add(column.Name);
            if (node is FunctionCallExpression && node.ReferencedSymbol is FunctionSymbol function)
                functions.Add(function.Name);
        });
        return new(columns.Order(StringComparer.OrdinalIgnoreCase).ToArray(),
            functions.Order(StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private static void ValidateRequest(TransformationValidationRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Query))
            throw new RequestValidationException("query", "Query must not be empty.");
        if (request.Query.Length > 65_536)
            throw new RequestValidationException("query", "Query exceeds the 64 KiB character limit.");
        if (request.SourceColumns is null || request.SourceColumns.Count == 0)
            throw new RequestValidationException("sourceColumns", "Source columns must not be empty.");
        if (request.DestinationColumns is { Count: 0 })
            throw new RequestValidationException("destinationColumns", "Destination columns must not be empty when supplied.");
        if (request.SourceColumns.Count + (request.DestinationColumns?.Count ?? 0) > MaxColumns)
            throw new RequestValidationException("columns", $"Source and destination schemas exceed the combined limit of {MaxColumns} columns.");
        ValidateColumns(request.SourceColumns, "sourceColumns");
        if (request.DestinationColumns is not null)
            ValidateColumns(request.DestinationColumns, "destinationColumns");
    }

    private static void ValidateColumns(IReadOnlyList<ColumnDeclaration> columns, string field)
    {
        if (columns.Any(x => x is null))
            throw new RequestValidationException(field, "Column declarations must not contain null entries.");
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var column in columns)
        {
            if (string.IsNullOrWhiteSpace(column.Name) || column.Name.Length > MaxIdentifierLength || column.Name.Any(char.IsControl))
                throw new RequestValidationException(field, $"'{column.Name}' is not a valid column name.");
            if (!names.Add(column.Name))
                throw new RequestValidationException(field, $"Duplicate column '{column.Name}'.");
            if (string.IsNullOrWhiteSpace(column.Type))
                throw new RequestValidationException(field, $"Column '{column.Name}' requires a scalar type.");
            try
            {
                _ = GlobalStateFactory.ResolveType(column.Type);
            }
            catch (ArgumentException exception)
            {
                throw new RequestValidationException(field, exception.Message);
            }
        }
    }

    private void Add(List<ValidationDiagnostic> diagnostics, string query, string ruleId, string message, int start, int length) =>
        diagnostics.Add(Create(query, ruleId, message, start, length));

    private ValidationDiagnostic Create(string query, string ruleId, string message, int start, int length = 1) =>
        lintRules.CreateDiagnostic(query, ruleId, message, start, Math.Max(1, length));

    private static string MaskCommentsAndStrings(string query) => Mask().Replace(query, match => new string(' ', match.Length));

    private static readonly IReadOnlySet<SyntaxKind> AllowedQueryOperatorKinds = new HashSet<SyntaxKind>
    {
        SyntaxKind.ExtendOperator,
        SyntaxKind.ParseOperator,
        SyntaxKind.PrintOperator,
        SyntaxKind.ProjectOperator,
        SyntaxKind.ProjectAwayOperator,
        SyntaxKind.ProjectRenameOperator,
        SyntaxKind.FilterOperator,
    };

    private sealed record References(IReadOnlyList<string> Columns, IReadOnlyList<string> Functions);

    [GeneratedRegex("""@?(?:\"(?:\"\"|\\.|[^\"])*\"|'(?:''|\\.|[^'])*')|//[^\r\n]*|/\*[\s\S]*?\*/""", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex Mask();
    [GeneratedRegex(@"\b(?<function>[A-Za-z_]\w*)\s*\(", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex FunctionCall();
    [GeneratedRegex(@"(?im)(?:^|;)\s*let\s+(?<name>[A-Za-z_]\w*)\s*=\s*\((?<parameters>[^)]*)\)\s*\{", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex LocalFunction();
    [GeneratedRegex(@"(?i)(?:!in~|\bin~|\b(?:contains_any|has_all|has_any|hasprefix(?:_cs)?|hassuffix(?:_cs)?|notcontains(?:_cs)?|nothas(?:_cs)?|notstartswith(?:_cs)?|notendswith(?:_cs)?|search)\b)", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex UnsupportedStringOperator();
}
