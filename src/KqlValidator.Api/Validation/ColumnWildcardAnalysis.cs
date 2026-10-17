using KqlValidator.Contracts;
using Kusto.Language;
using Kusto.Language.Symbols;
using Kusto.Language.Syntax;

namespace KqlValidator.Validation;

/// <summary>Aligns column projections with query engine wildcard and empty-selection behavior.</summary>
internal static class ColumnWildcardAnalysis
{
    private const int MaxRebinds = 64;

    public static KustoCode ParseAndAnalyze(string query, GlobalState globals, CancellationToken cancellationToken)
    {
        Kusto.Language.Utils.CancellationToken kustoCancellation = cancellationToken;
        var code = KustoCode.ParseAndAnalyze(query, globals, kustoCancellation);
        for (var pass = 0; ; pass++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            char[]? normalized = null;
            var phantomColumns = new HashSet<Symbol>();
            SyntaxElement.WalkNodes(code.Syntax, node =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                var expressions = Expressions(node);
                if (expressions is null || node.ContainsSyntaxDiagnostics || HasTabularParameters(node)) return;

                var remove = expressions.Select(entry => IsUnmatchedWildcard(entry.Element, phantomColumns)).ToArray();
                if (!remove.Any(value => value)) return;

                // The binder invents an output column for an unmatched reorder expression.
                // Track its symbol so dependent wildcards can be removed in this same pass.
                if (node is ProjectReorderOperator { ResultType: TableSymbol table })
                    for (var i = 0; i < expressions.Count; i++)
                        if (remove[i] && WildcardName(expressions[i].Element) is { } name)
                            foreach (var column in table.Columns.Where(column => column.Name == name.SimpleName))
                                phantomColumns.Add(column);

                normalized ??= code.Text.ToCharArray();
                var followingSelection = false;
                for (var i = expressions.Count - 1; i >= 0; i--)
                {
                    if (remove[i]) Blank(expressions[i].Element);
                    // Keep separators only between surviving selections. Trivia and line breaks
                    // retain their positions so all analysis spans still address the submitted KQL.
                    if (expressions[i].Separator is { } separator &&
                        (remove[i] || !followingSelection))
                        Blank(separator);
                    followingSelection |= !remove[i];
                }

                void Blank(SyntaxElement element)
                {
                    for (var i = element.TextStart; i < element.End; i++)
                        if (normalized[i] is not ('\r' or '\n')) normalized[i] = ' ';
                }
            });
            if (normalized is null) return code;
            if (pass == MaxRebinds)
                throw new RequestValidationException("query", "Query exceeds the static analysis complexity limit.");
            // Rebind the entire query so later operators and local functions see the corrected schema.
            code = KustoCode.ParseAndAnalyze(new string(normalized), globals, kustoCancellation);
        }
    }

    public static IReadOnlyList<ValidationDiagnostic> EmptyProjectionDiagnostics(
        string query, KustoCode code, CancellationToken cancellationToken)
    {
        var diagnostics = new List<ValidationDiagnostic>();
        var visiting = new HashSet<Symbol>();
        var inspectedBodies = new HashSet<SyntaxNode>();
        var reported = new HashSet<int>();
        Inspect(code.Syntax, 0);
        return diagnostics;

        void Inspect(SyntaxNode root, int depth) => SyntaxElement.WalkNodes(root, node =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (node is FunctionCallExpression { ReferencedSignature.Declaration: not null } call && !HasTabularParameters(call) &&
                call.ReferencedSymbol is { } function && visiting.Add(function))
            {
                if (call.GetCalledFunctionBody() is { } body && inspectedBodies.Add(body))
                {
                    if (depth >= 64 || inspectedBodies.Count > 256)
                        throw new RequestValidationException("query", "Query exceeds the static analysis complexity limit.");
                    Inspect(body, depth + 1);
                }
                visiting.Remove(function);
            }

            if (node is not (ProjectAwayOperator or ProjectKeepOperator or ProjectReorderOperator or ProjectByNamesOperator) ||
                node is not Expression { ResultType: TableSymbol { IsOpen: false, Columns.Count: 0 } } ||
                node.ContainsSyntaxDiagnostics || HasTabularParameters(node) ||
                node.Parent is not PipeExpression { Expression.ResultType: TableSymbol { IsOpen: false, Columns.Count: > 0 } })
                return;

            // Dynamic selectors in function declarations can depend on invocation arguments.
            if (node is ProjectByNamesOperator byNames && byNames.Expressions.Any(entry => entry.Element.ConstantValue is null))
                return;

            var original = node.GetOriginalNode();
            if (!reported.Add(original.TextStart)) return;
            diagnostics.Add(new ValidationDiagnostic(
                "KQLV003", Contracts.DiagnosticSeverity.Error,
                "The projection retains zero columns. Retain at least one input column.",
                KqlLinter.Span(query, original.TextStart, original.GetFirstToken().Width),
                "https://learn.microsoft.com/en-us/kusto/query/", "semantic"));
        });
    }

    private static SyntaxList<SeparatedElement<Expression>>? Expressions(SyntaxNode node) => node switch
    {
        ProjectAwayOperator away => away.Expressions,
        ProjectKeepOperator keep => keep.Expressions,
        ProjectReorderOperator reorder => reorder.Expressions,
        _ => null,
    };

    private static bool HasTabularParameters(SyntaxNode node)
    {
        for (var parent = node.Parent; parent is not null; parent = parent.Parent)
            if (parent is Kusto.Language.Syntax.FunctionDeclaration declaration &&
                declaration.Parameters.Parameters.Any(parameter => parameter.Element.NameAndType.Type is SchemaTypeExpression))
                return true;
        return false;
    }

    private static NameReference? WildcardName(Expression expression)
    {
        if (expression is OrderedExpression ordered) expression = ordered.Expression;
        return expression is NameReference { Name: WildcardedName or BracketedWildcardedName } name ? name : null;
    }

    private static bool IsUnmatchedWildcard(Expression expression, IReadOnlySet<Symbol> phantomColumns) =>
        WildcardName(expression) is { } name &&
        (name.SemanticDiagnostics.Any(diagnostic => diagnostic.Code == "KS142") ||
         name.ReferencedSymbol is { } symbol && (phantomColumns.Contains(symbol) ||
         symbol is GroupSymbol { Members.Count: > 0 } group && group.Members.All(phantomColumns.Contains)));
}
