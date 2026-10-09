using KqlValidator.Contracts;
using Kusto.Language;
using Kusto.Language.Symbols;
using Kusto.Language.Syntax;

namespace KqlValidator.Validation;

internal sealed class ColumnRelationInspector
{
    private readonly ColumnRelationCatalog catalog;
    private readonly LintRuleCatalog rules;
    private readonly Dictionary<ColumnSymbol, Origin> physical = [];
    private readonly Dictionary<ColumnSymbol, Origin?> cache = [];
    private readonly CancellationToken cancellationToken;
    private readonly HashSet<FunctionSymbol> customFunctions;

    public ColumnRelationInspector(ColumnRelationCatalog catalog, LintRuleCatalog rules, KustoCode code, CancellationToken cancellationToken)
    {
        this.catalog = catalog;
        this.rules = rules;
        this.cancellationToken = cancellationToken;
        customFunctions = code.Globals.Database.Members.OfType<FunctionSymbol>().ToHashSet();
        foreach (var table in code.Globals.Database.Members.OfType<TableSymbol>())
            foreach (var column in table.Columns)
                physical[column] = new(new(table.Name, column.Name));
    }

    public IReadOnlyList<ValidationDiagnostic> Analyze(string query, KustoCode code, LintPolicy policy)
    {
        var diagnostics = new List<ValidationDiagnostic>();
        SyntaxElement.WalkNodes(code.Syntax, node =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (node is not JoinOperator { ConditionClause: JoinOnClause on } join ||
                join.Parent is not PipeExpression pipe || pipe.Expression.ResultType is not TableSymbol leftTable ||
                join.Expression.ResultType is not TableSymbol rightTable)
                return;

            var keys = new List<KeyPair>();
            foreach (var condition in on.Expressions)
                CollectKeys(condition.Element, leftTable, rightTable, keys);
            foreach (var key in keys)
            {
                var leftFamilies = catalog.Families(key.Left.Endpoint);
                var rightFamilies = catalog.Families(key.Right.Endpoint);
                // A future ambiguous endpoint or an unresolved expression is not evidence of incompatibility.
                if (leftFamilies.Count == 1 && rightFamilies.Count == 1 && leftFamilies[0] != rightFamilies[0])
                    Add("KQLR001", $"This join compares {Describe(key.Left)} ({catalog.FamilyLabel(leftFamilies[0])}) with " +
                        $"{Describe(key.Right)} ({catalog.FamilyLabel(rightFamilies[0])}). These identifiers have different meanings; choose compatible correlation keys.", key.Syntax);

                foreach (var origin in new[] { key.Left, key.Right })
                {
                    var families = catalog.Families(origin.Endpoint);
                    if (origin.CaseFolded && families.Count == 1 && families[0] is "entra-token" or "aws-resource" or "gcp-resource")
                        Add("KQLR002", $"This join changes the case of {Describe(origin)} ({catalog.FamilyLabel(families[0])}). " +
                            "Preserve identifier case and use exact equality; case folding can merge distinct identifiers.", key.Syntax);
                }

                if (leftFamilies.Count != 1 || rightFamilies.Count != 1 || leftFamilies[0] != "process-start-key" ||
                    rightFamilies[0] != "process-start-key" || !KnownRelation(key.Left.Endpoint, key.Right.Endpoint))
                    continue;
                var hasDeviceKey = keys.Any(k => DeviceKey(k.Left.Endpoint, key.Left.Endpoint.Table) &&
                    DeviceKey(k.Right.Endpoint, key.Right.Endpoint.Table));
                var leftDevice = FixedDevice(pipe.Expression, key.Left.Endpoint.Table);
                var rightDevice = FixedDevice(join.Expression, key.Right.Endpoint.Table);
                if (!hasDeviceKey && (leftDevice is null || leftDevice != rightDevice))
                    Add("KQLR003", $"This process-key join between {key.Left.Endpoint.Table} and {key.Right.Endpoint.Table} omits device scope. " +
                        "Match DeviceId as well as the process key, or restrict both inputs to the same device. Retain tenant context and match tenant identifiers when available; " +
                        "activity should occur at or after process creation. Process keys are device-scoped, not globally unique.", key.Syntax);
            }
        });
        return diagnostics.DistinctBy(d => (d.RuleId, d.Span.Start, d.Message)).ToArray();

        void Add(string id, string message, SyntaxNode syntax)
        {
            if (policy.IsEnabled(id, rules.Get(id).DefaultSeverity))
                diagnostics.Add(rules.CreateDiagnostic(query, id, message, syntax.TextStart, syntax.Width));
        }
    }

    private void CollectKeys(Expression expression, TableSymbol left, TableSymbol right, List<KeyPair> keys, int depth = 0)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (depth > 64) return;
        if (expression is ParenthesizedExpression parenthesized)
            CollectKeys(parenthesized.Expression, left, right, keys, depth + 1);
        else if (expression is BinaryExpression { Kind: SyntaxKind.AndExpression } and)
        {
            CollectKeys(and.Left, left, right, keys, depth + 1);
            CollectKeys(and.Right, left, right, keys, depth + 1);
        }
        else if (expression is BinaryExpression { Kind: SyntaxKind.EqualExpression } equal)
        {
            var l = Resolve(equal.Left);
            var r = Resolve(equal.Right);
            // Use the input roles, not endpoint ordering: joins can reverse $left/$right in equality.
            if (l is not null && r is not null)
            {
                if (JoinSide(equal.Left) == "$right" && JoinSide(equal.Right) == "$left")
                    (l, r) = (r, l);
                keys.Add(new(l, r, expression));
            }
        }
        else if (expression is NameReference name)
        {
            var l = left.Columns.FirstOrDefault(c => c.Name == name.SimpleName);
            var r = right.Columns.FirstOrDefault(c => c.Name == name.SimpleName);
            if (l is not null && r is not null && ResolveColumn(l, 0) is { } lo && ResolveColumn(r, 0) is { } ro)
                keys.Add(new(lo, ro, expression));
        }
    }

    private static string? JoinSide(Expression expression) => expression switch
    {
        PathExpression { Expression: NameReference name } when name.SimpleName is "$left" or "$right" => name.SimpleName,
        ParenthesizedExpression p => JoinSide(p.Expression),
        _ => null,
    };

    private Origin? Resolve(Expression expression, int depth = 0)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (depth > 64) return null;
        if (expression.ReferencedSymbol is ColumnSymbol column)
            return ResolveColumn(column, depth + 1);
        switch (expression)
        {
            case ParenthesizedExpression parenthesized:
                return Resolve(parenthesized.Expression, depth + 1);
            case SimpleNamedExpression named:
                return Resolve(named.Expression, depth + 1);
            case PathExpression path when path.Selector is NameReference selector:
                return Append(Resolve(path.Expression, depth + 1), selector.SimpleName);
            case ElementExpression element when element.Selector is BracketedExpression bracket && bracket.Expression.ConstantValue is string property:
                return Append(Resolve(element.Expression, depth + 1), property);
            case FunctionCallExpression call when call.ReferencedSymbol is FunctionSymbol function && !customFunctions.Contains(function):
                var args = call.ArgumentList.Expressions;
                if (args.Count == 1 && function.Name is "tostring" or "parse_json" or "todynamic" or "tolower" or "toupper")
                {
                    var origin = Resolve(args[0].Element, depth + 1);
                    return origin is null ? null : origin with { CaseFolded = origin.CaseFolded || function.Name is "tolower" or "toupper" };
                }
                // The source's AAD Graph example removes only trailing Base64 padding.
                if (args.Count == 2 && function.Name == "trim_end" && args[0].Element.ConstantValue is string pattern && pattern == "=+")
                    return Resolve(args[1].Element, depth + 1);
                return null;
            default:
                return null;
        }
    }

    private Origin? ResolveColumn(ColumnSymbol column, int depth)
    {
        if (depth > 64) return null;
        if (physical.TryGetValue(column, out var origin)) return origin;
        if (cache.TryGetValue(column, out var cached)) return cached;
        cache[column] = null; // Guard recursive symbol sources.
        if (column.Source is Expression source)
            origin = Resolve(source, depth + 1);
        else if (column.OriginalColumns.Count > 0)
        {
            var originals = column.OriginalColumns.Select(c => ResolveColumn(c, depth + 1)).ToArray();
            // Even same-family union branches can represent different identities and scopes.
            origin = originals.All(o => o is not null) && originals.Distinct().Count() == 1 ? originals[0] : null;
        }
        else origin = null;
        cache[column] = origin;
        return origin;
    }

    private string? FixedDevice(Expression expression, string table, int depth = 0)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (depth > 64) return null;
        return expression switch
        {
            ParenthesizedExpression p => FixedDevice(p.Expression, table, depth + 1),
            NameReference { ReferencedSymbol: VariableSymbol { Source: { } source } } => FixedDevice(source, table, depth + 1),
            PipeExpression { Operator: FilterOperator where } pipe => DeviceConstant(where.Condition, table) ?? FixedDevice(pipe.Expression, table, depth + 1),
            PipeExpression pipe when pipe.Operator is ProjectOperator or ProjectRenameOperator or ExtendOperator or ProjectAwayOperator or TakeOperator or SortOperator =>
                FixedDevice(pipe.Expression, table, depth + 1),
            _ => null,
        };
    }

    private string? DeviceConstant(Expression expression, string table, int depth = 0)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (depth > 64) return null;
        if (expression is ParenthesizedExpression p) return DeviceConstant(p.Expression, table, depth + 1);
        if (expression is BinaryExpression { Kind: SyntaxKind.AndExpression } and)
            return DeviceConstant(and.Left, table, depth + 1) ?? DeviceConstant(and.Right, table, depth + 1);
        if (expression is not BinaryExpression { Kind: SyntaxKind.EqualExpression } equal) return null;
        foreach (var (key, value) in new[] { (equal.Left, equal.Right), (equal.Right, equal.Left) })
            if (Resolve(key) is { CaseFolded: false } origin && DeviceKey(origin.Endpoint, table) && value.ConstantValue is string { Length: > 0 } text)
                return text;
        return null;
    }

    private bool KnownRelation(ColumnRelationEndpoint left, ColumnRelationEndpoint right) => catalog.Relations.Any(r =>
        ColumnRelationCatalog.Same(r.From, left) && ColumnRelationCatalog.Same(r.To, right) ||
        ColumnRelationCatalog.Same(r.To, left) && ColumnRelationCatalog.Same(r.From, right));
    private static bool DeviceKey(ColumnRelationEndpoint endpoint, string table) => endpoint.Path is null &&
        endpoint.Column == "DeviceId" && endpoint.Table.Equals(table, StringComparison.OrdinalIgnoreCase);
    private static Origin? Append(Origin? origin, string path) => origin is null ? null : origin with
    {
        Endpoint = origin.Endpoint with { Path = origin.Endpoint.Path is null ? path : $"{origin.Endpoint.Path}.{path}" },
    };
    private static string Describe(Origin origin) => $"{origin.Endpoint.Table}.{origin.Endpoint.Column}" +
        (origin.Endpoint.Path is null ? "" : $".{origin.Endpoint.Path}");
    private sealed record Origin(ColumnRelationEndpoint Endpoint, bool CaseFolded = false);
    private sealed record KeyPair(Origin Left, Origin Right, SyntaxNode Syntax);
}
