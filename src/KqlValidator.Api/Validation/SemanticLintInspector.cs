using System.Net;
using System.Text;
using System.Text.Json;
using KqlValidator.Contracts;
using Kusto.Language;
using Kusto.Language.Symbols;
using Kusto.Language.Syntax;
using DiagnosticSeverity = KqlValidator.Contracts.DiagnosticSeverity;

namespace KqlValidator.Validation;

/// <summary>Advisory checks over bound KQL. Unknown types and lineage are not evidence of a problem.</summary>
internal sealed class SemanticLintInspector
{
    private readonly LintRuleCatalog rules;
    private readonly ValidateRequest request;
    private readonly LintPolicy policy;
    private readonly KustoCode code;
    private readonly CancellationToken cancellationToken;
    private readonly List<ValidationDiagnostic> diagnostics = [];
    private readonly Dictionary<ColumnSymbol, Origin> physical = [];
    private readonly HashSet<FunctionSymbol> builtins;
    private readonly Dictionary<ColumnSymbol, Origin?> origins = [];
    private readonly List<SyntaxNode> nodes = [];
    private readonly Dictionary<Symbol, int> referenceCounts = [];

    public SemanticLintInspector(LintRuleCatalog rules, ValidateRequest request, LintPolicy policy, KustoCode code, CancellationToken cancellationToken)
    {
        this.rules = rules;
        this.request = request;
        this.policy = policy;
        this.code = code;
        this.cancellationToken = cancellationToken;
        builtins = code.Globals.Functions.Concat(code.Globals.Aggregates).ToHashSet();
        foreach (var table in code.Globals.Database.Members.OfType<TableSymbol>())
            foreach (var column in table.Columns)
                physical[column] = new(table, column.Name);
    }

    public IReadOnlyList<ValidationDiagnostic> Analyze()
    {
        SyntaxElement.WalkNodes(code.Syntax, node =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            nodes.Add(node);
            if (node is NameReference { ReferencedSymbol: { } symbol })
                referenceCounts[symbol] = referenceCounts.GetValueOrDefault(symbol) + 1;
        });
        foreach (var node in nodes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            switch (node)
            {
                case BinaryExpression binary: CheckBinary(binary); break;
                case FunctionCallExpression call: CheckFunction(call); break;
                case InExpression membership: CheckMembership(membership, membership.Left, membership.Right, false); break;
                case HasAnyExpression any: CheckMembership(any, any.Left, any.Right, true); break;
                case JoinOperator join: CheckJoin(join); break;
                case SummarizeOperator summarize: CheckProvenance(summarize); break;
                case LetStatement let: CheckReuse(let.Name, let.Expression); break;
                case AsOperator alias when alias.Parent is PipeExpression pipe && !Materialized(alias.Parameters):
                    CheckReuse(alias.Name, pipe.Expression, implicitUse: true); break;
            }
        }
        return diagnostics.DistinctBy(d => (d.RuleId, d.Span.Start)).ToArray();
    }

    private void Add(string id, string message, SyntaxNode node, DiagnosticSeverity? severity = null)
    {
        var effectiveSeverity = severity ?? rules.Get(id).DefaultSeverity;
        if (policy.IsEnabled(id, effectiveSeverity))
            diagnostics.Add(rules.CreateDiagnostic(request.Query, id, message, node.TextStart, node.Width, severity));
    }

    private void CheckBinary(BinaryExpression binary)
    {
        var op = binary.Operator.Text;
        if (op is "has" or "has_cs" or "!has" or "!has_cs" or "hasprefix" or "hasprefix_cs" or "!hasprefix" or "!hasprefix_cs" &&
            binary.Right.ConstantValue is string term && term.Length is > 0 and < 3 && term.All(char.IsLetterOrDigit))
            Add("KQLH006", "Terms shorter than three characters are not term-indexed; narrow the input first.", binary.Right);

        if (op is "==" or "!=" or "<>")
        {
            foreach (var (operand, literal) in new[] { (binary.Left, binary.Right), (binary.Right, binary.Left) })
            {
                if (operand.ResultType == ScalarTypes.String && literal.ResultType == ScalarTypes.String && literal.ConstantValue is string { Length: 0 })
                    Add("KQLP005", "Consider isempty() or isnotempty() for clarity. Comparing a string with an empty string is also valid KQL.", binary);
                if (op == "==" && KnownScalar(operand.ResultType) && operand.ResultType != ScalarTypes.String &&
                    literal.IsConstant && literal.ConstantValue is null && KnownScalar(literal.ResultType))
                    Add("KQLP011", "Equality with a typed null does not identify null rows. Use isnull() to test for null.", binary);
            }
        }
        if (op is "==" or "=~")
        {
            CheckCaseTransform(binary.Left, binary);
            CheckCaseTransform(binary.Right, binary);
        }

        if (op == "matches regex" && binary.Right.ConstantValue is string { Length: > 0 } pattern &&
            pattern.All(c => char.IsLetterOrDigit(c) || c is ' ' or '_' or '-' or '/' or ':'))
            Add("KQLP010", "This regex is a plain case-sensitive substring. Consider contains_cs; has and contains have different matching semantics.", binary);

        if (op == "==")
            CheckWindowsCase(binary);
    }

    private void CheckFunction(FunctionCallExpression call)
    {
        var function = Builtin(call);
        var args = Arguments(call);
        if (function == "count_distinct" || function == "count_distinctif")
            Add("KQLP008", "Consider dcount() (or dcountif()) only if an approximate distinct count is acceptable; exact counts may be required for thresholds.", call);
        if (function is "make_list" or "make_set" && args.Count == 1 ||
            function is "make_list_if" or "make_set_if" && args.Count == 2)
            Add("KQLP009", "This array aggregate uses the large default element cap. Consider an explicit maxSize only when discarding excess values is acceptable.", call);
        if (function == "isnull" && args.Count == 1 && args[0].ResultType == ScalarTypes.String)
            Add("KQLP011", "KQL strings do not contain null. Use isempty() if the intended test is for a missing or empty string.", call);
        if (function is "parse_json" or "todynamic" && args.Count == 1 && args[0].ResultType is DynamicSymbol)
        {
            var arg = JsonField(args[0], 0);
            if (arg is not null)
            {
                var encoded = StaticJson(arg, 0) is { ValueKind: JsonValueKind.String } value && ValidJson(value.GetString());
                Add("KQLP012", "parse_json passes dynamic input through unchanged. If this nested field contains encoded JSON text, use parse_json(tostring(field)); if it is already an object, no second parse is needed.", call,
                    encoded ? DiagnosticSeverity.Warning : null);
            }
        }
    }

    private void CheckMembership(Expression syntax, Expression left, ExpressionList right, bool hasAny)
    {
        var expressions = right.Expressions.Select(x => x.Element).ToArray();
        foreach (var expression in expressions)
            if (expression.ResultType is TableSymbol { Columns.Count: > 1 })
                Add("KQLP016", "This tabular membership input uses only its first column. Explicitly project the intended membership field.", expression);

        var values = new List<string>();
        var staticList = true;
        foreach (var expression in expressions)
            staticList = StaticStrings(expression, values) && staticList;
        if (hasAny && staticList)
        {
            var distinct = values.Distinct(StringComparer.Ordinal).Count();
            if (distinct > 10_000)
                Add("KQLP014", $"This has_any input has {distinct:N0} distinct static values; only up to 10,000 are considered. Restructure the search without changing term semantics.", syntax);
            else if (values.Count > 128)
                Add("KQLP013", $"This has_any input has {values.Count} search terms; more than 128 disables text-index optimization. Narrow the input or review the search structure.", syntax);
            else if (values.Any(v => v.Length is > 0 and < 3 && v.All(char.IsLetterOrDigit)))
                Add("KQLH006", "This has_any list includes terms shorter than three characters, which are not term-indexed; narrow the input first.", syntax);
        }
        if (syntax is InExpression membership)
        {
            var unicode = values.Any(v => v.EnumerateRunes().Any(r => r.Value > 127 && Rune.IsLetter(r)));
            if (membership.Operator.Text is "in~" or "!in~" && unicode)
                Add("KQLP015", "in~ and !in~ support ASCII case-insensitive matching only. Use explicit normalization if Unicode case-insensitive comparison is intended.", syntax);
            if (!unicode)
                CheckCaseTransform(left, syntax);
        }
        if (staticList && values.Distinct(StringComparer.Ordinal).Count() > 10 &&
            (IndicatorColumn(Resolve(left)?.Column) || values.All(Indicator)))
        {
            var suggestion = policy.Target == KqlTarget.DefenderNrt ?
                "Defender NRT does not support joins or externaldata; manage compatible literal data or consider a scheduled target." :
                request.Environment is KqlEnvironment.Sentinel or KqlEnvironment.Unified ?
                    "Consider a managed watchlist or current ThreatIntelIndicators data where appropriate for this target." :
                    "Consider a managed indicator source supported by the query environment and target.";
            Add("KQLD008", "This query embeds more than ten static indicators (a project maintainability heuristic, not a platform limit). " + suggestion, syntax);
        }
    }

    private void CheckCaseTransform(Expression expression, SyntaxNode syntax)
    {
        if (Unwrap(expression) is FunctionCallExpression call && Builtin(call) is "tolower" or "toupper" &&
            Arguments(call) is { Count: 1 } args && Resolve(args[0]) is not null)
            Add("KQLH004", "Avoid transforming every row with tolower()/toupper() when an appropriate string operator preserves the intended semantics. Explicit normalization can be necessary for Unicode comparisons.", syntax);
    }

    private void CheckWindowsCase(BinaryExpression binary)
    {
        foreach (var (operand, literal) in new[] { (binary.Left, binary.Right), (binary.Right, binary.Left) })
        {
            if (Resolve(operand) is not { Table.Name: "DeviceProcessEvents" or "DeviceFileEvents" or "DeviceImageLoadEvents", Column: "FileName" or "FolderPath" or "InitiatingProcessFileName" or "InitiatingProcessFolderPath" } origin ||
                literal.ConstantValue is not string text)
                continue;
            var windows = origin.Column.EndsWith("FolderPath", StringComparison.Ordinal) && WindowsPath(text);
            if (!windows && Ancestor<FilterOperator>(binary) is { } filter)
                windows = WindowsPredicate(filter.Condition) || PrecedingWindowsFilter(filter);
            if (windows)
                Add("KQLD007", "Review case-sensitive filename/path equality in this Windows context. Consider =~ or in~ if case variations should match; case sensitivity can be intentional.", binary);
        }
    }

    private bool PrecedingWindowsFilter(FilterOperator filter)
    {
        if (filter.Parent is not PipeExpression pipe) return false;
        var input = Unwrap(pipe.Expression);
        for (var depth = 0; depth < 64 && input is PipeExpression p; depth++, input = Unwrap(p.Expression))
        {
            if (p.Operator is FilterOperator preceding && WindowsPredicate(preceding.Condition)) return true;
            if (p.Operator is not (FilterOperator or ProjectOperator or ProjectAwayOperator or ProjectRenameOperator or ExtendOperator)) return false;
        }
        return false;
    }

    private bool WindowsPredicate(Expression expression)
    {
        expression = Unwrap(expression);
        if (expression is BinaryExpression { Kind: SyntaxKind.AndExpression } and)
            return WindowsPredicate(and.Left) || WindowsPredicate(and.Right);
        if (expression is not BinaryExpression binary || binary.Operator.Text is not ("==" or "=~" or "startswith" or "startswith_cs")) return false;
        return Resolve(binary.Left) is { Column: "FolderPath" or "InitiatingProcessFolderPath" } &&
            binary.Right.ConstantValue is string path && WindowsPath(path);
    }

    private static bool WindowsPath(string value) => value.Length >= 3 && char.IsAsciiLetter(value[0]) && value[1] == ':' && value[2] == '\\';

    private void CheckReuse(NameDeclaration name, Expression expression, bool implicitUse = false)
    {
        if (name.ReferencedSymbol is not Symbol symbol || referenceCounts.GetValueOrDefault(symbol) < (implicitUse ? 1 : 2) ||
            !Nondeterministic(expression, new HashSet<Symbol>(), 0)) return;
        Add("KQLP017", "This nondeterministic named expression is referenced more than once and may be recalculated. Use toscalar for a scalar or materialize/hint.materialized=true for tabular data when references must share one evaluation; consider cache costs.", name);
    }

    private bool Nondeterministic(Expression expression, HashSet<Symbol> visiting, int depth)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (depth > 64 || expression is MaterializeExpression || expression is ToScalarExpression ||
            expression is PipeExpression { Operator: AsOperator rootAlias } && Materialized(rootAlias.Parameters)) return false;
        if (expression is NameReference { ReferencedSymbol: VariableSymbol { Source: { } source } variable })
            return visiting.Add(variable) && Nondeterministic(source, visiting, depth + 1);
        if (expression is FunctionCallExpression call && Builtin(call) is "rand" or "sample") return true;
        if (expression is SampleOperator) return true;
        if (expression is TakeOperator && expression.Parent is PipeExpression pipe && !Sorted(pipe.Expression)) return true;
        if (expression is AsOperator alias && Materialized(alias.Parameters)) return false;
        var found = false;
        SyntaxElement.WalkNodes(expression, n =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (ReferenceEquals(n, expression)) return;
            if (n is NameReference { ReferencedSymbol: VariableSymbol { Source: { } source } variable } && visiting.Add(variable))
                found |= Nondeterministic(source, visiting, depth + 1);
            if (n is FunctionCallExpression c && Builtin(c) is "rand" or "sample" || n is SampleOperator ||
                n is TakeOperator && n.Parent is PipeExpression p && !Sorted(p.Expression)) found = true;
        }, fnDescend: n => n is not (MaterializeExpression or ToScalarExpression) &&
            (n is not AsOperator a || !Materialized(a.Parameters)) &&
            (n is not PipeExpression { Operator: AsOperator p } || !Materialized(p.Parameters)));
        return found;
    }

    private static bool Sorted(Expression expression) => expression switch
    {
        ParenthesizedExpression p => Sorted(p.Expression),
        PipeExpression { Operator: SortOperator or TopOperator } => true,
        PipeExpression p when p.Operator is FilterOperator or ProjectOperator or ProjectAwayOperator or ProjectRenameOperator or ExtendOperator => Sorted(p.Expression),
        _ => false,
    };

    private void CheckProvenance(SummarizeOperator summarize)
    {
        var aggregates = summarize.Aggregates.Select(a => Unwrap(a.Element)).OfType<FunctionCallExpression>().ToArray();
        var eventTime = aggregates.Where(c => Builtin(c) is "max" or "min" or "take_any" && Arguments(c).Count == 1 &&
            Resolve(Arguments(c)[0]) is { Column: "Timestamp" or "TimeGenerated" } o && EventTable(o.Table)).ToArray();
        var reportId = aggregates.Where(c => Builtin(c) is "take_any" or "max" or "min" && Arguments(c).Count == 1 &&
            Resolve(Arguments(c)[0]) is { Column: "ReportId" } o && EventTable(o.Table)).ToArray();
        var groupedOrigins = summarize.ByClause?.Expressions.Select(g => Resolve(Unwrap(g.Element))).Where(o => o is not null).ToArray() ?? [];
        eventTime = eventTime.Where(c => !groupedOrigins.Contains(Resolve(Arguments(c)[0]))).ToArray();
        reportId = reportId.Where(c => !groupedOrigins.Contains(Resolve(Arguments(c)[0]))).ToArray();
        if (eventTime.Any(time => reportId.Any(id => !ReferenceEquals(time, id) &&
            Resolve(Arguments(time)[0])?.Table == Resolve(Arguments(id)[0])?.Table)) &&
            code.ResultType is TableSymbol output && CarriesAggregate(output, summarize, eventTime, true) && CarriesAggregate(output, summarize, reportId, false))
            Add("KQLD009", "Separate aggregates can select event time and ReportId from different records. Use arg_max(Timestamp, ReportId, ...) for the latest event, or one joint take_any(...) if any single event is sufficient.", summarize);
    }

    private static bool CarriesAggregate(TableSymbol output, SummarizeOperator summarize, IReadOnlyList<FunctionCallExpression> calls, bool eventTime)
    {
        var selected = summarize.Aggregates.Where(a => calls.Contains(Unwrap(a.Element))).Select(a =>
            a.Element is SimpleNamedExpression named ? named.Name.ReferencedSymbol as ColumnSymbol : null).OfType<ColumnSymbol>().ToArray();
        return output.Columns.Where(c => eventTime ? c.Name is "Timestamp" or "TimeGenerated" : c.Name == "ReportId")
            .Any(c => selected.Any(target => CarriesColumn(c, target, new HashSet<ColumnSymbol>(), 0)) ||
                FromAggregate(c, calls, new HashSet<ColumnSymbol>(), 0));
    }

    private static bool CarriesColumn(ColumnSymbol column, ColumnSymbol target, HashSet<ColumnSymbol> visited, int depth)
    {
        if (ReferenceEquals(column, target)) return true;
        if (depth > 64 || !visited.Add(column)) return false;
        if (column.Source is Expression source && Unwrap(source).ReferencedSymbol is ColumnSymbol original &&
            CarriesColumn(original, target, visited, depth + 1)) return true;
        return column.OriginalColumns.Any(c => CarriesColumn(c, target, visited, depth + 1));
    }

    private static bool FromAggregate(ColumnSymbol column, IReadOnlyList<FunctionCallExpression> calls, HashSet<ColumnSymbol> visited, int depth)
    {
        if (depth > 64 || !visited.Add(column)) return false;
        if (column.Source is Expression expression)
        {
            expression = Unwrap(expression);
            if (expression is FunctionCallExpression call && calls.Contains(call)) return true;
            if (expression.ReferencedSymbol is ColumnSymbol source && FromAggregate(source, calls, visited, depth + 1)) return true;
        }
        return column.OriginalColumns.Any(c => FromAggregate(c, calls, visited, depth + 1));
    }

    private void CheckJoin(JoinOperator join)
    {
        if (join.ConditionClause is not JoinOnClause on || join.Parent is not PipeExpression pipe ||
            pipe.Expression.ResultType is not TableSymbol left || join.Expression.ResultType is not TableSymbol right) return;
        var kind = join.Parameters.FirstOrDefault(p => p.Name.SimpleName == "kind")?.Expression.ToString().Trim() ?? "innerunique";
        var keys = new List<(ColumnSymbol Left, ColumnSymbol Right)>();
        var complete = on.Expressions.All(e => JoinKeys(e.Element, left, right, keys));
        if (!complete || keys.Count == 0) return;
        if (kind == "leftsemi" && keys.Count == 1 && join.Parameters.All(p => p.Name.SimpleName == "kind") &&
            keys[0].Left.Type == keys[0].Right.Type && keys[0].Left.Type == ScalarTypes.String && !Remote(join.Expression) && !Remote(pipe.Expression))
            Add("KQLP018", "Consider in with an explicitly projected single-column RHS for this leftsemi membership join, if matching semantics and service limits permit. Benchmark before changing strategy.", join);
        if (kind is "leftsemi" or "rightsemi" or "leftanti" or "rightanti" or "anti" or "leftantisemi" or "rightantisemi") return;
        var leftOrigins = keys.Select(k => ResolveColumn(k.Left, 0)).ToArray();
        var rightOrigins = keys.Select(k => ResolveColumn(k.Right, 0)).ToArray();
        if (leftOrigins.Any(o => o is null) || rightOrigins.Any(o => o is null)) return;
        var lt = leftOrigins.Select(o => o!.Table).Distinct().ToArray();
        var rt = rightOrigins.Select(o => o!.Table).Distinct().ToArray();
        if (lt.Length != 1 || rt.Length != 1 || !EventTable(lt[0]) || !EventTable(rt[0]) ||
            HasAggregate(pipe.Expression) || HasAggregate(join.Expression)) return;
        if (leftOrigins.Concat(rightOrigins).All(o => o!.Column is "ActionType" or "EventID" or "EventId" or "OperationName" or "LogonType"))
            Add("KQLH015", "This event join matches only categorical keys. Matching rows can multiply within each category; review whether an entity key is intended.", on);
        var compatibleKeys = leftOrigins.Zip(rightOrigins).Where(pair => pair.First!.Column == pair.Second!.Column).Select(pair => pair.First!.Column).ToHashSet(StringComparer.Ordinal);
        var endpoint = lt[0].Name.StartsWith("Device", StringComparison.Ordinal) || rt[0].Name.StartsWith("Device", StringComparison.Ordinal);
        if (compatibleKeys.Contains("ReportId") && (!endpoint || compatibleKeys.Contains("DeviceId")) ||
            compatibleKeys.Overlaps(["NetworkMessageId", "AlertId", "Timestamp", "TimeGenerated"])) return;
        // Shared source symbols cannot distinguish the roles of self-join timestamps reliably.
        if (lt[0] == rt[0]) return;
        var leftTime = left.Columns.Where(c => ResolveColumn(c, 0) is { Column: "Timestamp" or "TimeGenerated" } o && o.Table == lt[0]).ToArray();
        var rightTime = right.Columns.Where(c => ResolveColumn(c, 0) is { Column: "Timestamp" or "TimeGenerated" } o && o.Table == rt[0]).ToArray();
        if (leftTime.Length > 0 && rightTime.Length > 0 && !ProximityAfter(pipe, leftTime, rightTime))
            Add("KQLQ005", "These event streams are joined without a recognized cross-input time proximity constraint. Review whether temporal correlation is required; a suitable window depends on the behavior being detected.", join);
    }

    private bool JoinKeys(Expression expression, TableSymbol left, TableSymbol right, List<(ColumnSymbol Left, ColumnSymbol Right)> keys)
    {
        expression = Unwrap(expression);
        if (expression is BinaryExpression { Kind: SyntaxKind.AndExpression } and)
            return JoinKeys(and.Left, left, right, keys) && JoinKeys(and.Right, left, right, keys);
        if (expression is NameReference name)
        {
            var l = left.Columns.FirstOrDefault(c => c.Name == name.SimpleName);
            var r = right.Columns.FirstOrDefault(c => c.Name == name.SimpleName);
            if (l is null || r is null) return false;
            keys.Add((l, r)); return true;
        }
        if (expression is BinaryExpression { Kind: SyntaxKind.EqualExpression } equal &&
            equal.Left.ReferencedSymbol is ColumnSymbol lc && equal.Right.ReferencedSymbol is ColumnSymbol rc)
        {
            if (JoinSide(equal.Left) == "$right" && JoinSide(equal.Right) == "$left") (lc, rc) = (rc, lc);
            else if (JoinSide(equal.Left) != "$left" || JoinSide(equal.Right) != "$right") return false;
            if (!left.Columns.Contains(lc) || !right.Columns.Contains(rc)) return false;
            keys.Add((lc, rc)); return true;
        }
        return false;
    }

    private bool ProximityAfter(PipeExpression joinPipe, ColumnSymbol[] leftTimes, ColumnSymbol[] rightTimes)
    {
        SyntaxNode current = joinPipe;
        var bounds = 0;
        for (var depth = 0; depth < 64 && current.Parent is PipeExpression parent && ReferenceEquals(parent.Expression, current); depth++, current = parent)
        {
            if (parent.Operator is FilterOperator filter)
                bounds |= TimeBounds(filter.Condition, leftTimes, rightTimes);
            if (bounds == 3) return true;
            if (parent.Operator is not (FilterOperator or ExtendOperator or ProjectOperator or ProjectRenameOperator or ProjectAwayOperator)) break;
        }
        return false;
    }

    // Bit 1 bounds the lower event-time delta, bit 2 the upper. One-sided ordering alone is not proximity.
    private int TimeBounds(Expression condition, ColumnSymbol[] leftTimes, ColumnSymbol[] rightTimes)
    {
        condition = Unwrap(condition);
        if (condition is BinaryExpression { Kind: SyntaxKind.AndExpression } and)
            return TimeBounds(and.Left, leftTimes, rightTimes) | TimeBounds(and.Right, leftTimes, rightTimes);
        if (condition is BetweenExpression between && between.Operator.Text == "between")
            return ComparisonBound(between.Left, between.Right.First, ">=", leftTimes, rightTimes) |
                ComparisonBound(between.Left, between.Right.Second, "<=", leftTimes, rightTimes);
        return condition is BinaryExpression binary ? ComparisonBound(binary.Left, binary.Right, binary.Operator.Text, leftTimes, rightTimes) : 0;
    }

    private int ComparisonBound(Expression left, Expression right, string op, ColumnSymbol[] leftTimes, ColumnSymbol[] rightTimes)
    {
        if (op is not ("<" or "<=" or ">" or ">=" or "==")) return 0;
        left = Unwrap(left); right = Unwrap(right);
        if (right is FunctionCallExpression rightCall && Builtin(rightCall) == "abs")
        {
            (left, right) = (right, left);
            op = op switch { "<" => ">", "<=" => ">=", ">" => "<", ">=" => "<=", _ => op };
        }
        if (left is FunctionCallExpression abs && Builtin(abs) == "abs" && Arguments(abs) is { Count: 1 } args &&
            right.ConstantValue is TimeSpan { Ticks: >= 0 } && op is "<" or "<=" or "==" &&
            LinearTime(args[0], leftTimes, rightTimes, 0) is { Left: 1, Right: -1 } or { Left: -1, Right: 1 }) return 3;
        if (left is FunctionCallExpression diffAbs && Builtin(diffAbs) == "abs" && Arguments(diffAbs) is { Count: 1 } diffArgs &&
            Unwrap(diffArgs[0]) is FunctionCallExpression diff && Builtin(diff) == "datetime_diff" &&
            Arguments(diff) is { Count: 3 } dateArgs && dateArgs[0].ConstantValue is string unit &&
            unit is "year" or "quarter" or "month" or "week" or "day" or "hour" or "minute" or "second" or "millisecond" or "microsecond" or "nanosecond" &&
            right.ConstantValue is long or int or double or decimal && Convert.ToDouble(right.ConstantValue, System.Globalization.CultureInfo.InvariantCulture) >= 0 &&
            op is "<" or "<=" or "==")
        {
            var first = LinearTime(dateArgs[1], leftTimes, rightTimes, 0);
            var second = LinearTime(dateArgs[2], leftTimes, rightTimes, 0);
            if (first is not null && second is not null && Math.Abs(first.Left - second.Left) == 1 &&
                first.Left - second.Left == -(first.Right - second.Right)) return 3;
        }
        var l = LinearTime(left, leftTimes, rightTimes, 0);
        var r = LinearTime(right, leftTimes, rightTimes, 0);
        if (l is null || r is null) return 0;
        var deltaLeft = l.Left - r.Left;
        var deltaRight = l.Right - r.Right;
        if (Math.Abs(deltaLeft) != 1 || deltaLeft != -deltaRight) return 0;
        if (op == "==") return 3;
        var upper = op is "<" or "<=";
        return upper == (deltaLeft == 1) ? 2 : 1;
    }

    private TimeCoefficients? LinearTime(Expression expression, ColumnSymbol[] leftTimes, ColumnSymbol[] rightTimes, int depth)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (depth > 64) return null;
        expression = Unwrap(expression);
        if (expression.ConstantValue is TimeSpan) return new(0, 0);
        if (expression is PrefixUnaryExpression unary && unary.Operator.Text is "+" or "-" && unary.Expression.ConstantValue is TimeSpan) return new(0, 0);
        if (expression.ReferencedSymbol is ColumnSymbol column)
        {
            var left = leftTimes.Any(c => CarriesColumn(column, c, new HashSet<ColumnSymbol>(), 0));
            var right = rightTimes.Any(c => CarriesColumn(column, c, new HashSet<ColumnSymbol>(), 0));
            if (left != right) return left ? new(1, 0) : new(0, 1);
            return column.Source is Expression source ? LinearTime(source, leftTimes, rightTimes, depth + 1) : null;
        }
        if (expression is NameReference { ReferencedSymbol: VariableSymbol { Source: { } variableSource } })
            return LinearTime(variableSource, leftTimes, rightTimes, depth + 1);
        if (expression is BinaryExpression binary && binary.Operator.Text is "+" or "-")
        {
            var left = LinearTime(binary.Left, leftTimes, rightTimes, depth + 1);
            var right = LinearTime(binary.Right, leftTimes, rightTimes, depth + 1);
            if (left is null || right is null) return null;
            var sign = binary.Operator.Text == "+" ? 1 : -1;
            return new(left.Left + sign * right.Left, left.Right + sign * right.Right);
        }
        return null;
    }

    private sealed record TimeCoefficients(int Left, int Right);

    private bool HasAggregate(Expression expression, int depth = 0)
    {
        if (depth > 64) return true;
        expression = Unwrap(expression);
        if (expression is MaterializeExpression materialized) return HasAggregate(materialized.Expression, depth + 1);
        if (expression is NameReference { ReferencedSymbol: VariableSymbol { Source: { } source } }) return HasAggregate(source, depth + 1);
        if (expression is PipeExpression pipe) return pipe.Operator is SummarizeOperator or DistinctOperator || HasAggregate(pipe.Expression, depth + 1);
        return false;
    }

    private bool Remote(Expression expression, int depth = 0)
    {
        if (depth > 64) return true;
        var remote = false;
        SyntaxElement.WalkNodes(expression, n =>
        {
            if (n is FunctionCallExpression call && Builtin(call) is "cluster" or "database") remote = true;
            if (n is NameReference { ReferencedSymbol: VariableSymbol { Source: { } source } }) remote |= Remote(source, depth + 1);
        });
        return remote;
    }

    private bool StaticStrings(Expression expression, List<string> values, int depth = 0)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (depth > 64) return false;
        expression = Unwrap(expression);
        if (expression.ConstantValue is string value && expression.ResultType == ScalarTypes.String) { values.Add(value); return true; }
        if (expression is NameReference { ReferencedSymbol: VariableSymbol { Source: { } source } }) return StaticStrings(source, values, depth + 1);
        if (expression is DynamicExpression dynamic) return StaticStrings(dynamic.Expression, values, depth + 1);
        if (expression is JsonArrayExpression array)
            return array.Values.All(v => StaticStrings(v.Element, values, depth + 1));
        return false;
    }

    private JsonElement? StaticJson(Expression expression, int depth)
    {
        if (depth > 64) return null;
        expression = Unwrap(expression);
        if (expression is NameReference { ReferencedSymbol: VariableSymbol { Source: { } source } }) return StaticJson(source, depth + 1);
        if (expression is NameReference { ReferencedSymbol: ColumnSymbol { Source: Expression columnSource } }) return StaticJson(columnSource, depth + 1);
        if (expression is FunctionCallExpression call && Builtin(call) is "parse_json" or "todynamic" &&
            Arguments(call) is { Count: 1 } args && args[0].ConstantValue is string text)
        {
            try { using var document = JsonDocument.Parse(text); return document.RootElement.Clone(); }
            catch (JsonException) { return null; }
        }
        if (expression is PathExpression path && path.Selector is NameReference selector && StaticJson(path.Expression, depth + 1) is { ValueKind: JsonValueKind.Object } obj &&
            obj.TryGetProperty(selector.SimpleName, out var property)) return property;
        if (expression is ElementExpression element && element.Selector is BracketedExpression bracket && bracket.Expression.ConstantValue is string key &&
            StaticJson(element.Expression, depth + 1) is { ValueKind: JsonValueKind.Object } bag && bag.TryGetProperty(key, out var item)) return item;
        return null;
    }

    private static bool ValidJson(string? text)
    {
        if (text is null) return false;
        try { using var document = JsonDocument.Parse(text); return document.RootElement.ValueKind is JsonValueKind.Object or JsonValueKind.Array; }
        catch (JsonException) { return false; }
    }

    private Expression? JsonField(Expression expression, int depth)
    {
        if (depth > 64) return null;
        expression = Unwrap(expression);
        if (expression is NameReference { ReferencedSymbol: ColumnSymbol column })
        {
            if (column.Source is Expression source) return JsonField(source, depth + 1);
            if (column.OriginalColumns.Count == 1 && column.OriginalColumns[0].Source is Expression original) return JsonField(original, depth + 1);
        }
        if (expression is NameReference { ReferencedSymbol: VariableSymbol { Source: { } variableSource } }) return JsonField(variableSource, depth + 1);
        if (expression is PathExpression path && FromJson(path.Expression) || expression is ElementExpression element && FromJson(element.Expression)) return expression;
        return null;
    }

    private bool FromJson(Expression expression, int depth = 0)
    {
        if (depth > 64) return false;
        expression = Unwrap(expression);
        if (expression is FunctionCallExpression call) return Builtin(call) is "parse_json" or "todynamic";
        if (expression is PathExpression path) return FromJson(path.Expression, depth + 1);
        if (expression is ElementExpression element) return FromJson(element.Expression, depth + 1);
        if (expression is NameReference { ReferencedSymbol: ColumnSymbol { Source: Expression source } }) return FromJson(source, depth + 1);
        if (expression is NameReference { ReferencedSymbol: VariableSymbol { Source: { } variableSource } }) return FromJson(variableSource, depth + 1);
        return false;
    }

    private Origin? Resolve(Expression expression, int depth = 0)
    {
        if (depth > 64) return null;
        expression = Unwrap(expression);
        return expression.ReferencedSymbol is ColumnSymbol column ? ResolveColumn(column, depth + 1) : null;
    }

    private Origin? ResolveColumn(ColumnSymbol column, int depth)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (depth > 64) return null;
        if (physical.TryGetValue(column, out var origin)) return origin;
        if (origins.TryGetValue(column, out var cached)) return cached;
        origins[column] = null;
        if (column.Source is Expression source) origin = Resolve(source, depth + 1);
        else if (column.OriginalColumns.Count > 0)
        {
            var originals = column.OriginalColumns.Select(c => ResolveColumn(c, depth + 1)).ToArray();
            origin = originals.All(o => o is not null) && originals.Distinct().Count() == 1 ? originals[0] : null;
        }
        else origin = null;
        origins[column] = origin;
        return origin;
    }

    private string? Builtin(FunctionCallExpression call) => call.ReferencedSymbol is FunctionSymbol f && builtins.Contains(f) ? f.Name : null;
    private static IReadOnlyList<Expression> Arguments(FunctionCallExpression call) => call.ArgumentList.Expressions.Select(a => a.Element).ToArray();
    private static Expression Unwrap(Expression expression) => expression switch
    {
        ParenthesizedExpression p => Unwrap(p.Expression),
        SimpleNamedExpression n => Unwrap(n.Expression),
        _ => expression,
    };
    private static bool KnownScalar(TypeSymbol? type) => type is ScalarSymbol && type != ScalarTypes.Unknown;
    private static bool Materialized(SyntaxList<NamedParameter> parameters) => parameters.Any(p => p.Name.SimpleName == "hint.materialized" && p.Expression.ConstantValue is true);
    private static string? JoinSide(Expression expression) => expression is PathExpression { Expression: NameReference name } ? name.SimpleName : null;
    private static bool EventTable(TableSymbol table) => table.Columns.Any(c => c.Name is "Timestamp" or "TimeGenerated") &&
        table.Name is not ("DeviceInfo" or "DeviceNetworkInfo" or "DeviceFileCertificateInfo" or "IdentityInfo") &&
        (table.Columns.Any(c => c.Name is "ReportId" or "EventID" or "EventId" or "ActionType") || table.Name is "SigninLogs" or "AuditLogs" or "AzureActivity" or "OfficeActivity");
    private static bool IndicatorColumn(string? name) => name is "RemoteIP" or "LocalIP" or "IPAddress" or "SHA1" or "SHA256" or "MD5" or "RemoteUrl" or "Url" or "UrlDomain";
    private static bool Indicator(string value) => IPAddress.TryParse(value, out _) ||
        value.Length is 32 or 40 or 64 && value.All(char.IsAsciiHexDigit) ||
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https" ||
        Uri.CheckHostName(value) == UriHostNameType.Dns && value.Contains('.') && !value.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
    private static T? Ancestor<T>(SyntaxNode node) where T : SyntaxNode
    {
        for (var p = node.Parent; p is not null; p = p.Parent) if (p is T found) return found;
        return null;
    }
    private sealed record Origin(TableSymbol Table, string Column);
}
