using System.Text.Json;
using System.Text.Json.Serialization;
using Kusto.Language.Symbols;
using Kusto.Language.Syntax;

namespace KqlValidator.Validation;

/// <summary>Microsoft's baseline with overrides scoped to operand forms and types.</summary>
public sealed class DefenderNrtFeatures
{
    public const string DocumentationUrl = "https://github.com/f-bader/KQLValidator/blob/main/src/KqlValidator.Api/Schemas/defender-nrt-overrides.json";
    public const string Endpoint = "https://security.microsoft.com/apiproxy/hunting/huntingService/rules/checkCompatibility";
    private readonly Dictionary<string, NrtFeatureOverride> overrides;

    public DefenderNrtFeatures(string? path = null)
    {
        var snapshot = JsonSerializer.Deserialize<NrtFeatureSnapshot>(
            File.ReadAllText(path ?? Path.Combine(AppContext.BaseDirectory, "Schemas", "defender-nrt-overrides.json")), JsonOptions)
            ?? throw new InvalidDataException("The Defender NRT override snapshot is empty.");
        if (snapshot.Version != 1 || snapshot.Endpoint != Endpoint || snapshot.Overrides is null)
            throw new InvalidDataException("The Defender NRT override snapshot has an unsupported version or endpoint.");
        overrides = new(StringComparer.Ordinal);
        foreach (var entry in snapshot.Overrides)
        {
            if (entry.Kind is not ("operator" or "function") || string.IsNullOrWhiteSpace(entry.Name) ||
                string.IsNullOrWhiteSpace(entry.Shape) || entry.Shape.Contains("expression", StringComparison.Ordinal) ||
                entry.ArgumentTypes is null || entry.ArgumentTypes.Count == 0 || entry.ArgumentTypes.Any(t => !AzureMonitorTransformationFeatures.ScalarTypes.Contains(t)) ||
                !overrides.TryAdd(Key(entry.Kind, entry.Name, entry.Shape, entry.ArgumentTypes), entry))
                throw new InvalidDataException("The Defender NRT override snapshot contains an invalid or duplicate entry.");
        }
    }

    public static JsonSerializerOptions JsonOptions { get; } = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public bool? ObservedSupport(NrtFeatureUse feature) => overrides.TryGetValue(feature.Key, out var entry) ? entry.Supported : null;

    public bool Supports(NrtFeatureUse feature) => ObservedSupport(feature) ?? Documented(feature.Kind, feature.Name);

    public static bool Documented(string kind, string name) => kind == "function"
        ? AzureMonitorTransformationFeatures.AllowedFunctions.Contains(name)
        : name is "==" or "!=" or "=~" or "!~" or "<" or "<=" or ">" or ">=" or "between" or "!between" or
            "contains" or "!contains" or "contains_cs" or "!contains_cs" or "has" or "!has" or "has_cs" or "!has_cs" or
            "startswith" or "!startswith" or "startswith_cs" or "!startswith_cs" or "endswith" or "!endswith" or
            "endswith_cs" or "!endswith_cs" or "matches regex" or "in" or "!in";

    public static string Key(string kind, string name, string shape, IReadOnlyList<string> types) =>
        $"{kind}:{name}:{shape}:{string.Join(',', types)}";

    public static string CanonicalOperator(string text) => text.ToLowerInvariant() switch
    {
        "<>" => "!=",
        "containscs" => "contains_cs",
        "notcontains" => "!contains",
        "notcontainscs" => "!contains_cs",
        "likecs" => "like_cs",
        "notlike" => "!like",
        "notlikecs" => "!like_cs",
        var value => value,
    };

    public static NrtFeatureUse? GetUse(SyntaxNode node)
    {
        switch (node)
        {
            case BinaryExpression binary when SyntaxFacts.GetOperatorKind(binary.Operator.Kind) is not
                (OperatorKind.None or OperatorKind.And or OperatorKind.Or or OperatorKind.Add or OperatorKind.Subtract or
                 OperatorKind.Multiply or OperatorKind.Divide or OperatorKind.Modulo):
                return Use("operator", CanonicalOperator(binary.Operator.Text), Shape(binary.Right),
                    [Type(binary.Left), Type(binary.Right)], binary.Operator);
            case InExpression membership:
                return Membership(membership.Operator, membership.Left, membership.Right.Expressions.Select(x => x.Element));
            case HasAnyExpression any:
                return Membership(any.Operator, any.Left, any.Right.Expressions.Select(x => x.Element));
            case HasAllExpression all:
                return Membership(all.Operator, all.Left, all.Right.Expressions.Select(x => x.Element));
            case BetweenExpression between:
                return Use("operator", CanonicalOperator(between.Operator.Text), $"range-{Shape(between.Right.First)}-{Shape(between.Right.Second)}",
                    [Type(between.Left), Type(between.Right.First), Type(between.Right.Second)], between.Operator);
            case FunctionCallExpression call:
                var args = call.ArgumentList.Expressions.Select(x => x.Element).ToArray();
                var shape = string.Join('-', args.Select(Shape));
                return Use("function", call.Name.SimpleName, shape, args.Select(Type).ToArray(), call.Name);
            default:
                return null;
        }
    }

    private static NrtFeatureUse Membership(SyntaxToken token, Expression left, IEnumerable<Expression> expressions)
    {
        var args = expressions.ToArray();
        var shape = args.All(Literal) ? args is [DynamicExpression dynamic] ? Shape(dynamic) : "literal-list"
            : args.Length == 1 ? MembershipShape(args[0])
            : args.All(arg => arg is LiteralExpression || LiteralVariable(arg)) ? "literal-variable-list" : "expression-list";
        // List length varies independently of operand type. Keep one type for each distinct RHS type.
        return Use("operator", CanonicalOperator(token.Text), shape,
            new[] { Type(left) }.Concat(args.Select(Type).Distinct().Order(StringComparer.Ordinal)).ToArray(), token);
    }

    private static bool LiteralVariable(Expression expression) => expression is NameReference
    {
        ReferencedSymbol: VariableSymbol { Source: LiteralExpression },
    };

    private static string MembershipShape(Expression expression) => expression is NameReference
    {
        ReferencedSymbol: VariableSymbol { Type: var type },
    } && type == ScalarTypes.String && !LiteralVariable(expression) ? "expression" : Shape(expression);

    private static string Shape(Expression expression) => expression switch
    {
        DynamicExpression { Expression: JsonArrayExpression } => "dynamic-array",
        DynamicExpression { Expression: JsonObjectExpression } => "dynamic-object",
        LiteralExpression => "literal",
        NameReference { ReferencedSymbol: ColumnSymbol } => "column",
        NameReference { ReferencedSymbol: VariableSymbol } => "scalar-variable",
        _ => "expression",
    };

    private static bool Literal(Expression expression) => expression is LiteralExpression or DynamicExpression;
    private static string Type(Expression expression) => expression.ResultType?.Name ?? "unknown";
    private static NrtFeatureUse Use(string kind, string name, string shape, string[] types, SyntaxElement span) =>
        new(kind, name, shape, types, span.TextStart, span.Width);
}

public sealed record NrtFeatureUse(string Kind, string Name, string Shape, IReadOnlyList<string> ArgumentTypes, int Start, int Length)
{
    public string Key => DefenderNrtFeatures.Key(Kind, Name, Shape, ArgumentTypes);
}

public sealed record NrtFeatureOverride(string Kind, string Name, string Shape, IReadOnlyList<string> ArgumentTypes,
    [property: JsonRequired] bool Supported);
public sealed record NrtFeatureSnapshot(int Version, string Endpoint, IReadOnlyList<NrtFeatureOverride> Overrides);
