using System.Text.RegularExpressions;
using KqlValidator.Contracts;

namespace KqlValidator.Validation;

public sealed partial class RequestValidator(SchemaCatalog catalog, LintRuleCatalog lintRules)
{
    private const int MaxDeclarations = 100;
    private const int MaxColumns = 5_000;
    private const int MaxParameters = 1_000;
    private const int MaxLintSelections = 100;
    private const int MaxIdentifierLength = 128;

    public void Validate(ValidateRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Query))
            throw new RequestValidationException("query", "Query must not be empty.");
        if (request.Query.Length > 65_536)
            throw new RequestValidationException("query", "Query exceeds the 64 KiB character limit.");
        if (!Enum.IsDefined(request.Environment))
            throw new RequestValidationException("environment", "Environment must be xdr, sentinel, or unified.");
        if (!Enum.IsDefined(request.Profile))
            throw new RequestValidationException("profile", "Profile must be general, hunting, or detection.");
        ValidateTarget(request);
        ValidateLintOptions(request.Lint);

        var extensions = request.Extensions;
        if (extensions is null)
            return;
        if (extensions.Tables?.Count > MaxDeclarations) throw Limit("tables", MaxDeclarations);
        if (extensions.Functions?.Count > MaxDeclarations) throw Limit("functions", MaxDeclarations);
        if (extensions.Watchlists?.Count > MaxDeclarations) throw Limit("watchlists", MaxDeclarations);
        if (extensions.Tables?.Any(x => x is null) == true ||
            extensions.Functions?.Any(x => x is null) == true ||
            extensions.Watchlists?.Any(x => x is null) == true)
            throw new RequestValidationException("extensions", "Extension declarations must not contain null entries.");

        var tables = extensions.Tables ?? [];
        var functions = extensions.Functions ?? [];
        var watchlists = extensions.Watchlists ?? [];
        foreach (var table in tables)
        {
            ValidateIdentifier(table.Name, "table name");
            if (table.Columns is null)
                throw new RequestValidationException("extensions.tables", $"Table '{table.Name}' requires columns.");
            ValidateColumns(table.Columns, $"table '{table.Name}'");
        }

        foreach (var watchlist in watchlists)
        {
            ValidateIdentifier(watchlist.Name, "watchlist alias");
            if (watchlist.Columns is null)
                throw new RequestValidationException("extensions.watchlists", $"Watchlist '{watchlist.Name}' requires columns.");
            ValidateColumns(watchlist.Columns, $"watchlist '{watchlist.Name}'");
        }

        foreach (var function in functions)
            ValidateFunction(function);

        var columnCount = tables.Sum(x => x.Columns.Count) +
            functions.Sum(x => x.Returns.Columns?.Count ?? 0) +
            watchlists.Sum(x => x.Columns.Count);
        if (columnCount > MaxColumns) throw Limit("columns", MaxColumns);
        if (functions.Sum(x => x.Parameters?.Count ?? 0) > MaxParameters) throw Limit("function parameters", MaxParameters);

        var schema = catalog.Get(request.Environment);
        var names = new HashSet<string>(schema.Tables.Keys.Concat(schema.Functions.Keys), StringComparer.OrdinalIgnoreCase);
        foreach (var name in tables.Select(x => x.Name).Concat(functions.Select(x => x.Name)))
        {
            if (!names.Add(name))
                throw new RequestValidationException("extensions", $"Extension name '{name}' collides with another declaration or built-in.");
        }

        var watchlistNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var watchlist in watchlists)
        {
            if (!watchlistNames.Add(watchlist.Name))
                throw new RequestValidationException("extensions", $"Duplicate watchlist alias '{watchlist.Name}'.");
        }
    }

    private static void ValidateFunction(FunctionDeclaration function)
    {
        ValidateIdentifier(function.Name, "function name");
        if (function.Returns is null)
            throw new RequestValidationException("extensions.functions", $"Function '{function.Name}' requires a return declaration.");

        var parameters = function.Parameters ?? [];
        if (parameters.Any(x => x is null))
            throw new RequestValidationException("extensions.functions", $"Function '{function.Name}' contains a null parameter.");
        var parameterNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var optionalSeen = false;
        foreach (var parameter in parameters)
        {
            ValidateIdentifier(parameter.Name, "parameter name");
            if (!parameterNames.Add(parameter.Name))
                throw new RequestValidationException("extensions.functions", $"Function '{function.Name}' has duplicate parameter '{parameter.Name}'.");
            ValidateType(parameter.Type, $"parameter '{parameter.Name}'");
            if (!parameter.Optional && optionalSeen)
                throw new RequestValidationException("extensions.functions", $"Required parameter '{parameter.Name}' cannot follow an optional parameter.");
            optionalSeen |= parameter.Optional;
        }

        if (function.Returns.Kind?.Equals("scalar", StringComparison.OrdinalIgnoreCase) == true)
        {
            if (string.IsNullOrWhiteSpace(function.Returns.Type))
                throw new RequestValidationException("extensions.functions", $"Scalar function '{function.Name}' requires a return type.");
            ValidateType(function.Returns.Type, $"function '{function.Name}' return type");
            if (function.Returns.PreserveInput)
                throw new RequestValidationException("extensions.functions", $"Scalar function '{function.Name}' cannot preserve tabular input.");
        }
        else if (function.Returns.Kind?.Equals("tabular", StringComparison.OrdinalIgnoreCase) == true)
        {
            if (function.Returns.Columns is null)
                throw new RequestValidationException("extensions.functions", $"Tabular function '{function.Name}' requires a columns collection.");
            ValidateColumns(function.Returns.Columns, $"function '{function.Name}' return");
        }
        else
            throw new RequestValidationException("extensions.functions", $"Function '{function.Name}' return kind must be scalar or tabular.");
    }

    private static void ValidateColumns(IReadOnlyList<ColumnDeclaration> columns, string owner)
    {
        if (columns.Any(x => x is null))
            throw new RequestValidationException("extensions", $"The {owner} contains a null column.");
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var column in columns)
        {
            ValidateIdentifier(column.Name, "column name");
            if (!names.Add(column.Name))
                throw new RequestValidationException("extensions", $"The {owner} has duplicate column '{column.Name}'.");
            ValidateType(column.Type, $"column '{column.Name}'");
        }
    }

    private static void ValidateIdentifier(string? value, string kind)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > MaxIdentifierLength || !Identifier().IsMatch(value))
            throw new RequestValidationException("extensions", $"'{value}' is not a valid {kind}.");
    }

    private static void ValidateType(string? type, string field)
    {
        if (string.IsNullOrWhiteSpace(type))
            throw new RequestValidationException("extensions", $"The {field} requires a scalar type.");
        _ = GlobalStateFactory.ResolveType(type);
    }

    private static RequestValidationException Limit(string collection, int limit) =>
        new("extensions", $"Custom {collection} exceed the limit of {limit}.");

    private static void ValidateTarget(ValidateRequest request)
    {
        if (request.Target is null) return;
        if (!Enum.IsDefined(request.Target.Value))
            throw new RequestValidationException("target", "Target is not supported.");
        if (request.Target == KqlTarget.InteractiveHunting && request.Profile != LintProfile.Hunting)
            throw new RequestValidationException("target", "interactive-hunting requires the hunting profile.");
        if (request.Target is KqlTarget.SentinelScheduled or KqlTarget.SentinelNrt &&
            (request.Profile != LintProfile.Detection || request.Environment != KqlEnvironment.Sentinel))
            throw new RequestValidationException("target", "Sentinel targets require the detection profile and sentinel environment.");
        if (request.Target is KqlTarget.DefenderScheduled or KqlTarget.DefenderNrt &&
            (request.Profile != LintProfile.Detection || request.Environment is not (KqlEnvironment.Xdr or KqlEnvironment.Unified)))
            throw new RequestValidationException("target", "Defender targets require the detection profile and xdr or unified environment.");
    }

    private void ValidateLintOptions(LintOptions? options)
    {
        if (options is null) return;
        if (options.MinimumSeverity is { } severity && !Enum.IsDefined(severity))
            throw new RequestValidationException("lint.minimumSeverity", "Minimum severity is not supported.");
        if (options.RuleSets?.Count > MaxLintSelections ||
            options.EnableRules?.Count > MaxLintSelections ||
            options.DisableRules?.Count > MaxLintSelections)
            throw new RequestValidationException("lint", $"Each lint selection list is limited to {MaxLintSelections} entries.");
        foreach (var ruleSet in options.RuleSets ?? [])
            if (string.IsNullOrWhiteSpace(ruleSet) || !lintRules.ContainsRuleSet(ruleSet))
                throw new RequestValidationException("lint.ruleSets", $"Unknown lint rule set '{ruleSet}'.");
        foreach (var ruleId in (options.EnableRules ?? []).Concat(options.DisableRules ?? []))
            if (string.IsNullOrWhiteSpace(ruleId) || !lintRules.ContainsRule(ruleId))
                throw new RequestValidationException("lint", $"Unknown lint rule ID '{ruleId}'.");
    }

    [GeneratedRegex(@"^[A-Za-z_][A-Za-z0-9_]*$")]
    private static partial Regex Identifier();
}

public sealed class RequestValidationException(string field, string message) : Exception(message)
{
    public string Field { get; } = field;
}
