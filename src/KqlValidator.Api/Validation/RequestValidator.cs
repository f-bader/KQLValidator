using System.Text.RegularExpressions;
using KqlValidator.Contracts;

namespace KqlValidator.Validation;

public sealed partial class RequestValidator(SchemaCatalog catalog, LintRuleCatalog lintRules)
{
    public void Validate(ValidateRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Query))
            throw new RequestValidationException("query", "Query must not be empty.");
        if (request.Query.Length > 65_536)
            throw new RequestValidationException("query", "Query exceeds the 64 KiB character limit.");
        ValidateTarget(request);
        ValidateLintOptions(request.Lint);

        var extensions = request.Extensions;
        if (extensions is null)
            return;
        if (extensions.Tables?.Count > 100) throw Limit("tables", 100);
        if (extensions.Tables?.Sum(x => x.Columns.Count) > 5_000) throw Limit("columns", 5_000);
        if (extensions.Functions?.Count > 100) throw Limit("functions", 100);
        if (extensions.Watchlists?.Count > 100) throw Limit("watchlists", 100);

        var schema = catalog.Get(request.Environment);
        var names = new HashSet<string>(schema.Tables.Keys.Concat(schema.Functions.Keys), StringComparer.OrdinalIgnoreCase);
        foreach (var name in symbolNames())
        {
            if (!Identifier().IsMatch(name))
                throw new RequestValidationException("extensions", $"'{name}' is not a valid KQL identifier.");
            if (!names.Add(name))
                throw new RequestValidationException("extensions", $"Extension name '{name}' collides with another declaration or built-in.");
        }

        var watchlistNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var watchlist in extensions.Watchlists ?? [])
        {
            if (!Identifier().IsMatch(watchlist.Name))
                throw new RequestValidationException("extensions", $"'{watchlist.Name}' is not a valid watchlist alias.");
            if (!watchlistNames.Add(watchlist.Name))
                throw new RequestValidationException("extensions", $"Duplicate watchlist alias '{watchlist.Name}'.");
            foreach (var column in watchlist.Columns) ValidateColumn(column);
        }

        foreach (var column in extensions.Tables?.SelectMany(x => x.Columns)
            .Concat(extensions.Functions?.SelectMany(x => x.Returns.Columns ?? []) ?? []) ?? [])
            ValidateColumn(column);
        foreach (var parameter in extensions.Functions?.SelectMany(x => x.Parameters ?? []) ?? [])
            _ = GlobalStateFactory.ResolveType(parameter.Type);

        foreach (var function in extensions.Functions ?? [])
        {
            if (function.Returns.Kind.Equals("scalar", StringComparison.OrdinalIgnoreCase))
            {
                if (string.IsNullOrWhiteSpace(function.Returns.Type))
                    throw new RequestValidationException("extensions", $"Scalar function '{function.Name}' requires a return type.");
                _ = GlobalStateFactory.ResolveType(function.Returns.Type);
            }
            else if (!function.Returns.Kind.Equals("tabular", StringComparison.OrdinalIgnoreCase))
                throw new RequestValidationException("extensions", $"Function '{function.Name}' return kind must be scalar or tabular.");
        }

        IEnumerable<string> symbolNames()
        {
            foreach (var table in extensions.Tables ?? []) yield return table.Name;
            foreach (var function in extensions.Functions ?? []) yield return function.Name;
        }
    }

    private static void ValidateColumn(ColumnDeclaration column)
    {
        if (!Identifier().IsMatch(column.Name))
            throw new RequestValidationException("extensions", $"'{column.Name}' is not a valid column name.");
        _ = GlobalStateFactory.ResolveType(column.Type);
    }

    private static RequestValidationException Limit(string collection, int limit) =>
        new("extensions", $"Custom {collection} exceed the limit of {limit}.");

    private static void ValidateTarget(ValidateRequest request)
    {
        if (request.Target is null) return;
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
        foreach (var ruleSet in options.RuleSets ?? [])
            if (!lintRules.ContainsRuleSet(ruleSet))
                throw new RequestValidationException("lint.ruleSets", $"Unknown lint rule set '{ruleSet}'.");
        foreach (var ruleId in (options.EnableRules ?? []).Concat(options.DisableRules ?? []))
            if (!lintRules.ContainsRule(ruleId))
                throw new RequestValidationException("lint", $"Unknown lint rule ID '{ruleId}'.");
    }

    [GeneratedRegex(@"^[A-Za-z_][A-Za-z0-9_]*$")]
    private static partial Regex Identifier();
}

public sealed class RequestValidationException(string field, string message) : Exception(message)
{
    public string Field { get; } = field;
}
