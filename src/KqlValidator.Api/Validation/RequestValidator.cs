using System.Text.RegularExpressions;
using KqlValidator.Contracts;

namespace KqlValidator.Validation;

public sealed partial class RequestValidator(SchemaCatalog catalog)
{
    public void Validate(ValidateRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Query))
            throw new RequestValidationException("query", "Query must not be empty.");
        if (request.Query.Length > 65_536)
            throw new RequestValidationException("query", "Query exceeds the 64 KiB character limit.");
        if (request.Environment == KqlEnvironment.Unified && request.Profile == LintProfile.Detection)
            throw new RequestValidationException("profile", "The detection profile requires either xdr or sentinel, not unified.");

        var extensions = request.Extensions;
        if (extensions is null)
            return;
        if (extensions.Tables?.Count > 100) throw Limit("tables", 100);
        if (extensions.Tables?.Sum(x => x.Columns.Count) > 5_000) throw Limit("columns", 5_000);
        if (extensions.Functions?.Count > 100) throw Limit("functions", 100);
        if (extensions.Watchlists?.Count > 100) throw Limit("watchlists", 100);

        var schema = catalog.Get(request.Environment);
        var names = new HashSet<string>(schema.Tables.Keys.Concat(schema.Functions.Keys), StringComparer.OrdinalIgnoreCase);
        foreach (var name in extensionNames())
        {
            if (!Identifier().IsMatch(name))
                throw new RequestValidationException("extensions", $"'{name}' is not a valid KQL identifier.");
            if (!names.Add(name))
                throw new RequestValidationException("extensions", $"Extension name '{name}' collides with another declaration or built-in.");
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

        IEnumerable<string> extensionNames()
        {
            foreach (var table in extensions.Tables ?? []) yield return table.Name;
            foreach (var function in extensions.Functions ?? []) yield return function.Name;
            foreach (var watchlist in extensions.Watchlists ?? []) yield return $"watchlist:{watchlist.Name}";
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

    [GeneratedRegex(@"^[A-Za-z_][A-Za-z0-9_]*$")]
    private static partial Regex Identifier();
}

public sealed class RequestValidationException(string field, string message) : Exception(message)
{
    public string Field { get; } = field;
}
