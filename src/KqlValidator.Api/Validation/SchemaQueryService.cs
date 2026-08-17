using System.Text;
using KqlValidator.Contracts;

namespace KqlValidator.Validation;

public sealed class SchemaQueryService(SchemaCatalog catalog)
{
    public IReadOnlyList<EnvironmentSummary> ListEnvironments() => catalog.List();

    public SchemaTable? GetTable(KqlEnvironment environment, string table) =>
        catalog.Get(environment).Tables.GetValueOrDefault(table);

    public SchemaSearchResponse Search(KqlEnvironment environment, string? query, string? kind, int limit, string? cursor)
    {
        limit = Math.Clamp(limit, 1, 100);
        var offset = DecodeCursor(cursor);
        var schema = catalog.Get(environment);
        var results = new List<SchemaSearchResult>();

        if (kind is null or "table")
            results.AddRange(schema.Tables.Values.Select(x => new SchemaSearchResult("table", x.Name, null, null, schema.Name)));
        if (kind is null or "column")
            results.AddRange(schema.Tables.Values.SelectMany(t => t.Columns.Select(c => new SchemaSearchResult("column", c.Name, t.Name, c.Type, schema.Name))));
        if (kind is null or "function")
            results.AddRange(schema.Functions.Values.Select(x => new SchemaSearchResult("function", x.Name, null,
                x.ScalarReturnType ?? "tabular", schema.Name)));

        var filtered = results
            .Where(x => string.IsNullOrWhiteSpace(query)
                || x.Name.Contains(query, StringComparison.OrdinalIgnoreCase)
                || (x.Parent?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false))
            .OrderBy(x => x.Kind, StringComparer.Ordinal)
            .ThenBy(x => x.Parent, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (offset > filtered.Length)
            offset = filtered.Length;
        var page = filtered.Skip(offset).Take(limit).ToArray();
        var next = offset + page.Length < filtered.Length ? EncodeCursor(offset + page.Length) : null;
        return new SchemaSearchResponse(page, next);
    }

    private static int DecodeCursor(string? cursor)
    {
        if (string.IsNullOrWhiteSpace(cursor)) return 0;
        try
        {
            var value = Encoding.UTF8.GetString(Convert.FromBase64String(cursor));
            return int.TryParse(value, out var offset) && offset >= 0 ? offset : 0;
        }
        catch (FormatException) { return 0; }
    }

    private static string EncodeCursor(int value) => Convert.ToBase64String(Encoding.UTF8.GetBytes(value.ToString()));
}
