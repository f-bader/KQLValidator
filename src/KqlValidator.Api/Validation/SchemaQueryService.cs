using System.Collections.Frozen;
using System.Text;
using KqlValidator.Contracts;

namespace KqlValidator.Validation;

public sealed class SchemaQueryService
{
    private readonly SchemaCatalog catalog;
    private readonly FrozenDictionary<KqlEnvironment, SearchIndex> indexes;

    public SchemaQueryService(SchemaCatalog catalog)
    {
        this.catalog = catalog;
        indexes = Enum.GetValues<KqlEnvironment>()
            .ToFrozenDictionary(environment => environment, environment => BuildIndex(catalog.Get(environment)));
    }

    public IReadOnlyList<EnvironmentSummary> ListEnvironments() => catalog.List();

    public SchemaTable? GetTable(KqlEnvironment environment, string table) =>
        catalog.Get(environment).Tables.GetValueOrDefault(table);

    public SchemaFunction? GetFunction(KqlEnvironment environment, string function) =>
        catalog.Get(environment).Functions.GetValueOrDefault(function);

    public SchemaSearchResponse Search(KqlEnvironment environment, string? query, string? kind, int limit, string? cursor)
    {
        limit = Math.Clamp(limit, 1, 100);
        var offset = DecodeCursor(cursor);
        var index = indexes[environment];

        // Kinds concatenate in ordinal kind order (column, function, table) so the
        // stream is already fully sorted and pagination never materializes the catalog.
        IEnumerable<SchemaSearchResult> results = [];
        if (kind is null or "column")
            results = results.Concat(index.Columns);
        if (kind is null or "function")
            results = results.Concat(index.Functions);
        if (kind is null or "table")
            results = results.Concat(index.Tables);

        var filtered = results.Where(x => string.IsNullOrWhiteSpace(query)
            || x.Name.Contains(query, StringComparison.OrdinalIgnoreCase)
            || (x.Parent?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false));

        var page = filtered.Skip(offset).Take(limit + 1).ToArray();
        var next = page.Length > limit ? EncodeCursor(offset + limit) : null;
        return new SchemaSearchResponse(page.Length > limit ? page[..limit] : page, next);
    }

    private static SearchIndex BuildIndex(EnvironmentSchema schema)
    {
        return new SearchIndex(
            Sorted(schema.Tables.Values.SelectMany(t => t.Columns.Select(c =>
                new SchemaSearchResult("column", c.Name, t.Name, c.Type, schema.Name)))),
            Sorted(schema.Functions.Values.Select(x =>
                new SchemaSearchResult("function", x.Name, null, x.ScalarReturnType ?? "tabular", schema.Name))),
            Sorted(schema.Tables.Values.Select(x =>
                new SchemaSearchResult("table", x.Name, null, null, schema.Name))));

        static SchemaSearchResult[] Sorted(IEnumerable<SchemaSearchResult> results) => results
            .OrderBy(x => x.Parent, StringComparer.OrdinalIgnoreCase)
            .ThenBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private sealed record SearchIndex(
        SchemaSearchResult[] Columns,
        SchemaSearchResult[] Functions,
        SchemaSearchResult[] Tables);

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
