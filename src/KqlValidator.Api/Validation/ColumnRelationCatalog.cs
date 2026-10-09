using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using KqlValidator.Contracts;

namespace KqlValidator.Validation;

public sealed record ColumnRelationEndpoint(string Table, string Column, string? Path = null, string? TimeColumn = null);
public sealed record ColumnRelationFamily(string Id, string Label, string Short);
public sealed record ColumnRelationNote(string Title, string Text, string? SourceLabel = null, string? SourceUrl = null,
    string? Query = null, string? QueryLanguage = null);
public sealed record ColumnRelation(string Id, string Title, string Description, ColumnRelationEndpoint From,
    ColumnRelationEndpoint To, IReadOnlyList<string> Tags, string Guidance, string Family,
    IReadOnlyList<ColumnRelationNote>? OtherNotes = null, string? Kql = null);
public sealed record ColumnRelationResponse(int Version, string Source, string Sha256,
    IReadOnlyList<ColumnRelationFamily> Families, IReadOnlyList<ColumnRelation> Items);

public sealed class ColumnRelationCatalog
{
    public const string SourceUrl = "https://xdrinternals.com/data/column-relations.json";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly Snapshot snapshot;
    private readonly string hash;
    private readonly IReadOnlyDictionary<string, string[]> familiesByEndpoint;

    public ColumnRelationCatalog(string path, bool required = true)
    {
        if (!File.Exists(path))
        {
            if (required) throw new InvalidDataException("Bundled column relations snapshot is missing.");
            snapshot = new(1, [], []);
            hash = "";
        }
        else
        {
            try
            {
                var json = File.ReadAllText(path);
                snapshot = JsonSerializer.Deserialize<Snapshot>(json, JsonOptions)
                    ?? throw new InvalidDataException("Empty column relations snapshot.");
                Validate(snapshot);
                using var document = JsonDocument.Parse(json);
                hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                    JsonSerializer.Serialize(document.RootElement)))).ToLowerInvariant();
            }
            catch (Exception exception) when (exception is JsonException or ArgumentException or NullReferenceException)
            {
                throw new InvalidDataException("Bundled column relations snapshot is malformed.", exception);
            }
        }
        familiesByEndpoint = snapshot.Relations.SelectMany(r => new[] { (r.From, r.Family), (r.To, r.Family) })
            .GroupBy(x => Key(x.Item1)).ToDictionary(g => g.Key, g => g.Select(x => x.Family).Distinct().ToArray());
    }

    public IReadOnlyList<ColumnRelation> Relations => snapshot.Relations;
    public IReadOnlyList<string> Families(ColumnRelationEndpoint endpoint) => familiesByEndpoint.GetValueOrDefault(Key(endpoint)) ?? [];
    public string FamilyLabel(string family) => snapshot.Families.FirstOrDefault(f => f.Id == family)?.Label ?? family;

    public ColumnRelationResponse Get(EnvironmentSchema schema, string table, string? column = null)
    {
        var items = snapshot.Relations.Where(r => Available(schema, r.From) && Available(schema, r.To))
            .Where(r => Matches(r.From, table, column) || Matches(r.To, table, column))
            .OrderBy(r => r.Id, StringComparer.Ordinal).ToArray();
        var used = items.Select(r => r.Family).ToHashSet(StringComparer.Ordinal);
        return new(snapshot.Version, SourceUrl, hash, snapshot.Families.Where(f => used.Contains(f.Id)).ToArray(), items);
    }

    public static bool Same(ColumnRelationEndpoint left, ColumnRelationEndpoint right) => Key(left) == Key(right);
    private static string Key(ColumnRelationEndpoint endpoint) =>
        $"{endpoint.Table}\0{endpoint.Column}\0{endpoint.Path ?? ""}";

    private static bool Matches(ColumnRelationEndpoint endpoint, string table, string? column) =>
        endpoint.Table.Equals(table, StringComparison.OrdinalIgnoreCase) &&
        (string.IsNullOrWhiteSpace(column) || endpoint.Column.Equals(column, StringComparison.OrdinalIgnoreCase));

    private static bool Available(EnvironmentSchema schema, ColumnRelationEndpoint endpoint) =>
        schema.Tables.TryGetValue(endpoint.Table, out var table) &&
        table.Columns.Any(c => c.Name.Equals(endpoint.Column, StringComparison.OrdinalIgnoreCase)) &&
        (endpoint.TimeColumn is null || table.Columns.Any(c => c.Name.Equals(endpoint.TimeColumn, StringComparison.OrdinalIgnoreCase)));

    private static void Validate(Snapshot value)
    {
        if (value.Version != 1 || value.Relations is null || value.Families is null || value.Relations.Count == 0 || value.Families.Count == 0)
            throw new InvalidDataException("Unsupported or empty column relations snapshot.");
        var families = value.Families.Select(f => f.Id).ToHashSet(StringComparer.Ordinal);
        if (families.Count != value.Families.Count || value.Families.Any(f => string.IsNullOrWhiteSpace(f.Id) || string.IsNullOrWhiteSpace(f.Label)) ||
            value.Relations.Select(r => r.Id).Distinct(StringComparer.Ordinal).Count() != value.Relations.Count)
            throw new InvalidDataException("Duplicate or invalid column relation identifiers.");
        foreach (var relation in value.Relations)
        {
            if (string.IsNullOrWhiteSpace(relation.Id) || string.IsNullOrWhiteSpace(relation.Title) || string.IsNullOrWhiteSpace(relation.Description) ||
                string.IsNullOrWhiteSpace(relation.Guidance) || !families.Contains(relation.Family) || relation.Tags is null || relation.Tags.Any(string.IsNullOrWhiteSpace))
                throw new InvalidDataException("Invalid column relation metadata.");
            foreach (var endpoint in new[] { relation.From, relation.To })
                if (endpoint is null || string.IsNullOrWhiteSpace(endpoint.Table) || string.IsNullOrWhiteSpace(endpoint.Column) ||
                    endpoint.Path is not null && string.IsNullOrWhiteSpace(endpoint.Path) ||
                    endpoint.TimeColumn is not null && string.IsNullOrWhiteSpace(endpoint.TimeColumn))
                    throw new InvalidDataException("Invalid column relation endpoint.");
        }
    }

    private sealed record Snapshot(int Version, IReadOnlyList<ColumnRelation> Relations, IReadOnlyList<ColumnRelationFamily> Families);
}
