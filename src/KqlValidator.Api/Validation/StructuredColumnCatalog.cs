using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace KqlValidator.Validation;

public sealed record StructuredCoverage(bool Exhaustive = false, bool AdditionalFieldsPossible = true,
    bool AdditionalVariantsPossible = true, bool FieldPresenceGuaranteed = false);
public sealed record StructuredVariant(Dictionary<string, string> Discriminators, string Status,
    IReadOnlyList<StructuredEntry> Shapes, IReadOnlyList<StructuredKnownAction> KnownActions);
public sealed record StructuredColumnSummary(string Table, string Column, string KqlType, int VariantCount,
    int ObservedShapeCount, int IllustrativeShapeCount, IReadOnlyList<string> DiscriminatorKeys);
public sealed record StructuredListResponse(int Version, string Source, string Sha256, StructuredCoverage Coverage,
    string Caveat, int TotalCount, IReadOnlyList<StructuredColumnSummary> Items, string? NextCursor);
public sealed record StructuredDetailResponse(int Version, string Source, string Sha256, StructuredCoverage Coverage,
    string Caveat, string Status, string? KqlType, string Guidance, int TotalCount,
    IReadOnlyList<StructuredVariant> Items, string? NextCursor);

public sealed class StructuredColumnCatalog
{
    public const string SourceUrl = "https://xdrinternals.com/data/structured-columns/index.json";
    public const string Caveat = "Captured shapes and illustrative examples are not an exhaustive vendor contract. Fields may be absent or have other types. Missing fields or variants are not evidence that they are invalid.";
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };
    private readonly StructuredSnapshot snapshot;
    private readonly string hash;
    private readonly StructuredVariant[] variants;

    public StructuredColumnCatalog(string path, bool required = true)
    {
        if (!File.Exists(path))
        {
            if (required) throw new InvalidDataException("Bundled structured columns snapshot is missing.");
            snapshot = new(1, [], [], []);
            hash = "";
        }
        else
        {
            try
            {
                var json = File.ReadAllText(path);
                snapshot = JsonSerializer.Deserialize<StructuredSnapshot>(json, Options)
                    ?? throw new InvalidDataException("Empty structured columns snapshot.");
                StructuredSnapshotValidator.Validate(snapshot);
                using var document = JsonDocument.Parse(json);
                hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(document.RootElement)))).ToLowerInvariant();
            }
            catch (Exception e) when (e is JsonException or ArgumentException or NullReferenceException)
            {
                throw new InvalidDataException("Malformed structured columns snapshot.", e);
            }
        }
        variants = snapshot.Combinations.Select(c => (c.Table, c.Column, c.Discriminators))
            .Concat(snapshot.KnownActions.Select(c => (c.Table, c.Column, c.Discriminators)))
            .Concat(snapshot.Entries.Select(c => (c.Table, c.Column, c.Discriminators)))
            .DistinctBy(c => Key(c.Table, c.Column, c.Discriminators))
            .OrderBy(c => Key(c.Table, c.Column, c.Discriminators), StringComparer.Ordinal)
            .Select(c =>
            {
                var entries = snapshot.Entries.Where(e => Key(e.Table, e.Column, e.Discriminators) == Key(c.Table, c.Column, c.Discriminators)).OrderBy(e => e.Id, StringComparer.Ordinal).ToArray();
                var actions = snapshot.KnownActions.Where(e => Key(e.Table, e.Column, e.Discriminators) == Key(c.Table, c.Column, c.Discriminators)).ToArray();
                return new StructuredVariant(c.Discriminators, Status(entries, true), entries, actions);
            }).ToArray();
    }

    // Keep table/column identity alongside each variant, including combinations with no captured shape.
    private IEnumerable<(string Table, string Column, StructuredVariant Variant)> All() =>
        snapshot.Combinations.Select(c => (c.Table, c.Column, c.Discriminators))
            .Concat(snapshot.KnownActions.Select(c => (c.Table, c.Column, c.Discriminators)))
            .Concat(snapshot.Entries.Select(c => (c.Table, c.Column, c.Discriminators)))
            .DistinctBy(c => Key(c.Table, c.Column, c.Discriminators))
            .OrderBy(c => Key(c.Table, c.Column, c.Discriminators), StringComparer.Ordinal)
            .Zip(variants, (c, v) => (c.Table, c.Column, v));

    public StructuredListResponse List(EnvironmentSchema schema, string? table, string? column, int limit, string? cursor)
    {
        var items = All().Where(x => Available(schema, x.Table, x.Column) is not null)
            .Where(x => (table is null || x.Table.Equals(table, StringComparison.OrdinalIgnoreCase)) &&
                (column is null || x.Column.Equals(column, StringComparison.OrdinalIgnoreCase)))
            .GroupBy(x => (x.Table, x.Column)).Select(g => new StructuredColumnSummary(g.Key.Table, g.Key.Column,
                Available(schema, g.Key.Table, g.Key.Column)!, g.Count(),
                g.Sum(x => x.Variant.Shapes.Count(e => e.Origin == "observed")),
                g.Sum(x => x.Variant.Shapes.Count(e => e.Origin == "illustrative")),
                g.SelectMany(x => x.Variant.Discriminators.Keys).Distinct().Order(StringComparer.Ordinal).ToArray())).ToArray();
        var page = Page(items, limit, cursor);
        return new(snapshot.Version, SourceUrl, hash, new(), Caveat, items.Length, page.Items, page.Next);
    }

    public static Dictionary<string, string>? ParseDiscriminators(string json)
    {
        try { return JsonSerializer.Deserialize<Dictionary<string, string>>(json); }
        catch (JsonException) { throw new ArgumentException("discriminators must be a JSON object of string values."); }
    }

    public StructuredDetailResponse Get(EnvironmentSchema schema, string table, string column,
        IReadOnlyDictionary<string, string>? discriminators, bool includeExamples, int limit, string? cursor)
    {
        if (discriminators is not null && discriminators.Any(d => string.IsNullOrWhiteSpace(d.Key) || d.Value is null))
            throw new ArgumentException("Discriminators must have nonempty keys and string values.");
        var type = Available(schema, table, column);
        var items = type is null ? [] : All().Where(x => x.Table.Equals(table, StringComparison.OrdinalIgnoreCase) && x.Column.Equals(column, StringComparison.OrdinalIgnoreCase))
            .Select(x => x.Variant).Where(v => discriminators is null || discriminators.All(d => v.Discriminators.TryGetValue(d.Key, out var value) && value == d.Value)).ToArray();
        var status = type is null ? "target-unavailable" : Status(items.SelectMany(v => v.Shapes), items.Length > 0);
        var page = Page(items, limit, cursor);
        var output = page.Items.Select(v => includeExamples ? v : v with
        {
            Shapes = v.Shapes.Select(e => e with { Example = null }).ToArray()
        }).ToArray();
        return new(snapshot.Version, SourceUrl, hash, new(), Caveat, status, type,
            "Paths are descriptive notation, not executable KQL. For json-string, use parse_json(value) on a string column, or parse_json(tostring(value)) when a dynamic value contains a JSON string; parse_json(dynamic) otherwise leaves it unchanged. Native-json may be accessed directly when the effective KQL type is dynamic. For xml-string, use format-aware XML parsing, not parse_json. Arrays need expansion; named-property selectors identify key/value entries; ::<json> marks another JSON decoding boundary: use parse_json(tostring(value)) to decode that extracted string, including strings held in dynamic values. Cast extracted values explicitly and handle missing values. Encoding describes the captured representation, not all live events.",
            items.Length, output, page.Next);
    }

    private static string Status(IEnumerable<StructuredEntry> entries, bool known) => entries.Any(e => e.Origin == "observed")
        ? "observed-shapes-available" : entries.Any() ? "illustrative-only" : known ? "known-combination-without-shape" : "no-catalog-match";
    private static string? Available(EnvironmentSchema schema, string table, string column) => schema.Tables.GetValueOrDefault(table)?.Columns.FirstOrDefault(c => c.Name.Equals(column, StringComparison.OrdinalIgnoreCase))?.Type;
    private static string Key(string table, string column, IReadOnlyDictionary<string, string> discriminators) =>
        JsonSerializer.Serialize(new { table, column, discriminators = discriminators.OrderBy(d => d.Key, StringComparer.Ordinal).ToArray() });
    private static (T[] Items, string? Next) Page<T>(T[] items, int limit, string? cursor)
    {
        limit = Math.Clamp(limit, 1, 100);
        var offset = 0;
        if (cursor is not null)
        {
            try { _ = int.TryParse(Encoding.UTF8.GetString(Convert.FromBase64String(cursor)), out offset); }
            catch (FormatException) { }
            offset = Math.Max(0, offset);
        }
        var page = items.Skip(offset).Take(limit).ToArray();
        return (page, offset < items.Length - page.Length ? Convert.ToBase64String(Encoding.UTF8.GetBytes(((long)offset + page.Length).ToString())) : null);
    }

}
