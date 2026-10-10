using System.Text.Json;
using System.Text.Json.Serialization;

#if SCHEMA_SYNC
namespace KqlValidator.SchemaSync;
#else
namespace KqlValidator.Validation;
#endif

public sealed record StructuredField(string Path, string Type);
public sealed record StructuredEntry(string Id, string Table, string Column, Dictionary<string, string> Discriminators,
    string ShapeId, string Format, string Encoding, [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] JsonElement? Example, IReadOnlyList<StructuredField> Fields,
    string Origin, int GeneratorVersion, int PolicyVersion, string Notes, string SourceUrl);
public sealed record StructuredCombination(string Table, string Column, Dictionary<string, string> Discriminators,
    IReadOnlyList<string> ObservedShapes, IReadOnlyList<string> IllustrativeShapes);
public sealed record StructuredKnownAction(string Table, string Column, Dictionary<string, string> Discriminators,
    string SourcePath, string SourceUrl);
public sealed record StructuredSnapshot(int Version, IReadOnlyList<StructuredEntry> Entries,
    IReadOnlyList<StructuredCombination> Combinations, IReadOnlyList<StructuredKnownAction> KnownActions);

public static class StructuredSnapshotValidator
{
    private static string Key(string table, string column, IReadOnlyDictionary<string, string> discriminators) =>
        JsonSerializer.Serialize(new { table, column, discriminators = discriminators.OrderBy(d => d.Key, StringComparer.Ordinal).ToArray() });
    public static void Validate(StructuredSnapshot value)
    {
        if (value.Version != 1 || value.Entries is null || value.Combinations is null || value.KnownActions is null)
            throw new InvalidDataException("Unsupported structured columns snapshot.");
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var e in value.Entries)
        {
            Target(e.Table, e.Column, e.Discriminators);
            if (!ids.Add(e.Id) || string.IsNullOrWhiteSpace(e.Id) || string.IsNullOrWhiteSpace(e.ShapeId) ||
                e.Origin is not ("observed" or "illustrative") || e.Format is not ("json" or "xml") ||
                e.Encoding is not ("json-string" or "native-json" or "xml-string") ||
                (e.Format == "xml") != (e.Encoding == "xml-string") || e.Fields is null ||
                e.Fields.Any(f => f is null || string.IsNullOrWhiteSpace(f.Path) || string.IsNullOrWhiteSpace(f.Type)) ||
                string.IsNullOrWhiteSpace(e.Notes) || string.IsNullOrWhiteSpace(e.SourceUrl) || e.GeneratorVersion < 1 || e.PolicyVersion < 1)
                throw new InvalidDataException("Invalid structured entry.");
        }
        var combinations = new HashSet<string>(StringComparer.Ordinal);
        foreach (var c in value.Combinations)
        {
            Target(c.Table, c.Column, c.Discriminators);
            if (!combinations.Add(Key(c.Table, c.Column, c.Discriminators)) || c.ObservedShapes is null || c.IllustrativeShapes is null)
                throw new InvalidDataException("Invalid structured combination.");
            foreach (var (shapes, origin) in new[] { (c.ObservedShapes, "observed"), (c.IllustrativeShapes, "illustrative") })
                foreach (var shape in shapes)
                    if (!value.Entries.Any(e => e.ShapeId == shape && e.Origin == origin && Key(e.Table, e.Column, e.Discriminators) == Key(c.Table, c.Column, c.Discriminators)))
                        throw new InvalidDataException("Unknown structured shape reference.");
        }
        foreach (var e in value.Entries)
            if (!value.Combinations.Any(c => Key(c.Table, c.Column, c.Discriminators) == Key(e.Table, e.Column, e.Discriminators) &&
                (e.Origin == "observed" ? c.ObservedShapes : c.IllustrativeShapes).Contains(e.ShapeId)))
                throw new InvalidDataException("Structured entry is not referenced by its combination.");
        foreach (var a in value.KnownActions)
        {
            Target(a.Table, a.Column, a.Discriminators);
            if (string.IsNullOrWhiteSpace(a.SourcePath) || string.IsNullOrWhiteSpace(a.SourceUrl)) throw new InvalidDataException("Invalid known action.");
        }
        static void Target(string table, string column, Dictionary<string, string> discriminators)
        {
            if (string.IsNullOrWhiteSpace(table) || string.IsNullOrWhiteSpace(column) || discriminators is null ||
                discriminators.Any(d => string.IsNullOrWhiteSpace(d.Key) || d.Value is null))
                throw new InvalidDataException("Invalid structured target.");
        }
    }
}
