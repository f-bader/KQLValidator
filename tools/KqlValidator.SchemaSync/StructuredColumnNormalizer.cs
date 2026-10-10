using System.Text.Json;
using System.Text.Json.Nodes;

namespace KqlValidator.SchemaSync;

public static class StructuredColumnNormalizer
{
    public const string SourceUrl = "https://xdrinternals.com/data/structured-columns/index.json";
    public static JsonObject Normalize(string json)
    {
        try
        {
            var snapshot = JsonSerializer.Deserialize<StructuredSnapshot>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web))
                ?? throw new InvalidDataException("Empty structured columns snapshot.");
            StructuredSnapshotValidator.Validate(snapshot);
            if (snapshot.Entries.Count == 0) throw new InvalidDataException("Empty structured columns entries.");
            // Canonicalize object keys and arrays without trimming values or losing path/type pairs.
            var root = JsonNode.Parse(json)!.AsObject();
            root.Remove("$schema");
            root["source"] = SourceUrl;
            foreach (var property in new[] { "entries", "combinations", "knownActions" })
                root[property] = new JsonArray(root[property]!.AsArray()
                    .Select(n => Canonical(n!)).OrderBy(n => n.ToJsonString(), StringComparer.Ordinal).ToArray());
            return (JsonObject)Canonical(root);
        }
        catch (Exception e) when (e is JsonException or ArgumentException or NullReferenceException)
        {
            throw new InvalidDataException("Malformed structured columns snapshot.", e);
        }
    }
    private static JsonNode Canonical(JsonNode node) => node switch
    {
        JsonObject obj => new JsonObject(obj.OrderBy(p => p.Key, StringComparer.Ordinal)
            .Select(p => new KeyValuePair<string, JsonNode?>(p.Key, p.Value is null ? null : Canonical(p.Value)))),
        JsonArray array => new JsonArray(array.Select(n => n is null ? null : Canonical(n)).ToArray()),
        _ => node.DeepClone()
    };
}
