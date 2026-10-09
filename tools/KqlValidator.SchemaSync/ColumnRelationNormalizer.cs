using System.Text.Json.Nodes;

namespace KqlValidator.SchemaSync;

public static class ColumnRelationNormalizer
{
    public const string SourceUrl = "https://xdrinternals.com/data/column-relations.json";

    public static JsonObject Normalize(string json)
    {
        var root = JsonNode.Parse(json) as JsonObject
            ?? throw new InvalidDataException("Column relations must be an object.");
        if (root["version"]?.GetValue<int>() != 1 || root["relations"] is not JsonArray { Count: > 0 } relations ||
            root["families"] is not JsonArray { Count: > 0 } families)
            throw new InvalidDataException("Unsupported or empty column relations catalog.");

        var familyIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var family in families)
        {
            _ = Required(family, "short");
            if (!familyIds.Add(Required(family, "id")) || string.IsNullOrWhiteSpace(Required(family, "label")))
                throw new InvalidDataException("Invalid or duplicate relation family.");
        }
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var relation in relations)
        {
            if (!ids.Add(Required(relation, "id")) || !familyIds.Contains(Required(relation, "family")))
                throw new InvalidDataException("Invalid or duplicate column relation.");
            foreach (var field in new[] { "title", "description", "guidance" })
                _ = Required(relation, field);
            if (relation?["tags"] is not JsonArray tags || tags.Any(tag => tag is not JsonValue value || !value.TryGetValue<string>(out var text) || string.IsNullOrWhiteSpace(text)))
                throw new InvalidDataException("Column relation requires string tags.");
            ValidateOptionalStrings(relation, ["kql"]);
            if (relation?["otherNotes"] is { } notesNode)
            {
                if (notesNode is not JsonArray notes) throw new InvalidDataException("Relation notes must be an array.");
                foreach (var note in notes)
                {
                    _ = Required(note, "title");
                    _ = Required(note, "text");
                    ValidateOptionalStrings(note, ["sourceLabel", "sourceUrl", "query", "queryLanguage"]);
                }
            }
            foreach (var side in new[] { "from", "to" })
            {
                _ = Required(relation?[side], "table");
                _ = Required(relation?[side], "column");
                foreach (var optional in new[] { "path", "timeColumn" })
                    if (relation?[side]?[optional] is not null) _ = Required(relation[side], optional);
            }
        }
        // Preserve upstream guidance and examples; machine-enforced constraints are reviewed separately.
        root.Remove("$schema");
        root["source"] = SourceUrl;
        return root;
    }

    private static void ValidateOptionalStrings(JsonNode? node, string[] fields)
    {
        foreach (var field in fields)
            if (node?[field] is { } value && (value is not JsonValue scalar || !scalar.TryGetValue<string>(out _)))
                throw new InvalidDataException($"Relation '{field}' must be a string.");
    }

    private static string Required(JsonNode? node, string field) =>
        node?[field] is JsonValue value && value.TryGetValue<string>(out var text) && !string.IsNullOrWhiteSpace(text)
            ? text : throw new InvalidDataException($"Column relation requires '{field}'.");
}
