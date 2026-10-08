using System.Text.Json;
using System.Text.Json.Nodes;

namespace KqlValidator.SchemaSync;

public static class XdrSchemaNormalizer
{
    private const string SourceUrl = "https://xdrinternals.com/FullSchema-latest.json";

    public static JsonObject Normalize(string json)
    {
        using var document = JsonDocument.Parse(json);
        // The unified upstream feed also contains Sentinel and unclassified tables.
        // Only an explicit Defender classification belongs in the XDR catalog.
        var tables = document.RootElement.EnumerateArray()
            .Where(table => table.TryGetProperty("UsxResourceType", out var resourceType) &&
                resourceType.ValueKind == JsonValueKind.String && resourceType.GetString() == "Defender")
            .Select(table => new JsonObject
            {
                ["name"] = table.GetProperty("Name").GetString(),
                ["columns"] = new JsonArray(table.GetProperty("Schema").EnumerateArray()
                    .Select(column => (JsonNode)new JsonObject
                    {
                        ["name"] = column.GetProperty("Name").GetString(),
                        ["type"] = NormalizeType(column.GetProperty("Type").GetString()!),
                    })
                    .OrderBy(column => column!["name"]!.GetValue<string>(), StringComparer.OrdinalIgnoreCase)
                    .ToArray()),
            })
            .OrderBy(table => table["name"]!.GetValue<string>(), StringComparer.OrdinalIgnoreCase)
            .Cast<JsonNode>()
            .ToArray();
        ValidateTables(tables);
        return new JsonObject { ["source"] = SourceUrl, ["tables"] = new JsonArray(tables) };
    }

    private static string NormalizeType(string type) => type.Trim().ToLowerInvariant() switch
    {
        "int16" or "int32" or "integer" => "int",
        "int64" or "bigint" => "long",
        "boolean" => "bool",
        "object" or "array" => "dynamic",
        "float" or "double" or "decimal" => "real",
        "date" or "datetime" => "datetime",
        "guid" => "guid",
        "timespan" => "timespan",
        "dynamic" => "dynamic",
        _ => "string",
    };

    private static void ValidateTables(IEnumerable<JsonNode> tables)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var table in tables)
        {
            var name = table!["name"]!.GetValue<string>();
            if (!names.Add(name)) throw new InvalidDataException($"Duplicate table '{name}'.");
            var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var column in table["columns"]!.AsArray())
                if (!columns.Add(column!["name"]!.GetValue<string>())) throw new InvalidDataException($"Duplicate column in '{name}'.");
        }
    }
}
