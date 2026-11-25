using System.Text.Json;
using System.Text.Json.Nodes;

namespace KqlValidator.SchemaSync;

public static class SentinelSchemaNormalizer
{
    public static JsonObject NormalizeUpstreamFeed(string json, bool includeCustomTables = false)
    {
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("XDRInternals feed must contain a table array.");

        var tables = new List<JsonNode>();
        foreach (var table in document.RootElement.EnumerateArray())
        {
            var isSentinel = ReadString(table, "TableSource").Equals("sentinel", StringComparison.OrdinalIgnoreCase) ||
                ReadString(table, "UsxResourceType").Equals("Sentinel", StringComparison.OrdinalIgnoreCase);
            if (!isSentinel) continue;

            var name = ReadString(table, "Name");
            if (string.IsNullOrWhiteSpace(name)) throw new InvalidDataException("Sentinel feed entry has no table name.");
            if (!includeCustomTables && name.EndsWith("_CL", StringComparison.OrdinalIgnoreCase)) continue;
            if (!table.TryGetProperty("Schema", out var sourceColumns) || sourceColumns.ValueKind != JsonValueKind.Array)
                throw new InvalidDataException($"Sentinel table '{name}' has no schema array.");

            var columns = sourceColumns.EnumerateArray()
                .Select(column => new JsonObject
                {
                    ["name"] = ReadString(column, "Name"),
                    ["type"] = NormalizeType(ReadString(column, "Type")),
                })
                .Where(column => !string.IsNullOrWhiteSpace(column["name"]?.GetValue<string>()))
                .GroupBy(column => column["name"]!.GetValue<string>(), StringComparer.OrdinalIgnoreCase)
                .Select(group =>
                {
                    if (group.Select(column => column["type"]!.GetValue<string>()).Distinct(StringComparer.OrdinalIgnoreCase).Skip(1).Any())
                        throw new InvalidDataException($"Sentinel table '{name}' has conflicting types for duplicate columns.");
                    return group.OrderBy(column => column["name"]!.GetValue<string>(), StringComparer.Ordinal).First();
                })
                .OrderBy(column => column["name"]!.GetValue<string>(), StringComparer.OrdinalIgnoreCase)
                .Cast<JsonNode>()
                .ToArray();
            tables.Add(new JsonObject { ["name"] = name, ["columns"] = new JsonArray(columns) });
        }

        ValidateTables(tables);
        return new JsonObject { ["source"] = "XDRInternals FullSchema Sentinel tables", ["tables"] = new JsonArray(tables.ToArray()) };
    }

    public static JsonObject MergeWithDocumentation(
        JsonObject upstreamSentinel,
        JsonObject documentationTables,
        JsonObject? previousSnapshot = null)
    {
        var documentedNames = ReadNames(documentationTables);
        var tables = new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase);
        foreach (var table in upstreamSentinel["tables"]?.AsArray() ?? [])
        {
            if (table is not JsonObject value) throw new InvalidDataException("Sentinel feed contains a non-object table.");
            var name = ReadNodeString(value, "name");
            if (!documentedNames.Contains(name)) continue;
            tables[name] = (JsonObject)value.DeepClone();
        }

        // Existing declarations remain available. New declarations require both sources.
        foreach (var table in previousSnapshot?["tables"]?.AsArray() ?? [])
        {
            if (table is not JsonObject value) throw new InvalidDataException("Existing Sentinel snapshot contains a non-object table.");
            var name = ReadNodeString(value, "name");
            tables.TryAdd(name, (JsonObject)value.DeepClone());
        }

        var ordered = tables.Values
            .OrderBy(table => ReadNodeString(table, "name"), StringComparer.OrdinalIgnoreCase)
            .Cast<JsonNode>()
            .ToArray();
        ValidateTables(ordered);
        return new JsonObject
        {
            ["source"] = "XDRInternals FullSchema columns filtered by Microsoft Docs table inventory; existing tables retained",
            ["tables"] = new JsonArray(ordered),
        };
    }

    private static HashSet<string> ReadNames(JsonObject snapshot)
    {
        var tables = snapshot["tables"]?.AsArray() ?? throw new InvalidDataException("Documentation snapshot does not contain a tables array.");
        return tables.Select(table => table is JsonObject value ? ReadNodeString(value, "name") :
                throw new InvalidDataException("Documentation snapshot contains a non-object table."))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    private static string ReadString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? "" : "";

    private static string ReadNodeString(JsonObject value, string property) =>
        value[property]?.GetValue<string>() ?? throw new InvalidDataException($"Table is missing '{property}'.");

    private static string NormalizeType(string type) => type.Trim().ToLowerInvariant() switch
    {
        "int" or "int16" or "int32" or "integer" => "int",
        "long" or "int64" or "bigint" => "long",
        "bool" or "boolean" => "bool",
        "object" or "array" or "dynamic" => "dynamic",
        "real" or "float" or "double" or "decimal" => "real",
        "date" or "datetime" => "datetime",
        "guid" => "guid",
        "timespan" => "timespan",
        _ => "string",
    };

    private static void ValidateTables(IEnumerable<JsonNode> tables)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var table in tables)
        {
            var name = table!["name"]!.GetValue<string>();
            if (!names.Add(name)) throw new InvalidDataException($"Duplicate Sentinel table '{name}'.");
            var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var column in table["columns"]!.AsArray())
                if (!columns.Add(column!["name"]!.GetValue<string>())) throw new InvalidDataException($"Duplicate column in '{name}'.");
        }
    }
}
