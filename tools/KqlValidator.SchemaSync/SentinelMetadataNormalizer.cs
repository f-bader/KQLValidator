using System.Text.Json;
using System.Text.Json.Nodes;

namespace KqlValidator.SchemaSync;

public static class SentinelMetadataNormalizer
{
    private const string Source = "Azure Log Analytics Metadata API";

    public static JsonObject Normalize(string json, bool includeCustomTables = false)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        RejectDeniedTables(root);
        if (!root.TryGetProperty("tables", out var sourceTables) || sourceTables.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Log Analytics metadata response does not contain a tables array.");

        var tables = sourceTables.EnumerateArray()
            .Select(NormalizeTable)
            .Where(table => table is not null)
            .Cast<JsonNode>()
            .Where(table => includeCustomTables || !IsCustomTable(table["name"]!.GetValue<string>()))
            .OrderBy(table => table["name"]!.GetValue<string>(), StringComparer.OrdinalIgnoreCase)
            .ToArray();
        ValidateTables(tables);
        if (tables.Length == 0) throw new InvalidDataException("Log Analytics metadata response contains no usable tables.");
        return new JsonObject { ["source"] = Source, ["tables"] = new JsonArray(tables) };
    }

    private static JsonObject? NormalizeTable(JsonElement table)
    {
        if (!table.TryGetProperty("name", out var nameProperty) || string.IsNullOrWhiteSpace(nameProperty.GetString())) return null;
        var columns = table.TryGetProperty("columns", out var sourceColumns) && sourceColumns.ValueKind == JsonValueKind.Array
            ? sourceColumns.EnumerateArray()
                .Where(column => column.TryGetProperty("name", out var name) && !string.IsNullOrWhiteSpace(name.GetString()))
                .Select(column => new JsonObject
                {
                    ["name"] = column.GetProperty("name").GetString(),
                    ["type"] = NormalizeType(column.TryGetProperty("type", out var type) ? type.GetString() : null),
                })
                .GroupBy(column => column["name"]!.GetValue<string>(), StringComparer.OrdinalIgnoreCase)
                .Select(group =>
                {
                    if (group.Select(column => column["type"]!.GetValue<string>()).Distinct(StringComparer.OrdinalIgnoreCase).Skip(1).Any())
                        throw new InvalidDataException($"Conflicting types for duplicate column '{group.Key}' in '{nameProperty.GetString()}'.");
                    return group.First();
                })
                .OrderBy(column => column["name"]!.GetValue<string>(), StringComparer.OrdinalIgnoreCase)
                .Cast<JsonNode>()
                .ToArray()
            : [];
        return new JsonObject { ["name"] = nameProperty.GetString(), ["columns"] = new JsonArray(columns) };
    }

    private static bool IsCustomTable(string tableName) => tableName.EndsWith("_CL", StringComparison.OrdinalIgnoreCase);

    private static void RejectDeniedTables(JsonElement root)
    {
        if (!root.TryGetProperty("permissions", out var permissions) || permissions.ValueKind != JsonValueKind.Object) return;
        foreach (var section in new[] { "resources", "workspaces" })
        {
            if (!permissions.TryGetProperty(section, out var entries) || entries.ValueKind != JsonValueKind.Array) continue;
            if (entries.EnumerateArray().Any(entry => entry.TryGetProperty("denyTables", out var denied) && denied.ValueKind == JsonValueKind.Array && denied.GetArrayLength() > 0))
                throw new InvalidDataException("Log Analytics metadata response denied access to one or more tables.");
        }
    }

    private static string NormalizeType(string? type) => type?.Trim().ToLowerInvariant() switch
    {
        "int" or "int16" or "int32" or "integer" => "int",
        "long" or "int64" or "bigint" => "long",
        "bool" or "boolean" => "bool",
        "object" or "array" => "dynamic",
        "real" or "float" or "double" or "decimal" => "real",
        "date" or "datetime" => "datetime",
        "guid" => "guid",
        "timespan" => "timespan",
        "dynamic" => "dynamic",
        "string" => "string",
        _ => "string",
    };

    private static void ValidateTables(IEnumerable<JsonNode> tables)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var table in tables)
        {
            var name = table["name"]!.GetValue<string>();
            if (!names.Add(name)) throw new InvalidDataException($"Duplicate table '{name}'.");
            var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var column in table["columns"]!.AsArray())
                if (!columns.Add(column!["name"]!.GetValue<string>())) throw new InvalidDataException($"Duplicate column in '{name}'.");
        }
    }
}
