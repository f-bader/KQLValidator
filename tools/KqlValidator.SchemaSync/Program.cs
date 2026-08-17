using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

const string xdrSchemaUrl = "https://xdrinternals.com/FullSchema-latest.json";
const string actionTypesUrl = "https://xdrinternals.com/ActionTypeSchema-latest.json";

var arguments = ParseArguments(args);
var outputDirectory = arguments.GetValueOrDefault("out")
    ?? throw new ArgumentException("--out is required");
Directory.CreateDirectory(outputDirectory);

using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
http.DefaultRequestHeaders.UserAgent.ParseAdd("kql-validator-schema-sync/1.0");

var rawXdr = await http.GetStringAsync(xdrSchemaUrl);
var rawActions = await http.GetStringAsync(actionTypesUrl);
var xdr = NormalizeXdr(rawXdr);
var actions = NormalizeActions(rawActions);

EnforceDropGuard(Path.Combine(outputDirectory, "xdr.json"), xdr, "tables", 0.8);
await WriteIfChanged(Path.Combine(outputDirectory, "xdr.json"), xdr);
await WriteIfChanged(Path.Combine(outputDirectory, "action-types.json"), actions);

JsonObject? sentinel = null;
if (arguments.TryGetValue("sentinel-dir", out var sentinelDirectory))
{
    sentinel = NormalizeSentinel(sentinelDirectory);
    EnforceDropGuard(Path.Combine(outputDirectory, "sentinel.json"), sentinel, "tables", 0.8);
    await WriteIfChanged(Path.Combine(outputDirectory, "sentinel.json"), sentinel);
}

var sources = new JsonArray(Source(xdrSchemaUrl, xdr), Source(actionTypesUrl, actions));
if (sentinel is not null)
    sources.Add(Source("https://github.com/MicrosoftDocs/azure-reference-other", sentinel));
var manifest = new JsonObject { ["sources"] = sources };
await WriteIfChanged(Path.Combine(outputDirectory, "manifest.json"), manifest);

static Dictionary<string, string> ParseArguments(string[] values)
{
    var parsed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    for (var i = 0; i < values.Length; i += 2)
    {
        if (i + 1 >= values.Length || !values[i].StartsWith("--", StringComparison.Ordinal))
            throw new ArgumentException("Arguments must be --name value pairs.");
        parsed[values[i][2..]] = values[i + 1];
    }
    return parsed;
}

static JsonObject NormalizeXdr(string json)
{
    using var document = JsonDocument.Parse(json);
    var tables = document.RootElement.EnumerateArray()
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
    return new JsonObject { ["source"] = xdrSchemaUrl, ["tables"] = new JsonArray(tables) };
}

static JsonObject NormalizeActions(string json)
{
    using var document = JsonDocument.Parse(json);
    var tables = document.RootElement.EnumerateArray()
        .Select(table =>
        {
            var actions = table.GetProperty("ActionTypes");
            var values = actions.ValueKind == JsonValueKind.Array
                ? actions.EnumerateArray().Select(x => x.GetString()!).ToArray()
                : [actions.GetString()!];
            return new JsonObject
            {
                ["tableName"] = table.GetProperty("TableName").GetString(),
                ["actionTypes"] = new JsonArray(values.Distinct(StringComparer.OrdinalIgnoreCase)
                    .Order(StringComparer.OrdinalIgnoreCase).Select(value => (JsonNode?)JsonValue.Create(value)).ToArray()),
            };
        })
        .OrderBy(table => table["tableName"]!.GetValue<string>(), StringComparer.OrdinalIgnoreCase)
        .Cast<JsonNode>()
        .ToArray();
    return new JsonObject { ["source"] = actionTypesUrl, ["tables"] = new JsonArray(tables) };
}

static JsonObject NormalizeSentinel(string directory)
{
    if (!Directory.Exists(directory)) throw new DirectoryNotFoundException(directory);
    var tables = new List<JsonNode>();
    foreach (var file in Directory.EnumerateFiles(directory, "*.md", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
    {
        var lines = File.ReadAllLines(file);
        var name = Path.GetFileNameWithoutExtension(file);
        var columns = new List<JsonNode>();
        var inColumns = false;
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.StartsWith("# ", StringComparison.Ordinal)) name = line[2..].Split(' ', StringSplitOptions.RemoveEmptyEntries)[0].Trim('`');
            if (line.StartsWith("## ", StringComparison.Ordinal)) inColumns = line.Contains("column", StringComparison.OrdinalIgnoreCase);
            if (!inColumns || !line.StartsWith('|')) continue;
            var cells = line.Split('|').Select(x => x.Trim().Trim('`')).Where(x => x.Length > 0).ToArray();
            if (cells.Length < 2 || cells[0].Contains("---", StringComparison.Ordinal) || cells[0].Contains("Column", StringComparison.OrdinalIgnoreCase)) continue;
            columns.Add(new JsonObject { ["name"] = cells[0], ["type"] = NormalizeType(cells[1]) });
        }
        if (columns.Count > 0)
            tables.Add(new JsonObject { ["name"] = name, ["columns"] = new JsonArray(columns.OrderBy(x => x!["name"]!.GetValue<string>(), StringComparer.OrdinalIgnoreCase).ToArray()) });
    }
    var ordered = tables.OrderBy(x => x!["name"]!.GetValue<string>(), StringComparer.OrdinalIgnoreCase).ToArray();
    ValidateTables(ordered);
    return new JsonObject { ["source"] = "https://github.com/MicrosoftDocs/azure-reference-other", ["tables"] = new JsonArray(ordered) };
}

static string NormalizeType(string type) => type.Trim().ToLowerInvariant() switch
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

static void ValidateTables(IEnumerable<JsonNode> tables)
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

static void EnforceDropGuard(string existingPath, JsonObject updated, string property, double minimumRatio)
{
    if (!File.Exists(existingPath)) return;
    var existing = JsonNode.Parse(File.ReadAllText(existingPath))!.AsObject()[property]!.AsArray().Count;
    var next = updated[property]!.AsArray().Count;
    if (existing > 0 && next < existing * minimumRatio)
        throw new InvalidDataException($"Drop guard rejected {next} entries; existing snapshot has {existing}.");
}

static JsonObject Source(string url, JsonObject content) => new()
{
    ["url"] = url,
    ["sha256"] = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content.ToJsonString()))).ToLowerInvariant(),
};

static async Task WriteIfChanged(string path, JsonObject value)
{
    var json = value.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + Environment.NewLine;
    if (File.Exists(path) && await File.ReadAllTextAsync(path) == json) return;
    await File.WriteAllTextAsync(path, json);
    Console.WriteLine($"updated {path}");
}
