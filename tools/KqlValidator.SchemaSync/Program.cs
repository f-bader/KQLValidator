using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using KqlValidator.SchemaSync;

const string xdrSchemaUrl = "https://xdrinternals.com/FullSchema-latest.json";
const string actionTypesUrl = "https://xdrinternals.com/ActionTypeSchema-latest.json";
const string logAnalyticsEndpoint = "https://api.loganalytics.azure.com/v1";
const string logAnalyticsResource = "https://api.loganalytics.io";
const string defenderXdrContentsUrl = "https://api.github.com/repos/MicrosoftDocs/defender-docs/contents/defender-xdr?ref=public";

var arguments = ParseArguments(args);
if (arguments.ContainsKey("sentinel-dir") && arguments.ContainsKey("sentinel-workspace-id"))
    throw new ArgumentException("Use either --sentinel-dir or --sentinel-workspace-id, not both.");
if (arguments.ContainsKey("sentinel-only") && !arguments.ContainsKey("sentinel-dir") && !arguments.ContainsKey("sentinel-workspace-id"))
    throw new ArgumentException("--sentinel-only requires --sentinel-dir or --sentinel-workspace-id.");
var outputDirectory = arguments.GetValueOrDefault("out")
    ?? throw new ArgumentException("--out is required");
Directory.CreateDirectory(outputDirectory);

using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
http.DefaultRequestHeaders.UserAgent.ParseAdd("kql-validator-schema-sync/1.0");

JsonObject? xdr = null;
JsonObject? actions = null;
// Cross-platform enrichment refreshes even with --sentinel-only.
var structures = StructuredColumnNormalizer.Normalize(await http.GetStringAsync(StructuredColumnNormalizer.SourceUrl));
foreach (var property in new[] { "entries", "combinations", "knownActions" })
    EnforceDropGuard(Path.Combine(outputDirectory, "structured-columns.json"), structures, property, 0.8);
await WriteIfChanged(Path.Combine(outputDirectory, "structured-columns.json"), structures);
JsonObject? relations = null;
JsonObject? officialXdrTables = null;
IReadOnlyList<OfficialXdrTableSource> officialXdrSources = [];
if (!arguments.ContainsKey("sentinel-only"))
{
    var rawXdr = await http.GetStringAsync(xdrSchemaUrl);
    var rawActions = await http.GetStringAsync(actionTypesUrl);
    xdr = XdrSchemaNormalizer.Normalize(rawXdr);
    actions = NormalizeActions(rawActions);
    relations = ColumnRelationNormalizer.Normalize(await http.GetStringAsync(ColumnRelationNormalizer.SourceUrl));
    EnforceDropGuard(Path.Combine(outputDirectory, "column-relations.json"), relations, "relations", 0.8);

    EnforceDropGuard(Path.Combine(outputDirectory, "xdr.json"), xdr, "tables", 0.8);
    await WriteIfChanged(Path.Combine(outputDirectory, "xdr.json"), xdr);
    await WriteIfChanged(Path.Combine(outputDirectory, "action-types.json"), actions);
    await WriteIfChanged(Path.Combine(outputDirectory, "column-relations.json"), relations);

    (officialXdrTables, officialXdrSources, var officialXdrCatalog) = await RefreshOfficialXdrTables(
        outputDirectory, http, arguments.ContainsKey("prune-official-xdr-tables"));
    if (officialXdrTables is not null)
        await WriteIfChanged(Path.Combine(outputDirectory, "xdr-official-tables.json"), officialXdrTables);
    if (officialXdrCatalog is not null)
        await WriteIfChanged(Path.Combine(outputDirectory, "xdr-official-table-sources.json"), officialXdrCatalog);
}

JsonObject? sentinel = null;
string? sentinelManifestSource = null;
if (arguments.TryGetValue("sentinel-dir", out var sentinelDirectory))
{
    sentinel = NormalizeSentinel(sentinelDirectory);
    sentinelManifestSource = "https://github.com/MicrosoftDocs/azure-reference-other";
}
else if (arguments.TryGetValue("sentinel-workspace-id", out var workspaceId))
{
    if (!Guid.TryParse(workspaceId, out _)) throw new ArgumentException("--sentinel-workspace-id must be a workspace GUID.");
    var accessToken = await GetAzureCliAccessToken();
    var request = new HttpRequestMessage(HttpMethod.Post, $"{logAnalyticsEndpoint}/workspaces/{workspaceId}/metadata")
    {
        Content = new StringContent("{}", Encoding.UTF8, "application/json"),
    };
    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
    using var response = await http.SendAsync(request);
    if (!response.IsSuccessStatusCode)
    {
        var requestId = response.Headers.TryGetValues("x-ms-request-id", out var values) ? values.FirstOrDefault() : null;
        throw new HttpRequestException($"Log Analytics metadata request failed with {(int)response.StatusCode} ({response.StatusCode})" +
            (requestId is null ? "." : $"; request ID: {requestId}."));
    }
    sentinel = SentinelMetadataNormalizer.Normalize(
        await response.Content.ReadAsStringAsync(),
        arguments.ContainsKey("include-custom-tables"));
}

if (sentinel is not null)
{
    EnforceDropGuard(Path.Combine(outputDirectory, "sentinel.json"), sentinel, "tables", 0.8);
    await WriteIfChanged(Path.Combine(outputDirectory, "sentinel.json"), sentinel);
}

if (arguments.TryGetValue("asim-dir", out var asimDirectory))
{
    var asim = AsimParserNormalizer.Normalize(asimDirectory);
    await WriteIfChanged(Path.Combine(outputDirectory, "sentinel-native-functions.json"), asim);
}

if (xdr is not null && actions is not null)
{
    var sources = new JsonArray(Source(xdrSchemaUrl, xdr), Source(actionTypesUrl, actions), Source(ColumnRelationNormalizer.SourceUrl, relations!), Source(StructuredColumnNormalizer.SourceUrl, structures));
    if (officialXdrTables is not null)
        foreach (var source in officialXdrSources)
            if (officialXdrTables["tables"]!.AsArray().FirstOrDefault(table => table!["name"]!.GetValue<string>().Equals(source.TableName, StringComparison.OrdinalIgnoreCase)) is JsonObject table)
                sources.Add(Source(source.DocumentationUrl, table));
    if (sentinel is not null && sentinelManifestSource is not null)
        sources.Add(Source(sentinelManifestSource, sentinel));
    var manifest = new JsonObject { ["sources"] = sources };
    await WriteIfChanged(Path.Combine(outputDirectory, "manifest.json"), manifest);
}

else
{
    var manifestPath = Path.Combine(outputDirectory, "manifest.json");
    var manifest = File.Exists(manifestPath) ? JsonNode.Parse(await File.ReadAllTextAsync(manifestPath))!.AsObject() : new JsonObject();
    var sources = manifest["sources"] as JsonArray ?? new JsonArray();
    foreach (var source in sources.Where(n => n?["url"]?.GetValue<string>() == StructuredColumnNormalizer.SourceUrl).ToArray())
        sources.Remove(source);
    sources.Add(Source(StructuredColumnNormalizer.SourceUrl, structures));
    if (sources.Parent is null) manifest["sources"] = sources;
    await WriteIfChanged(manifestPath, manifest);
}

static Dictionary<string, string> ParseArguments(string[] values)
{
    var parsed = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    for (var i = 0; i < values.Length; i++)
    {
        if (!values[i].StartsWith("--", StringComparison.Ordinal))
            throw new ArgumentException("Arguments must be --name value pairs, except --include-custom-tables and --sentinel-only.");
        var name = values[i][2..];
        if (name.Equals("include-custom-tables", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("sentinel-only", StringComparison.OrdinalIgnoreCase) ||
            name.Equals("prune-official-xdr-tables", StringComparison.OrdinalIgnoreCase))
        {
            parsed[name] = "true";
            continue;
        }
        if (i + 1 >= values.Length || values[i + 1].StartsWith("--", StringComparison.Ordinal))
            throw new ArgumentException("Arguments must be --name value pairs, except --include-custom-tables and --sentinel-only.");
        parsed[name] = values[++i];
    }
    return parsed;
}

static async Task<string> GetAzureCliAccessToken()
{
    var startInfo = new ProcessStartInfo("az")
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
    };
    startInfo.ArgumentList.Add("account");
    startInfo.ArgumentList.Add("get-access-token");
    startInfo.ArgumentList.Add("--resource");
    startInfo.ArgumentList.Add(logAnalyticsResource);
    startInfo.ArgumentList.Add("--query");
    startInfo.ArgumentList.Add("accessToken");
    startInfo.ArgumentList.Add("--output");
    startInfo.ArgumentList.Add("tsv");

    using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Unable to start Azure CLI. Install Azure CLI and run 'az login'.");
    var output = await process.StandardOutput.ReadToEndAsync();
    var error = await process.StandardError.ReadToEndAsync();
    await process.WaitForExitAsync();
    if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
        throw new InvalidOperationException("Azure CLI could not acquire a Log Analytics token. Run 'az login' and verify workspace access." +
            (string.IsNullOrWhiteSpace(error) ? string.Empty : " Azure CLI reported an error."));
    return output.Trim();
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

static async Task<(JsonObject? Snapshot, IReadOnlyList<OfficialXdrTableSource> Sources, JsonObject? Catalog)> RefreshOfficialXdrTables(
    string outputDirectory,
    HttpClient http,
    bool prune)
{
    var sourcePath = Path.Combine(outputDirectory, "xdr-official-table-sources.json");
    var existingSources = File.Exists(sourcePath)
        ? OfficialXdrTableNormalizer.LoadSources(await File.ReadAllTextAsync(sourcePath))
        : [];
    var snapshotPath = Path.Combine(outputDirectory, "xdr-official-tables.json");
    var tables = File.Exists(snapshotPath)
        ? JsonNode.Parse(await File.ReadAllTextAsync(snapshotPath))?.AsObject()["tables"]?.AsArray()
            ?.OfType<JsonObject>()
            .ToDictionary(table => table["name"]!.GetValue<string>(), table => table.DeepClone().AsObject(), StringComparer.OrdinalIgnoreCase)
            ?? new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase)
        : new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase);

    IReadOnlyList<OfficialXdrTableDocument> documents;
    try
    {
        using var response = await http.GetAsync(defenderXdrContentsUrl);
        response.EnsureSuccessStatusCode();
        documents = OfficialXdrTableNormalizer.DiscoverDocuments(await response.Content.ReadAsStringAsync());
    }
    catch (Exception exception)
    {
        Console.Error.WriteLine($"warning: retaining the official XDR catalog because Defender Docs discovery failed: {exception.Message}");
        return (Snapshot(tables), existingSources, null);
    }

    var sources = existingSources.ToDictionary(source => source.TableName, StringComparer.OrdinalIgnoreCase);
    var discoveredUrls = new HashSet<string>(documents.Select(document => document.MarkdownUrl), StringComparer.OrdinalIgnoreCase);
    foreach (var document in documents)
    {
        try
        {
            using var response = await http.GetAsync(document.MarkdownUrl);
            response.EnsureSuccessStatusCode();
            var markdown = await response.Content.ReadAsStringAsync();
            var source = OfficialXdrTableNormalizer.SourceFromDocument(document, markdown);
            tables[source.TableName] = OfficialXdrTableNormalizer.Normalize(source, markdown);
            sources[source.TableName] = source;
        }
        catch (Exception exception)
        {
            var retained = existingSources.FirstOrDefault(source => source.MarkdownUrl.Equals(document.MarkdownUrl, StringComparison.OrdinalIgnoreCase));
            Console.Error.WriteLine($"warning: retaining the last known official XDR schema for '{retained?.TableName ?? document.FileName}': {exception.Message}");
        }
    }

    if (prune)
    {
        var removed = sources.Values.Where(source => !discoveredUrls.Contains(source.MarkdownUrl)).ToArray();
        foreach (var source in removed)
        {
            sources.Remove(source.TableName);
            tables.Remove(source.TableName);
        }
    }

    var orderedSources = sources.Values.OrderBy(source => source.TableName, StringComparer.OrdinalIgnoreCase).ToArray();
    return (Snapshot(tables), orderedSources, new JsonObject
    {
        ["sources"] = new JsonArray(orderedSources.Select(source => (JsonNode)new JsonObject
        {
            ["tableName"] = source.TableName,
            ["documentationUrl"] = source.DocumentationUrl,
            ["markdownUrl"] = source.MarkdownUrl,
        }).ToArray()),
    });
}

static JsonObject Snapshot(IReadOnlyDictionary<string, JsonObject> tables) => new()
{
    ["source"] = "Microsoft Defender XDR documentation",
    ["tables"] = new JsonArray(tables.Values.OrderBy(table => table["name"]!.GetValue<string>(), StringComparer.OrdinalIgnoreCase).Cast<JsonNode?>().ToArray()),
};

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
