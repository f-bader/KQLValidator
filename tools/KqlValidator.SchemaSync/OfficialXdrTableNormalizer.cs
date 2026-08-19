using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace KqlValidator.SchemaSync;

public sealed record OfficialXdrTableSource(string TableName, string DocumentationUrl, string MarkdownUrl);
public sealed record OfficialXdrTableDocument(string FileName, string MarkdownUrl)
{
    public string DocumentationUrl => $"https://learn.microsoft.com/en-us/defender-xdr/{Path.GetFileNameWithoutExtension(FileName)}";
}

public static class OfficialXdrTableNormalizer
{
    private static readonly Regex TableDocumentName = new("^advanced-hunting-.+-table\\.md$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>Parses the GitHub Contents API response for the public defender-xdr directory.</summary>
    public static IReadOnlyList<OfficialXdrTableDocument> DiscoverDocuments(string contentsJson)
    {
        var contents = JsonNode.Parse(contentsJson)?.AsArray()
            ?? throw new InvalidDataException("Defender XDR Contents API response must be an array.");
        return contents.Select(item => item?.AsObject() ?? throw new InvalidDataException("Defender XDR Contents API entries must be objects."))
            .Where(item => item["type"]?.GetValue<string>() == "file")
            .Select(item => new { Name = item["name"]?.GetValue<string>(), DownloadUrl = item["download_url"]?.GetValue<string>() })
            .Where(item => item.Name is not null && TableDocumentName.IsMatch(item.Name))
            .Select(item => new OfficialXdrTableDocument(item.Name!, item.DownloadUrl is { Length: > 0 }
                ? item.DownloadUrl
                : throw new InvalidDataException($"Defender XDR table document '{item.Name}' has no download_url.")))
            .OrderBy(document => document.FileName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static OfficialXdrTableSource SourceFromDocument(OfficialXdrTableDocument document, string markdown) =>
        new(ExtractTableName(markdown), document.DocumentationUrl, document.MarkdownUrl);

    public static string ExtractTableName(string markdown)
    {
        var heading = markdown.Split(['\r', '\n'], StringSplitOptions.None)
            .Select(line => line.Trim())
            .FirstOrDefault(line => line.StartsWith("# ", StringComparison.Ordinal));
        if (heading is null) throw new InvalidDataException("Official XDR documentation has no H1 heading.");
        var name = heading[2..].Trim().Trim('`').Split([' ', '('], StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        if (string.IsNullOrEmpty(name) || !IsIdentifier(name))
            throw new InvalidDataException($"Official XDR documentation H1 does not begin with a table name: '{heading}'.");
        return name;
    }

    public static IReadOnlyList<OfficialXdrTableSource> LoadSources(string json)
    {
        var sources = JsonNode.Parse(json)?.AsObject()["sources"]?.AsArray()
            ?? throw new InvalidDataException("Official XDR table source catalog must contain a sources array.");
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        return sources.Select(source =>
        {
            var entry = source?.AsObject() ?? throw new InvalidDataException("Official XDR table source entries must be objects.");
            var tableName = Required(entry, "tableName");
            if (!names.Add(tableName)) throw new InvalidDataException($"Duplicate official XDR table '{tableName}'.");
            return new OfficialXdrTableSource(tableName, Required(entry, "documentationUrl"), Required(entry, "markdownUrl"));
        }).ToArray();
    }

    public static JsonObject Normalize(OfficialXdrTableSource source, string markdown)
    {
        var documentedName = ExtractTableName(markdown);
        if (!documentedName.Equals(source.TableName, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException($"Official XDR documentation H1 identifies '{documentedName}', not '{source.TableName}'.");
        var columns = new List<JsonNode>();
        foreach (var rawLine in markdown.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var cells = rawLine.Trim().Trim('|').Split('|').Select(cell => cell.Trim().Trim('`')).ToArray();
            if (cells.Length < 2 ||
                cells[0].Equals("Column name", StringComparison.OrdinalIgnoreCase) ||
                cells[0].All(character => character is '-' or ':' or ' '))
                continue;
            if (!IsIdentifier(cells[0]) || !IsSupportedType(cells[1])) continue;
            columns.Add(new JsonObject { ["name"] = cells[0], ["type"] = NormalizeType(cells[1]) });
        }

        if (columns.Count == 0) throw new InvalidDataException($"Official XDR documentation for '{source.TableName}' contains no schema columns.");
        var duplicate = columns.GroupBy(column => column!["name"]!.GetValue<string>(), StringComparer.OrdinalIgnoreCase).FirstOrDefault(group => group.Count() > 1);
        if (duplicate is not null) throw new InvalidDataException($"Official XDR documentation for '{source.TableName}' contains duplicate column '{duplicate.Key}'.");
        return new JsonObject
        {
            ["name"] = source.TableName,
            ["documentationUrl"] = source.DocumentationUrl,
            ["sourceUrl"] = source.MarkdownUrl,
            ["columns"] = new JsonArray(columns.OrderBy(column => column!["name"]!.GetValue<string>(), StringComparer.OrdinalIgnoreCase).ToArray()),
        };
    }

    private static string Required(JsonObject value, string property) => value[property]?.GetValue<string>() is { Length: > 0 } text
        ? text
        : throw new InvalidDataException($"Official XDR table source is missing '{property}'.");

    private static bool IsIdentifier(string value) => value.All(character => char.IsLetterOrDigit(character) || character == '_');

    private static bool IsSupportedType(string value) => value.Trim().ToLowerInvariant() is
        "int16" or "int32" or "integer" or "int64" or "bigint" or "boolean" or "object" or "array" or
        "float" or "double" or "decimal" or "date" or "datetime" or "guid" or "timespan" or "dynamic" or "string";

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
}
