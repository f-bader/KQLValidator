using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace KqlValidator.SchemaSync;

public static partial class AsimParserNormalizer
{
    private const string Source = "https://github.com/Azure/Azure-Sentinel/tree/master/Parsers";

    public static JsonObject Normalize(string directory)
    {
        if (!Directory.Exists(directory)) throw new DirectoryNotFoundException(directory);
        var functions = new Dictionary<string, ParserDefinition>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in Directory.EnumerateFiles(directory, "*.yaml", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            var content = File.ReadAllText(file);
            var name = BuiltInParser().Match(content).Groups["name"].Value;
            if (string.IsNullOrWhiteSpace(name)) continue;
            var schema = Schema().Match(content).Groups["schema"].Value;
            var definition = new ParserDefinition(name, ParseParameters(content), OutputColumns(schema));
            if (functions.TryGetValue(name, out var current))
                functions[name] = current.Merge(definition);
            else functions[name] = definition;
        }

        if (functions.Count == 0) throw new InvalidDataException("No ASIM parser definitions were found.");
        return new JsonObject
        {
            ["source"] = Source,
            ["functions"] = new JsonArray(functions.Values
                .OrderBy(function => function.Name, StringComparer.OrdinalIgnoreCase)
                .Select(function => (JsonNode)function.ToJson()).ToArray()),
        };
    }

    private static IReadOnlyList<ParameterDefinition> ParseParameters(string content)
    {
        var section = ParserParameters().Match(content).Groups["parameters"].Value;
        if (string.IsNullOrWhiteSpace(section)) return [];
        var result = new List<ParameterDefinition>();
        foreach (Match match in Parameter().Matches(section))
            result.Add(new ParameterDefinition(match.Groups["name"].Value, NormalizeType(match.Groups["type"].Value)));
        return result;
    }

    private static IReadOnlyList<SchemaColumnDefinition> OutputColumns(string schema) =>
    [
        new("TimeGenerated", "datetime"), new("EventType", "string"), new("EventResult", "string"),
        new("EventOriginalType", "string"), new("EventOriginalResultDetails", "string"),
        new("EventProduct", "string"), new("EventVendor", "string"), new("EventSchema", "string"),
        new("EventSchemaVersion", "string"), new("DvcHostname", "string"), new("DvcIpAddr", "string"),
        new("SrcIpAddr", "string"), new("SrcHostname", "string"), new("DstIpAddr", "string"),
        new("DstHostname", "string"), new("TargetUsername", "string"), new("ActorUsername", "string"),
        new("TargetUserId", "string"), new("ActorUserId", "string"), new("NetworkProtocol", "string"),
        new("NetworkProtocolNumber", "int"), new("AdditionalFields", "dynamic"), new("EventParser", "string"),
        new("EventCount", "long"), new("EventStartTime", "datetime"), new("EventEndTime", "datetime"),
        new("EventUid", "string"), new("EventMessage", "string"), new("EventSeverity", "string"),
        new("ASimSchema", "string"), new("ASimSchemaVersion", "string"),
        .. SchemaSpecificColumns(schema),
    ];

    private static IEnumerable<SchemaColumnDefinition> SchemaSpecificColumns(string schema) => schema switch
    {
        "Dns" => [new("DnsQuery", "string"), new("DnsQueryType", "int"), new("DnsQueryTypeName", "string"), new("DnsResponseCode", "int"), new("DnsResponseCodeName", "string")],
        "Authentication" => [new("LogonMethod", "string"), new("LogonType", "string"), new("TargetAppName", "string")],
        "NetworkSession" => [new("NetworkDirection", "string"), new("SrcPortNumber", "int"), new("DstPortNumber", "int"), new("NetworkBytes", "long")],
        "FileEvent" => [new("FileName", "string"), new("FilePath", "string"), new("FileHash", "string")],
        "ProcessEvent" => [new("Process", "string"), new("ProcessCommandLine", "string"), new("ParentProcess", "string")],
        "RegistryEvent" => [new("RegistryKey", "string"), new("RegistryValueName", "string"), new("RegistryValueData", "string")],
        "WebSession" => [new("Url", "string"), new("HttpStatusCode", "int"), new("HttpUserAgent", "string")],
        _ => [],
    };

    private static string NormalizeType(string type) => type.Trim().ToLowerInvariant() switch
    {
        "bool" or "boolean" => "bool",
        "int" or "int32" or "integer" => "int",
        "long" or "int64" => "long",
        "datetime" => "datetime",
        "dynamic" => "dynamic",
        "real" => "real",
        _ => "string",
    };

    [GeneratedRegex("^EquivalentBuiltInParser:\\s*(?<name>\\S+)\\s*$", RegexOptions.Multiline)]
    private static partial Regex BuiltInParser();

    [GeneratedRegex("^Normalization:\\s*\\r?\\n\\s+Schema:\\s*(?<schema>\\S+)", RegexOptions.Multiline)]
    private static partial Regex Schema();

    [GeneratedRegex("^ParserParams:\\s*\\r?\\n(?<parameters>.*?)(?=^ParserQuery:)", RegexOptions.Multiline | RegexOptions.Singleline)]
    private static partial Regex ParserParameters();

    [GeneratedRegex("^\\s+- Name:\\s*(?<name>\\S+)\\s*\\r?\\n\\s+Type:\\s*(?<type>\\S+)", RegexOptions.Multiline)]
    private static partial Regex Parameter();

    private sealed record ParameterDefinition(string Name, string Type)
    {
        public JsonObject ToJson() => new() { ["name"] = Name, ["type"] = Type, ["optional"] = true };
    }

    private sealed record SchemaColumnDefinition(string Name, string Type)
    {
        public JsonObject ToJson() => new() { ["name"] = Name, ["type"] = Type };
    }

    private sealed record ParserDefinition(string Name, IReadOnlyList<ParameterDefinition> Parameters, IReadOnlyList<SchemaColumnDefinition> OutputColumns)
    {
        public ParserDefinition Merge(ParserDefinition other) => new(
            Name,
            Parameters.Concat(other.Parameters).GroupBy(parameter => parameter.Name, StringComparer.OrdinalIgnoreCase).Select(group => group.First()).ToArray(),
            OutputColumns.Concat(other.OutputColumns).GroupBy(column => column.Name, StringComparer.OrdinalIgnoreCase).Select(group => group.First()).ToArray());

        public JsonObject ToJson() => new()
        {
            ["name"] = Name,
            ["parameters"] = new JsonArray(Parameters.Select(parameter => (JsonNode)parameter.ToJson()).ToArray()),
            ["outputColumns"] = new JsonArray(OutputColumns.Select(column => (JsonNode)column.ToJson()).ToArray()),
        };
    }
}
