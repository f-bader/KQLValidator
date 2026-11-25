using KqlValidator.SchemaSync;

namespace KqlValidator.Tests;

public sealed class SentinelSchemaNormalizerTests
{
    [Fact]
    public void NormalizeUpstreamFeed_imports_only_noncustom_Sentinel_tables()
    {
        var result = SentinelSchemaNormalizer.NormalizeUpstreamFeed("""
            [
              {"Name":"SigninLogs","TableSource":"sentinel","Schema":[{"Name":"TimeGenerated","Type":"DateTime"},{"Name":"Count","Type":"Int64"}]},
              {"Name":"Custom_CL","TableSource":"sentinel","Schema":[]},
              {"Name":"DeviceEvents","UsxResourceType":"Defender","Schema":[]},
              {"Name":"LegacySentinel","UsxResourceType":"Sentinel","Schema":[]}
            ]
            """);

        var tables = result["tables"]!.AsArray();
        Assert.Equal(new[] { "SigninLogs", "LegacySentinel" },
            tables.Select(table => table!["name"]!.GetValue<string>()).ToArray());
        Assert.Equal("long", tables[0]!["columns"]![0]!["type"]!.GetValue<string>());
        Assert.Equal("datetime", tables[0]!["columns"]![1]!["type"]!.GetValue<string>());
    }

    [Fact]
    public void MergeWithDocumentation_adds_intersection_and_retains_existing_tables()
    {
        var upstream = SentinelSchemaNormalizer.NormalizeUpstreamFeed("""
            [
              {"Name":"SigninLogs","TableSource":"sentinel","Schema":[{"Name":"Count","Type":"Int64"}]},
              {"Name":"Undocumented","TableSource":"sentinel","Schema":[]}
            ]
            """);
        var docs = System.Text.Json.Nodes.JsonNode.Parse("""
            {"tables":[{"name":"SigninLogs","columns":[]}]}
            """)!.AsObject();
        var previous = System.Text.Json.Nodes.JsonNode.Parse("""
            {"tables":[{"name":"SigninLogs","columns":[{"name":"Old","type":"string"}]},{"name":"MDECustomCollectionDeviceFileEvents","columns":[{"name":"FileName","type":"string"}]}]}
            """)!.AsObject();

        var result = SentinelSchemaNormalizer.MergeWithDocumentation(upstream, docs, previous);
        var tables = result["tables"]!.AsArray();
        Assert.Equal(new[] { "MDECustomCollectionDeviceFileEvents", "SigninLogs" },
            tables.Select(table => table!["name"]!.GetValue<string>()).ToArray());
        Assert.Equal("long", tables[1]!["columns"]![0]!["type"]!.GetValue<string>());
    }
}
