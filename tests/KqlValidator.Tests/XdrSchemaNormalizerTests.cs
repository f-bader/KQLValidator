using KqlValidator.SchemaSync;

namespace KqlValidator.Tests;

public sealed class XdrSchemaNormalizerTests
{
    [Fact]
    public void Normalize_only_imports_explicit_Defender_tables()
    {
        var result = XdrSchemaNormalizer.Normalize("""
            [
              {"Name":"DeviceEvents","UsxResourceType":"Defender","Schema":[
                {"Name":"Timestamp","Type":"DateTime"},
                {"Name":"ReportId","Type":"Int64"}
              ]},
              {"Name":"SigninLogs","Schema":[]},
              {"Name":"SecurityEvent","UsxResourceType":"Sentinel","Schema":[]},
              {"Name":"Unknown","UsxResourceType":null,"Schema":[]},
              {"Name":"Future","UsxResourceType":"Other","Schema":[]}
            ]
            """);

        var table = Assert.Single(result["tables"]!.AsArray())!;
        Assert.Equal("DeviceEvents", table["name"]!.GetValue<string>());
        var columns = table["columns"]!.AsArray();
        Assert.Equal("ReportId", columns[0]!["name"]!.GetValue<string>());
        Assert.Equal("long", columns[0]!["type"]!.GetValue<string>());
        Assert.Equal("datetime", columns[1]!["type"]!.GetValue<string>());
    }

    [Fact]
    public void Normalize_filters_before_reading_non_Defender_schema()
    {
        var result = XdrSchemaNormalizer.Normalize("""
            [{"Name":"SentinelOnly"}, {"UsxResourceType":"Sentinel"}]
            """);

        Assert.Empty(result["tables"]!.AsArray());
    }

    [Fact]
    public void Normalize_rejects_duplicate_Defender_tables()
    {
        Assert.Throws<InvalidDataException>(() => XdrSchemaNormalizer.Normalize("""
            [
              {"Name":"DeviceEvents","UsxResourceType":"Defender","Schema":[]},
              {"Name":"deviceevents","UsxResourceType":"Defender","Schema":[]}
            ]
            """));
    }
}
