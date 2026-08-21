using System.Text.Json.Nodes;
using KqlValidator.SchemaSync;

namespace KqlValidator.Tests;

public sealed class AsimParserNormalizerTests
{
    [Fact]
    public void Normalize_extracts_parser_names_parameters_and_schema_columns()
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllText(Path.Combine(directory, "imDns.yaml"),
                """
                EquivalentBuiltInParser: _Im_Dns
                Normalization:
                  Schema: Dns
                ParserParams:
                  - Name: starttime
                    Type: datetime
                  - Name: domain_has_any
                    Type: dynamic
                ParserQuery: |
                  DnsEvents | project TimeGenerated
                """);
            File.WriteAllText(Path.Combine(directory, "imDnsVendor.yaml"),
                """
                EquivalentBuiltInParser: _Im_Dns
                Normalization:
                  Schema: Dns
                ParserParams:
                  - Name: starttime
                    Type: datetime
                  - Name: response_has_ipv4
                    Type: string
                ParserQuery: |
                  VendorDns | project TimeGenerated
                """);

            var result = AsimParserNormalizer.Normalize(directory);

            var function = Assert.Single(result["functions"]!.AsArray());
            Assert.Equal("_Im_Dns", function!["name"]!.GetValue<string>());

            var parameters = function["parameters"]!.AsArray().Select(x => x!["name"]!.GetValue<string>()).ToArray();
            Assert.Contains("starttime", parameters);
            Assert.Contains("domain_has_any", parameters);
            Assert.Contains("response_has_ipv4", parameters);
            Assert.Equal(3, parameters.Length);
            Assert.All(function["parameters"]!.AsArray(), x => Assert.True(x!["optional"]!.GetValue<bool>()));

            var columns = function["outputColumns"]!.AsArray().Select(x => x!["name"]!.GetValue<string>()).ToArray();
            Assert.Contains("TimeGenerated", columns);
            Assert.Contains("DnsQuery", columns);
            Assert.Contains("DnsResponseCodeName", columns);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Normalize_rejects_a_directory_without_parsers()
    {
        var directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllText(Path.Combine(directory, "unrelated.yaml"), "Product: NotAParser");
            Assert.Throws<InvalidDataException>(() => AsimParserNormalizer.Normalize(directory));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
