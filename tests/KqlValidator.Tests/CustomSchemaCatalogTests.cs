using KqlValidator.Contracts;
using KqlValidator.Validation;

namespace KqlValidator.Tests;

public sealed class CustomSchemaCatalogTests : IDisposable
{
    private readonly string directory = Path.Combine(Path.GetTempPath(), $"kql-validator-overlay-{Guid.NewGuid():N}");

    public CustomSchemaCatalogTests() => Directory.CreateDirectory(directory);

    [Fact]
    public void Overlay_merges_common_and_environment_sections_with_unified_precedence()
    {
        var catalog = CreateCatalog("""
            {
              "common":{"tables":[{"name":"Shared","columns":[{"name":"Common","type":"string"}]},{"name":"DeviceEvents","columns":[{"name":"TenantTag","type":"string"}]}],"functions":[{"name":"SharedFunction","parameters":[],"returns":{"kind":"scalar","type":"string"}}]},
              "environments":{
                "xdr":{"tables":[{"name":"Conflict","columns":[{"name":"Source","type":"string"}]},{"name":"DeviceEvents","columns":[{"name":"Timestamp","type":"string"}]}],"functions":[{"name":"SharedFunction","parameters":[],"returns":{"kind":"scalar","type":"long"}},{"name":"FileProfile","parameters":[],"returns":{"kind":"scalar","type":"string"}}]},
                "sentinel":{"tables":[{"name":"Conflict","columns":[{"name":"Source","type":"long"}]}],"functions":[]},
                "unified":{"tables":[{"name":"Shared","columns":[{"name":"Unified","type":"bool"}]}],"functions":[]}
              }
            }
            """);

        var xdr = catalog.Get(KqlEnvironment.Xdr);
        var sentinel = catalog.Get(KqlEnvironment.Sentinel);
        var unified = catalog.Get(KqlEnvironment.Unified);

        Assert.Contains(xdr.Tables["DeviceEvents"].Columns, x => x.Name == "TenantTag" && x.Type == "string");
        Assert.Equal("string", xdr.Tables["DeviceEvents"].Columns.Single(x => x.Name == "Timestamp").Type);
        Assert.Equal("long", xdr.Functions["SharedFunction"].ScalarReturnType);
        Assert.Equal("string", xdr.Functions["FileProfile"].ScalarReturnType);
        Assert.Equal("string", unified.Tables["Conflict"].Columns.Single(x => x.Name == "Source").Type);
        Assert.Contains(unified.Tables["Shared"].Columns, x => x.Name == "Common");
        Assert.Contains(unified.Tables["Shared"].Columns, x => x.Name == "Unified" && x.Type == "bool");
        Assert.NotEqual(new SchemaCatalog().Get(KqlEnvironment.Xdr).Version, xdr.Version);
        Assert.Equal("long", sentinel.Tables["Conflict"].Columns.Single(x => x.Name == "Source").Type);
    }

    [Theory]
    [InlineData("{\"common\":{\"nope\":true},\"environments\":{}}", "Unknown property")]
    [InlineData("{\"common\":{\"tables\":[{\"name\":\"Bad\",\"columns\":[{\"name\":\"x\",\"type\":\"not-a-type\"}]}]},\"environments\":{}}", "supported KQL scalar type")]
    [InlineData("{\"common\":{\"functions\":[{\"name\":\"F\",\"parameters\":[],\"returns\":{\"kind\":\"scalar\",\"type\":\"string\",\"preserveInput\":true}}]},\"environments\":{}}", "cannot have columns or preserve input")]
    public void Invalid_overlay_fails_during_catalog_construction(string json, string expected)
    {
        var path = Write(json);
        var exception = Assert.Throws<InvalidDataException>(() => new SchemaCatalog(overlayPath: path));
        Assert.Contains(expected, exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Request_scoped_declarations_cannot_shadow_persistent_declarations()
    {
        var catalog = CreateCatalog("""
            {"common":{"tables":[{"name":"PersistentEvents","columns":[{"name":"Value","type":"string"}]}]},"environments":{}}
            """);
        var validator = new RequestValidator(catalog, new LintRuleCatalog());

        var exception = Assert.Throws<RequestValidationException>(() => validator.Validate(new ValidateRequest(
            "PersistentEvents", KqlEnvironment.Xdr, LintProfile.General,
            new ValidationExtensions(Tables: [new TableDeclaration("PersistentEvents", [new ColumnDeclaration("Value", "string")])]))));

        Assert.Contains("collides", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    private SchemaCatalog CreateCatalog(string json) => new(overlayPath: Write(json));

    private string Write(string json)
    {
        var path = Path.Combine(directory, "custom-schema.json");
        File.WriteAllText(path, json);
        return path;
    }

    public void Dispose()
    {
        if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
    }
}
