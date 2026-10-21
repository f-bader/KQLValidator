using System.Text.Json;
using KqlValidator.Contracts;
using KqlValidator.Validation;

namespace KqlValidator.Tests;

public sealed class StructuredSnapshotTests
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);

    private static StructuredSnapshot Snapshot()
    {
        Dictionary<string, string> entryTarget = new() { ["ActionType"] = "Exact value ", ["Context"] = "one" };
        Dictionary<string, string> combinationTarget = new() { ["Context"] = "one", ["ActionType"] = "Exact value " };
        return new(1,
            [new("entry", "DeviceEvents", "AdditionalFields", entryTarget, "shape", "json", "json-string",
                null, [new("Value", "string")], "observed", 1, 1, "Captured shape", "https://example.com/shape")],
            [new("DeviceEvents", "AdditionalFields", combinationTarget, ["shape"], [])], []);
    }

    [Fact]
    public void Shape_references_match_discriminators_in_any_key_order()
    {
        AssertValid(Snapshot());
    }

    [Theory]
    [InlineData("table")]
    [InlineData("column")]
    [InlineData("value")]
    [InlineData("case")]
    [InlineData("whitespace")]
    [InlineData("origin")]
    [InlineData("shape")]
    public void Shape_references_require_the_exact_target_shape_and_origin(string change)
    {
        var snapshot = Snapshot();
        var combination = snapshot.Combinations[0];
        combination = change switch
        {
            "table" => combination with { Table = "OtherTable" },
            "column" => combination with { Column = "OtherColumn" },
            "origin" => combination with { ObservedShapes = [], IllustrativeShapes = ["shape"] },
            "shape" => combination with { ObservedShapes = ["other-shape"] },
            _ => combination with
            {
                Discriminators = new(combination.Discriminators)
                {
                    ["ActionType"] = change == "case" ? "exact value " : change == "whitespace" ? "Exact value" : "Other value"
                }
            }
        };
        AssertInvalid(snapshot with { Combinations = [combination] }, "Unknown structured shape reference.");
    }

    [Fact]
    public void Duplicate_combinations_and_unreferenced_entries_are_rejected()
    {
        var snapshot = Snapshot();
        AssertInvalid(snapshot with
        {
            Combinations = [snapshot.Combinations[0], snapshot.Combinations[0] with { Discriminators = snapshot.Entries[0].Discriminators }]
        }, "Invalid structured combination.");
        AssertInvalid(snapshot with
        {
            Combinations = [snapshot.Combinations[0] with { ObservedShapes = [] }]
        }, "Structured entry is not referenced by its combination.");
    }

    [Fact]
    public void Catalog_keeps_shape_groups_entry_order_and_action_only_variants_across_pages()
    {
        var snapshot = Snapshot();
        Dictionary<string, string> otherTarget = new() { ["ActionType"] = "Other" };
        snapshot = snapshot with
        {
            Entries = [snapshot.Entries[0] with { Id = "z" }, snapshot.Entries[0] with { Id = "a" },
                snapshot.Entries[0] with { Id = "illustrative", Discriminators = otherTarget, Origin = "illustrative" }],
            Combinations = [snapshot.Combinations[0], new("DeviceEvents", "AdditionalFields", otherTarget, [], ["shape"])],
            KnownActions = [new("DeviceEvents", "AdditionalFields", new() { ["ActionType"] = "Action only" }, "ActionType", "https://example.com/action")]
        };
        AssertValid(snapshot);
        var path = Path.Combine(Path.GetTempPath(), $"structures-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(path, JsonSerializer.Serialize(snapshot, Options));
            var catalog = new StructuredColumnCatalog(path);
            var schema = TestSchemaCatalog.Bundled.Get(KqlEnvironment.Xdr);
            var all = catalog.Get(schema, "DeviceEvents", "AdditionalFields", null, true, 100, null);
            Assert.Equal(3, all.TotalCount);
            var observed = Assert.Single(all.Items, v => v.Status == "observed-shapes-available");
            Assert.Equal(new[] { "a", "z" }, observed.Shapes.Select(e => e.Id));
            Assert.Equal("illustrative", Assert.Single(Assert.Single(all.Items, v => v.Status == "illustrative-only").Shapes).Id);
            Assert.Single(Assert.Single(all.Items, v => v.Status == "known-combination-without-shape").KnownActions);
            string? cursor = null;
            foreach (var expected in all.Items)
            {
                var page = catalog.Get(schema, "DeviceEvents", "AdditionalFields", null, true, 1, cursor);
                Assert.Equal(JsonSerializer.Serialize(expected), JsonSerializer.Serialize(Assert.Single(page.Items)));
                cursor = page.NextCursor;
            }
            Assert.Null(cursor);
        }
        finally { File.Delete(path); }
    }

    private static void AssertValid(StructuredSnapshot snapshot)
    {
        StructuredSnapshotValidator.Validate(snapshot);
        KqlValidator.SchemaSync.StructuredColumnNormalizer.Normalize(JsonSerializer.Serialize(snapshot, Options));
    }

    private static void AssertInvalid(StructuredSnapshot snapshot, string message)
    {
        Assert.Equal(message, Assert.Throws<InvalidDataException>(() => StructuredSnapshotValidator.Validate(snapshot)).Message);
        Assert.Equal(message, Assert.Throws<InvalidDataException>(() =>
            KqlValidator.SchemaSync.StructuredColumnNormalizer.Normalize(JsonSerializer.Serialize(snapshot, Options))).Message);
    }
}
