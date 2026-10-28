using System.Text.Json.Nodes;

namespace KqlValidator.SchemaSync;

public static class ColumnObservationNormalizer
{
    public const string SourceUrl = "https://xdrinternals.com/data/column-observations.json";
    public static JsonObject Normalize(string json)
    {
        var snapshot = ColumnObservationSnapshotValidator.Parse(json);
        if (snapshot.Observations.Count == 0) throw new InvalidDataException("Empty column observations snapshot.");
        var root = JsonNode.Parse(json)!.AsObject();
        root.Remove("$schema");
        root["source"] = SourceUrl;
        return root;
    }
}
