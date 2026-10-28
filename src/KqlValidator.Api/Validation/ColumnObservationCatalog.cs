using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace KqlValidator.Validation;

public sealed record ObservationSource(string Name, string Url, string? Dataset = null);
public sealed record ColumnObservation(string Id, string Table, string Column, string Kind, string Title, string Text,
    IReadOnlyList<ObservationSource> Sources, string? Path = null, string? Guidance = null,
    string? Query = null, string? QueryLanguage = null, string? DiagnosticEligibility = null);
public sealed record ColumnObservationResponse(int Version, string Source, string Sha256, IReadOnlyList<ColumnObservation> Items);

public sealed class ColumnObservationCatalog
{
    public const string SourceUrl = "https://xdrinternals.com/data/column-observations.json";
    private readonly ColumnObservation[] entries;
    private readonly string hash;

    public ColumnObservationCatalog(string path, bool required = true)
    {
        if (!File.Exists(path))
        {
            if (required) throw new InvalidDataException("Bundled column observations snapshot is missing.");
            entries = []; hash = ""; return;
        }
        var json = File.ReadAllText(path);
        var snapshot = ColumnObservationSnapshotValidator.Parse(json);
        using var document = JsonDocument.Parse(json);
        hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(document.RootElement)))).ToLowerInvariant();
        var sources = snapshot.Sources.ToDictionary(s => s.Id, s => new ObservationSource(s.Name, s.Url, s.Dataset), StringComparer.Ordinal);
        entries = snapshot.Observations.OrderBy(e => e.Id, StringComparer.Ordinal).Select(e => new ColumnObservation(
            e.Id, e.Table, e.Column, e.Kind, e.Title, e.Text, e.SourceIds.Select(id => sources[id]).ToArray(),
            e.Path, e.Guidance, e.Query, e.QueryLanguage, e.DiagnosticEligibility)).ToArray();
    }

    public ColumnObservationResponse Get(EnvironmentSchema schema, string? table = null, string? column = null, string? path = null) =>
        new(1, SourceUrl, hash, entries.Where(e =>
            (table is null || e.Table.Equals(table, StringComparison.OrdinalIgnoreCase)) &&
            (column is null || e.Column.Equals(column, StringComparison.OrdinalIgnoreCase)) &&
            (path is null || (e.Path ?? "") == path) &&
            schema.Tables.TryGetValue(e.Table, out var known) && known.Columns.Any(c => c.Name.Equals(e.Column, StringComparison.OrdinalIgnoreCase)))
            .ToArray());

    public bool WindowsCaseReview(string table, string column) => entries.Any(e =>
        e.Table == table && e.Column == column && string.IsNullOrEmpty(e.Path) && e.DiagnosticEligibility == "windows-path-case-review");
}
