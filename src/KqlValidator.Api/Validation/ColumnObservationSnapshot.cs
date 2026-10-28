using System.Text.Json;
using System.Text.RegularExpressions;

#if SCHEMA_SYNC
namespace KqlValidator.SchemaSync;
#else
namespace KqlValidator.Validation;
#endif

public sealed record ColumnObservationSource(string Id, string Name, string Url, string? Dataset = null);
public sealed record ColumnObservationEntry(string Id, string Table, string Column, string Kind, string Title,
    string Text, IReadOnlyList<string> SourceIds, string? Path = null, string? Guidance = null,
    string? Query = null, string? QueryLanguage = null, string? DiagnosticEligibility = null);
public sealed record ColumnObservationSnapshot(int Version, IReadOnlyList<ColumnObservationSource> Sources,
    IReadOnlyList<ColumnObservationEntry> Observations);

public static partial class ColumnObservationSnapshotValidator
{
    public static ColumnObservationSnapshot Parse(string json)
    {
        try
        {
            var value = JsonSerializer.Deserialize<ColumnObservationSnapshot>(json, new JsonSerializerOptions(JsonSerializerDefaults.Web))
                ?? throw new InvalidDataException("Empty column observations snapshot.");
            if (value.Version != 1 || value.Sources is null || value.Observations is null)
                throw new InvalidDataException("Unsupported column observations snapshot.");
            var sources = new HashSet<string>(StringComparer.Ordinal);
            foreach (var source in value.Sources)
                if (source is null || string.IsNullOrWhiteSpace(source.Id) || !sources.Add(source.Id) || string.IsNullOrWhiteSpace(source.Name) ||
                    !Uri.TryCreate(source.Url, UriKind.Absolute, out var uri) || uri.Scheme != "https")
                    throw new InvalidDataException("Sources require unique IDs, names, and HTTPS URLs.");
            var ids = new HashSet<string>(StringComparer.Ordinal);
            var targets = new HashSet<(string, string, string, string)>();
            foreach (var entry in value.Observations)
            {
                if (entry is null || entry.Id is null || !StableId().IsMatch(entry.Id) || !ids.Add(entry.Id) ||
                    entry.Table is null || !Identifier().IsMatch(entry.Table) || entry.Column is null || !Identifier().IsMatch(entry.Column) ||
                    entry.Kind is not ("value-case-variation" or "identifier-format-variation") ||
                    !targets.Add((entry.Table, entry.Column, entry.Path ?? "", entry.Kind)) ||
                    string.IsNullOrWhiteSpace(entry.Title) || string.IsNullOrWhiteSpace(entry.Text) ||
                    entry.SourceIds is null || entry.SourceIds.Count == 0 || entry.SourceIds.Distinct(StringComparer.Ordinal).Count() != entry.SourceIds.Count ||
                    entry.SourceIds.Any(id => !sources.Contains(id)) || entry.Path is { Length: > 0 } && !NestedPath().IsMatch(entry.Path) ||
                    entry.Query is not null && string.IsNullOrWhiteSpace(entry.Query) || entry.QueryLanguage is not (null or "kusto"))
                    throw new InvalidDataException("Invalid column observation or unresolved source reference.");
                if (entry.DiagnosticEligibility is not null && (entry.DiagnosticEligibility != "windows-path-case-review" ||
                    entry.Kind != "value-case-variation" || !string.IsNullOrEmpty(entry.Path) || string.IsNullOrWhiteSpace(entry.Guidance)))
                    throw new InvalidDataException("Unsupported diagnostic eligibility or missing reviewed guidance.");
            }
            return value;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or NullReferenceException)
        {
            throw new InvalidDataException("Malformed column observations snapshot.", e);
        }
    }

    [GeneratedRegex(@"^[a-z0-9]+(?:-[a-z0-9]+)*$", RegexOptions.CultureInvariant)]
    private static partial Regex StableId();
    [GeneratedRegex(@"^[A-Za-z_][A-Za-z0-9_]*$", RegexOptions.CultureInvariant)]
    private static partial Regex Identifier();
    [GeneratedRegex("^(?:[A-Za-z_][A-Za-z0-9_]*|\\[(?:[0-9]*|\"(?:[^\"\\\\]|\\\\.)*\")\\])(?:\\.[A-Za-z_][A-Za-z0-9_]*|\\[(?:[0-9]*|\"(?:[^\"\\\\]|\\\\.)*\")\\])*$", RegexOptions.CultureInvariant)]
    private static partial Regex NestedPath();
}
