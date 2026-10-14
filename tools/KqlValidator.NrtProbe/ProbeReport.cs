using System.Text.Json;
using KqlValidator.Validation;

namespace KqlValidator.NrtProbe;

public sealed record ProbeObservation(string FixtureId, string QueryHash, string Phase, int Repeat,
    DateTimeOffset ObservedAt, string Status, bool? StreamingSupported, bool? CustomFrequencySupported, int? HttpStatus);
public sealed record ProbeBatch(int Version, string RunId, string GroupId, string ManifestHash, string ParserVersion,
    string ModuleVersion, string TenantHash, IReadOnlyList<ProbeObservation> Observations);
public sealed record ProbeEvidence(string Kind, string Reference, DateTimeOffset VerifiedAt, string TenantHash);
public sealed record ProbeFinding(NrtFeatureUse Feature, bool Documented, string Status, int Observations, int Sessions,
    bool? StreamingSupported, IReadOnlyList<ProbeEvidence> Evidence, IReadOnlyList<string> FixtureIds);

public static class ProbeReport
{
    public static string ManifestHash(ProbeManifest manifest) => ProbeInventory.Hash(JsonSerializer.Serialize(manifest, DefenderNrtFeatures.JsonOptions));

    public static bool MatchesInventory(ProbeManifest recorded, ProbeManifest current)
    {
        if (recorded.Version != current.Version || recorded.ParserVersion != current.ParserVersion ||
            recorded.Fixtures.Count != current.Fixtures.Count || recorded.Fixtures.Select(f => f.Id).Distinct().Count() != recorded.Fixtures.Count)
            return false;
        var fixtures = current.Fixtures.ToDictionary(f => f.Id, StringComparer.Ordinal);
        // Operand classification can improve after a probe. Keep the recorded manifest hash
        // while requiring the same validated queries, controls, features, and argument types.
        return recorded.Fixtures.All(f => fixtures.TryGetValue(f.Id, out var expected) &&
            f.Query == expected.Query && f.QueryHash == expected.QueryHash && f.ExpectedStreaming == expected.ExpectedStreaming &&
            f.Feature?.Kind == expected.Feature?.Kind && f.Feature?.Name == expected.Feature?.Name &&
            (f.Feature is null || f.Feature.ArgumentTypes.SequenceEqual(expected.Feature!.ArgumentTypes)));
    }

    public static bool Healthy(ProbeBatch batch, ProbeManifest manifest)
    {
        if (batch.Version != 1 || batch.ManifestHash != ManifestHash(manifest) || batch.ParserVersion != manifest.ParserVersion ||
            !Guid.TryParse(batch.RunId, out _) || batch.ModuleVersion != "1.0.23" ||
            batch.TenantHash.Length != 64 || !batch.TenantHash.All(Uri.IsHexDigit)) return false;
        foreach (var phase in new[] { "before", "after" })
            foreach (var control in manifest.Fixtures.Where(f => f.ExpectedStreaming.HasValue))
            {
                var records = batch.Observations.Where(o => o.FixtureId == control.Id && o.Phase == phase).ToArray();
                if (records.Length != 1 || !Valid(records[0], control) || records[0].StreamingSupported != control.ExpectedStreaming) return false;
            }
        var before = batch.Observations.Where(o => o.Phase == "before").Max(o => o.ObservedAt);
        var after = batch.Observations.Where(o => o.Phase == "after").Min(o => o.ObservedAt);
        return before <= after && batch.Observations.Where(o => o.Phase == "candidate").All(o => o.ObservedAt >= before && o.ObservedAt <= after);
    }

    public static IReadOnlyList<ProbeFinding> Build(ProbeManifest manifest, IReadOnlyList<ProbeBatch> batches, bool byFixture = false)
    {
        var fixtures = manifest.Fixtures.ToDictionary(f => f.Id, StringComparer.Ordinal);
        // A duplicated file or re-exported batch cannot supply additional observations.
        var records = batches.Where(b => Healthy(b, manifest)).DistinctBy(b => (b.RunId, b.GroupId))
            .SelectMany(b => b.Observations.Where(o => o.Phase == "candidate")
                .Select(o => (Batch: b, Observation: o)))
            .Where(x => fixtures.TryGetValue(x.Observation.FixtureId, out var f) && f.Feature is not null && Valid(x.Observation, f))
            .DistinctBy(x => (x.Batch.RunId, x.Observation.FixtureId, x.Observation.Repeat)).ToArray();
        return manifest.Fixtures.Where(f => f.Feature is not null).GroupBy(f => byFixture ? f.Id : f.Feature!.Key).Select(group =>
        {
            var ids = group.Select(f => f.Id).ToHashSet(StringComparer.Ordinal);
            var matching = records.Where(x => ids.Contains(x.Observation.FixtureId)).ToArray();
            var values = matching.Select(x => x.Observation.StreamingSupported!.Value).Distinct().ToArray();
            var sessions = matching.Select(x => x.Batch.RunId).Distinct().Count();
            // Require two repeats in each of two independent sessions for every spelling/fixture sharing this key.
            var covered = group.All(f => matching.Where(x => x.Observation.FixtureId == f.Id)
                .GroupBy(x => x.Batch.RunId).Count(g => g.Select(x => x.Observation.Repeat).Distinct().Count() >= 2) >= 2);
            var status = values.Length > 1 ? "conflicting" : !covered ? "inconclusive" : values[0] ? "supported" : "unsupported";
            var evidence = matching.Select(x => new ProbeEvidence("endpoint",
                $"evidence/{x.Batch.RunId}/batch-{x.Batch.GroupId}.json#{x.Observation.FixtureId}/{x.Observation.Repeat}", x.Observation.ObservedAt, x.Batch.TenantHash)).ToArray();
            var feature = group.First().Feature!;
            return new ProbeFinding(feature, DefenderNrtFeatures.Documented(feature.Kind, feature.Name), status,
                matching.Length, sessions, status is "supported" or "unsupported" ? values[0] : null, evidence, group.Select(f => f.Id).ToArray());
        }).OrderBy(f => byFixture ? f.FixtureIds[0] : f.Feature.Key, StringComparer.Ordinal).ToArray();
    }

    public static NrtFeatureSnapshot Merge(NrtFeatureSnapshot baseline, IReadOnlyList<ProbeFinding> findings)
    {
        var entries = baseline.Overrides.ToDictionary(e => DefenderNrtFeatures.Key(e.Kind, e.Name, e.Shape, e.ArgumentTypes));
        foreach (var finding in findings.Where(f => f.StreamingSupported.HasValue && !f.Feature.Shape.Contains("expression", StringComparison.Ordinal)))
        {
            var feature = finding.Feature;
            entries[feature.Key] = new(feature.Kind, feature.Name, feature.Shape, feature.ArgumentTypes,
                finding.StreamingSupported!.Value);
        }
        return new(1, DefenderNrtFeatures.Endpoint, entries.Values.OrderBy(e => DefenderNrtFeatures.Key(e.Kind, e.Name, e.Shape, e.ArgumentTypes), StringComparer.Ordinal).ToArray());
    }

    private static bool Valid(ProbeObservation observation, ProbeFixture fixture) => observation.QueryHash == fixture.QueryHash &&
        observation.Repeat > 0 && observation.Status == "ok" && observation.HttpStatus == 200 && observation.StreamingSupported.HasValue;
}
