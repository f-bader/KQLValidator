using System.Text.Json;
using KqlValidator.NrtProbe;
using KqlValidator.Validation;

namespace KqlValidator.NrtProbe;

internal static class ProbeProgram
{
    public static int Main(string[] args)
    {
        try
        {
            if (args is [var command, var manifestPath] && command is "prepare" or "prepare-follow-up")
            {
                var manifest = command == "prepare-follow-up" ? ProbeInventory.PrepareFollowUp() : ProbeInventory.Prepare();
                Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(manifestPath))!);
                File.WriteAllText(manifestPath, JsonSerializer.Serialize(manifest, DefenderNrtFeatures.JsonOptions));
                Console.WriteLine($"Prepared {manifest.Fixtures.Count} validated fixtures with parser {manifest.ParserVersion}.");
            }
            else if (args.Length >= 3 && args[0] is "report" or "report-follow-up")
            {
                var followUp = args[0] == "report-follow-up";
                var inventory = followUp ? ProbeInventory.PrepareFollowUp() : ProbeInventory.Prepare();
                var manifests = args.Skip(2).Select(directory =>
                    JsonSerializer.Deserialize<ProbeManifest>(File.ReadAllText(Path.Combine(directory, "manifest.json")), DefenderNrtFeatures.JsonOptions)
                    ?? throw new InvalidDataException("A probe manifest is empty.")).ToArray();
                var manifest = manifests[0];
                if (manifests.Any(m => !ProbeReport.MatchesInventory(m, inventory) || ProbeReport.ManifestHash(m) != ProbeReport.ManifestHash(manifest)))
                    throw new InvalidDataException("Probe manifests differ or contain queries outside the current inventory.");
                var batches = args.Skip(2).SelectMany(directory => Directory.EnumerateFiles(directory, "batch-*.json"))
                    .Select(path => JsonSerializer.Deserialize<ProbeBatch>(File.ReadAllText(path), DefenderNrtFeatures.JsonOptions)
                        ?? throw new InvalidDataException("A probe batch is empty.")).ToArray();
                var findings = ProbeReport.Build(manifest, batches, byFixture: followUp);
                if (followUp)
                    findings = findings.Select(f => f with { Feature = inventory.Fixtures.Single(fixture => fixture.Id == f.FixtureIds[0]).Feature! }).ToArray();
                var baseline = JsonSerializer.Deserialize<NrtFeatureSnapshot>(
                    File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Schemas", "defender-nrt-overrides.json")), DefenderNrtFeatures.JsonOptions)!;
                Directory.CreateDirectory(args[1]);
                foreach (var batch in batches.Where(b => ProbeReport.Healthy(b, manifest)).DistinctBy(b => (b.RunId, b.GroupId)))
                {
                    if (!int.TryParse(batch.GroupId, out var group) || group < 0)
                        throw new InvalidDataException("A probe batch has an invalid group identifier.");
                    var directory = Path.Combine(args[1], "evidence", batch.RunId);
                    Directory.CreateDirectory(directory);
                    File.WriteAllText(Path.Combine(directory, $"batch-{batch.GroupId}.json"), JsonSerializer.Serialize(batch, DefenderNrtFeatures.JsonOptions));
                }
                File.WriteAllText(Path.Combine(args[1], "report.json"), JsonSerializer.Serialize(new
                {
                    endpoint = DefenderNrtFeatures.Endpoint,
                    parserVersion = manifest.ParserVersion,
                    rejectedBatches = batches.Count(b => !ProbeReport.Healthy(b, manifest)),
                    findings,
                }, DefenderNrtFeatures.JsonOptions));
                if (followUp)
                {
                    var catalog = new DefenderNrtFeatures();
                    File.WriteAllText(Path.Combine(args[1], "variant-review.json"), JsonSerializer.Serialize(new
                    {
                        requiresManualReview = true,
                        variants = findings.Select(f => new
                        {
                            fixtureId = f.FixtureIds[0],
                            query = manifest.Fixtures.Single(fixture => fixture.Id == f.FixtureIds[0]).Query,
                            feature = f.Feature,
                            catalogSupported = catalog.Supports(f.Feature),
                            streamingSupported = f.StreamingSupported,
                            disagreesWithCatalog = f.StreamingSupported.HasValue && f.StreamingSupported.Value != catalog.Supports(f.Feature),
                            status = f.Status,
                            observations = f.Observations,
                            sessions = f.Sessions,
                        }),
                    }, DefenderNrtFeatures.JsonOptions));
                    Console.WriteLine($"Wrote follow-up review to {args[1]}. Conclusive variants: {findings.Count(f => f.StreamingSupported.HasValue)}. Review context and operand details before updating the catalog.");
                    return 0;
                }
                var snapshotPath = Path.Combine(args[1], "defender-nrt-overrides.candidate.json");
                File.WriteAllText(snapshotPath, JsonSerializer.Serialize(ProbeReport.Merge(baseline, findings), DefenderNrtFeatures.JsonOptions));
                _ = new DefenderNrtFeatures(snapshotPath);
                Console.WriteLine($"Wrote report and candidate snapshot to {args[1]}. Verified forms: {findings.Count(f => f.StreamingSupported.HasValue)}.");
            }
            else
            {
                Console.Error.WriteLine("Usage: prepare|prepare-follow-up <manifest.json> | report|report-follow-up <output-directory> <run-directory> [<run-directory> ...]");
                return 2;
            }
            return 0;
        }
        catch (Exception exception) when (exception is InvalidDataException or JsonException or IOException)
        {
            Console.Error.WriteLine(exception.Message);
            return 1;
        }
    }
}
