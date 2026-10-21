using System.Text.Json;
using KqlValidator.Contracts;
using KqlValidator.NrtProbe;
using KqlValidator.Validation;
using Kusto.Language;

namespace KqlValidator.Tests;

public sealed class DefenderNrtProbeTests
{
    private static readonly Lazy<ProbeManifest> Inventory = new(ProbeInventory.Prepare);

    [Fact]
    public void Comparison_inventory_covers_documented_operators_and_bound_scalar_comparisons()
    {
        var manifest = Inventory.Value;
        string[] required = ["==", "!=", "=~", "!~", "contains", "!contains", "contains_cs", "!contains_cs",
            "endswith", "!endswith", "endswith_cs", "!endswith_cs", "has", "!has", "has_all", "has_any", "has_cs", "!has_cs",
            "hasprefix", "!hasprefix", "hasprefix_cs", "!hasprefix_cs", "hassuffix", "!hassuffix", "hassuffix_cs", "!hassuffix_cs",
            "in", "!in", "in~", "!in~", "matches regex", "startswith", "!startswith", "startswith_cs", "!startswith_cs",
            "<", "<=", ">", ">=", "between", "!between"];
        foreach (var name in required)
            Assert.Contains(manifest.Fixtures, f => f.Feature is { Kind: "operator" } && f.Feature.Name == name);
        foreach (var function in GlobalState.Default.Functions.Where(f => ProbeInventory.ComparisonFunction(f.Name)))
            Assert.Contains(manifest.Fixtures, f => f.Feature is { Kind: "function" } && f.Feature.Name == function.Name);
        foreach (var op in GlobalState.Default.Operators)
            Assert.True(ProbeInventory.ComparisonTokens().Any(t => t.Kind.ToString() == op.Name) || manifest.Exclusions.Any(e => e.Kind == "operator" && e.Name == op.Name), op.Name);
        Assert.Equal(manifest.Fixtures.Count, manifest.Fixtures.Select(f => f.Id).Distinct().Count());
        Assert.All(manifest.Fixtures, f => Assert.Equal(ProbeInventory.Hash(f.Query), f.QueryHash));
    }

    [Fact]
    public void Follow_up_inventory_validates_context_and_membership_variants()
    {
        var manifest = ProbeInventory.PrepareFollowUp();
        Assert.Equal(12, manifest.Fixtures.Count(f => f.Feature is not null));
        Assert.Equal(6, manifest.Fixtures.Count(f => f.ExpectedStreaming.HasValue));
        Assert.Equal(manifest.Fixtures.Count, manifest.Fixtures.Select(f => f.Id).Distinct().Count());
        Assert.Contains(manifest.Fixtures, f => f.Id == "follow-up-has-any-projection" && f.Query.Contains("extend __nrtprobe", StringComparison.Ordinal));
        Assert.Contains(manifest.Fixtures, f => f.Id == "follow-up-strcmp-predicate" && f.Query.Contains("where strcmp", StringComparison.Ordinal));
        Assert.Contains(manifest.Fixtures, f => f.Id == "follow-up-has-any-string-variable" && f.Feature is { Shape: "scalar-variable" } && f.Feature.ArgumentTypes.SequenceEqual(["string", "string"]));
        Assert.Contains(manifest.Fixtures, f => f.Id == "follow-up-has-any-mixed-list" && f.Feature is { Shape: "literal-variable-list" });
        Assert.Contains(manifest.Fixtures, f => f.Id == "follow-up-has-any-udf-parameter" && f.Feature is { Shape: "expression" });
        Assert.Contains(manifest.Fixtures, f => f.Id == "follow-up-has-any-empty-array" && f.Feature is { Shape: "dynamic-array" });
        Assert.All(manifest.Fixtures, f => Assert.Equal(ProbeInventory.Hash(f.Query), f.QueryHash));
    }

    [Fact]
    public void Recorded_manifests_allow_classification_changes_and_require_the_validated_queries()
    {
        var current = ProbeInventory.PrepareFollowUp();
        var recorded = current with
        {
            Fixtures = current.Fixtures.Select(f => f.Feature is { Shape: "literal-variable-list" }
                ? f with { Feature = f.Feature with { Shape = "expression-list" } } : f).ToArray(),
        };
        Assert.True(ProbeReport.MatchesInventory(recorded, current));
        Assert.NotEqual(ProbeReport.ManifestHash(recorded), ProbeReport.ManifestHash(current));
        var changed = recorded.Fixtures.ToArray();
        changed[0] = changed[0] with { Query = changed[0].Query.Replace("==", "!=", StringComparison.Ordinal) };
        changed[0] = changed[0] with { QueryHash = ProbeInventory.Hash(changed[0].Query) };
        Assert.False(ProbeReport.MatchesInventory(recorded with { Fixtures = changed }, current));
        changed = recorded.Fixtures.ToArray();
        changed[0] = changed[0] with { ExpectedStreaming = false };
        Assert.False(ProbeReport.MatchesInventory(recorded with { Fixtures = changed }, current));
        Assert.False(ProbeReport.MatchesInventory(recorded with { Fixtures = recorded.Fixtures.Append(recorded.Fixtures[0]).ToArray() }, current));
    }

    [Theory]
    [InlineData(KqlEnvironment.Xdr)]
    [InlineData(KqlEnvironment.Unified)]
    public void Validator_matches_all_follow_up_results(KqlEnvironment environment)
    {
        string[] supported = ["follow-up-has-any-computed-left", "follow-up-has-any-mixed-list",
            "follow-up-has-any-projection", "follow-up-has-any-string-variable", "follow-up-has-any-variable-list",
            "follow-up-in-tilde-projection"];
        var catalog = new DefenderNrtFeatures();
        var validator = Validator(catalog);
        foreach (var fixture in ProbeInventory.PrepareFollowUp().Fixtures.Where(f => f.Feature is not null))
        {
            var feature = fixture.Feature!;
            var allowed = supported.Contains(fixture.Id);
            Assert.Equal(allowed, catalog.Supports(feature));
            var result = validator.Validate(new(fixture.Query, environment, LintProfile.Detection,
                Target: KqlTarget.DefenderNrt), TestContext.Current.CancellationToken);
            Assert.Equal(!allowed, result.Diagnostics.Any(d => d.RuleId == "KQLN004" && d.Span.Start == feature.Start));
        }
    }

    [Theory]
    [InlineData("let term = tolower('TEST');", "term")]
    [InlineData("let term = 'test';", "term, FileName")]
    [InlineData("let term = 'test';", "term, tolower('EXAMPLE')")]
    [InlineData("let term = dynamic(['test']);", "term")]
    [InlineData("let term = tolower('TEST');", "term, 'example'")]
    public void Literal_variable_support_keeps_unverified_membership_operands_separate(string declaration, string operands)
    {
        var query = $"{declaration}\nDeviceProcessEvents | where DeviceName has_any ({operands})";
        var result = Validator().Validate(new(query, KqlEnvironment.Xdr, LintProfile.Detection,
            Target: KqlTarget.DefenderNrt), TestContext.Current.CancellationToken);
        Assert.Contains(result.Diagnostics, d => d.RuleId == "KQLN004" && d.Message.Contains("'has_any'", StringComparison.Ordinal));
    }

    [Fact]
    public void Follow_up_reports_preserve_different_outcomes_for_queries_sharing_a_key()
    {
        var full = ProbeInventory.PrepareFollowUp();
        var manifest = full with
        {
            Fixtures = full.Fixtures.Where(f => f.ExpectedStreaming.HasValue ||
                f.Id is "follow-up-has-any-projection" or "follow-up-has-any-computed-left").ToArray(),
        };
        var first = Batch(manifest, true);
        var second = Batch(manifest, true);
        ProbeBatch RejectComputedLeft(ProbeBatch batch) => batch with
        {
            Observations = batch.Observations.Select(o => o.FixtureId == "follow-up-has-any-computed-left"
                ? o with { StreamingSupported = false } : o).ToArray(),
        };
        ProbeBatch[] batches = [RejectComputedLeft(first), RejectComputedLeft(second)];
        var byFeature = Assert.Single(ProbeReport.Build(manifest, batches));
        Assert.Equal("conflicting", byFeature.Status);
        var byFixture = ProbeReport.Build(manifest, batches, byFixture: true);
        Assert.Equal(2, byFixture.Count);
        Assert.Contains(byFixture, f => f.FixtureIds.SequenceEqual(["follow-up-has-any-projection"]) && f.Status == "supported");
        Assert.Contains(byFixture, f => f.FixtureIds.SequenceEqual(["follow-up-has-any-computed-left"]) && f.Status == "unsupported");
        Assert.All(byFixture, f => Assert.Equal(2, f.Sessions));
    }

    [Theory]
    [InlineData(KqlEnvironment.Xdr)]
    [InlineData(KqlEnvironment.Unified)]
    public void Issue_50_literal_list_is_allowed(KqlEnvironment environment)
    {
        var result = Validator().Validate(new("DeviceProcessEvents\n| where DeviceName has_any (\"test\")", environment,
            LintProfile.Detection, Target: KqlTarget.DefenderNrt), TestContext.Current.CancellationToken);
        Assert.True(result.Valid, string.Join("; ", result.Diagnostics.Select(d => d.Message)));
        Assert.DoesNotContain(result.Diagnostics, d => d.RuleId == "KQLN004");
        var rule = new LintRuleCatalog().Get("KQLN004");
        Assert.Equal("community", rule.SourceKind);
        Assert.Equal(DefenderNrtFeatures.DocumentationUrl, rule.DocumentationUrl);
    }

    [Theory]
    [InlineData("DeviceName has_any (dynamic([\"test\"]))")]
    [InlineData("DeviceName hasprefix_cs \"test\"")]
    [InlineData("DeviceName !hassuffix_cs \"test\"")]
    [InlineData("DeviceName in (dynamic([\"test\"]))")]
    [InlineData("DeviceName !in (FileName)")]
    [InlineData("ReportId between (1 .. 100)")]
    public void Verified_rejected_forms_remain_outside_support_catalog(string predicate)
    {
        var result = Validator().Validate(new($"DeviceProcessEvents | where {predicate}", KqlEnvironment.Xdr,
            LintProfile.Detection, Target: KqlTarget.DefenderNrt), TestContext.Current.CancellationToken);
        Assert.Contains(result.Diagnostics, d => d.RuleId == "KQLN004" && d.Message.Contains("support catalog", StringComparison.Ordinal));
        Assert.DoesNotContain(result.Diagnostics, d => d.Message.Contains("has_any()", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("has_all")]
    [InlineData("in~")]
    [InlineData("!in~")]
    public void Verified_literal_list_additions_are_allowed(string operation)
    {
        var result = Validator().Validate(new($"DeviceProcessEvents | where DeviceName {operation} ('test', 'example')",
            KqlEnvironment.Xdr, LintProfile.Detection, Target: KqlTarget.DefenderNrt), TestContext.Current.CancellationToken);
        Assert.True(result.Valid, string.Join("; ", result.Diagnostics.Select(d => d.Message)));
        Assert.DoesNotContain(result.Diagnostics, d => d.RuleId == "KQLN004");
    }

    [Theory]
    [InlineData(KqlTarget.DefenderNrt, false)]
    [InlineData(KqlTarget.DefenderScheduled, true)]
    public void Ipv4_performance_advice_respects_target_support(KqlTarget target, bool suggested)
    {
        var result = Validator().Validate(new("DeviceNetworkEvents | where RemoteIP has '192.0.2.1'",
            KqlEnvironment.Xdr, LintProfile.Detection, Target: target, Lint: new(EnableRules: ["KQLP006"])), TestContext.Current.CancellationToken);
        Assert.Equal(suggested, result.Diagnostics.Any(d => d.RuleId == "KQLP006"));
    }

    [Fact]
    public void Parsed_features_preserve_spans_and_ignore_identifier_and_literal_text()
    {
        const string query = "DeviceProcessEvents | extend has_any = DeviceName, in_string = 'has_all (abc)' | where has_any contains in_string";
        var result = Validator().Validate(new(query, KqlEnvironment.Xdr, LintProfile.Detection, Target: KqlTarget.DefenderNrt), TestContext.Current.CancellationToken);
        Assert.DoesNotContain(result.Diagnostics, d => d.RuleId == "KQLN004");
        const string invalid = "DeviceProcessEvents | where DeviceName !in~ (dynamic(['test']))";
        var diagnostic = Assert.Single(Validator().Validate(new(invalid, KqlEnvironment.Xdr, LintProfile.Detection, Target: KqlTarget.DefenderNrt), TestContext.Current.CancellationToken)
            .Diagnostics, d => d.RuleId == "KQLN004");
        Assert.Equal(invalid.IndexOf("!in~", StringComparison.Ordinal), diagnostic.Span.Start);
        Assert.Equal(4, diagnostic.Span.Length);
    }

    [Fact]
    public void Root_search_keeps_its_tabular_restriction()
    {
        var result = Validator().Validate(new("search in (DeviceProcessEvents) 'test'", KqlEnvironment.Xdr,
            LintProfile.Detection, Target: KqlTarget.DefenderNrt), TestContext.Current.CancellationToken);
        Assert.Contains(result.Diagnostics, d => d.RuleId == "KQLN004" && d.Message.Contains("'search'", StringComparison.Ordinal));
    }

    [Fact]
    public void Override_snapshot_requires_explicit_support_flag()
    {
        var use = Inventory.Value.Fixtures.First(f => f.Id == "issue-50").Feature!;
        var snapshot = new NrtFeatureSnapshot(1, DefenderNrtFeatures.Endpoint,
            [new(use.Kind, use.Name, use.Shape, use.ArgumentTypes, true)]);
        WithSnapshot(snapshot, _ => { });
        var path = Path.Combine(Path.GetTempPath(), $"nrt-invalid-{Guid.NewGuid():N}.json");
        try
        {
            var json = JsonSerializer.SerializeToNode(snapshot, DefenderNrtFeatures.JsonOptions)!;
            json["overrides"]![0]!.AsObject().Remove("supported");
            File.WriteAllText(path, json.ToJsonString(DefenderNrtFeatures.JsonOptions));
            Assert.Throws<JsonException>(() => new DefenderNrtFeatures(path));
        }
        finally { File.Delete(path); }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Scoped_catalog_entries_override_baseline_in_both_directions(bool support)
    {
        var feature = Inventory.Value.Fixtures.First(f => f.Feature?.Name == (support ? "has_all" : "contains") && f.Feature.Shape == (support ? "literal-list" : "literal"));
        WithSnapshot(new(1, DefenderNrtFeatures.Endpoint, [new(feature.Feature!.Kind, feature.Feature.Name, feature.Feature.Shape,
            feature.Feature.ArgumentTypes, support)]), catalog =>
        {
            var result = Validator(catalog).Validate(new(feature.Query, KqlEnvironment.Xdr, LintProfile.Detection, Target: KqlTarget.DefenderNrt), TestContext.Current.CancellationToken);
            Assert.Equal(!support, result.Diagnostics.Any(d => d.RuleId == "KQLN004"));
        });
    }

    [Theory]
    [InlineData("scalar-variable")]
    [InlineData("column")]
    public void Verified_regex_operand_forms_override_literal_requirement(string shape)
    {
        var fixture = Inventory.Value.Fixtures.First(f => f.Feature is { Name: "matches regex" } && f.Feature.Shape == shape);
        var use = fixture.Feature!;
        WithSnapshot(new(1, DefenderNrtFeatures.Endpoint, [new(use.Kind, use.Name, use.Shape, use.ArgumentTypes, true)]), catalog =>
        {
            var result = Validator(catalog).Validate(new(fixture.Query, KqlEnvironment.Xdr, LintProfile.Detection,
                Target: KqlTarget.DefenderNrt), TestContext.Current.CancellationToken);
            Assert.DoesNotContain(result.Diagnostics, d => d.RuleId is "KQLN004" or "KQLN005");
            WithSnapshot(new(1, DefenderNrtFeatures.Endpoint, []), baseline =>
            {
                var unobserved = Validator(baseline).Validate(new(fixture.Query, KqlEnvironment.Xdr, LintProfile.Detection,
                    Target: KqlTarget.DefenderNrt), TestContext.Current.CancellationToken);
                Assert.Contains(unobserved.Diagnostics, d => d.RuleId == "KQLN005");
            });
        });
    }

    [Fact]
    public void Observed_regex_literal_support_preserves_escaping_validation()
    {
        var fixture = Inventory.Value.Fixtures.First(f => f.Feature is { Name: "matches regex", Shape: "literal" });
        var use = fixture.Feature!;
        WithSnapshot(new(1, DefenderNrtFeatures.Endpoint, [new(use.Kind, use.Name, use.Shape, use.ArgumentTypes, true)]), catalog =>
        {
            var result = Validator(catalog).Validate(new("DeviceProcessEvents | where DeviceName matches regex \"\\AProcessCreated\"",
                KqlEnvironment.Xdr, LintProfile.Detection, Target: KqlTarget.DefenderNrt), TestContext.Current.CancellationToken);
            Assert.Contains(result.Diagnostics, d => d.RuleId == "KQLN005");
        });
    }

    [Fact]
    public void Project_overrides_preserve_transformation_and_sentinel_constraints()
    {
        var transformation = new AzureMonitorTransformationValidationService(new GlobalStateFactory(), new LintRuleCatalog())
            .Validate(new("source | where DeviceName has_any ('test') | project TimeGenerated", [new("DeviceName", "string"), new("TimeGenerated", "datetime")]), TestContext.Current.CancellationToken);
        Assert.Contains(transformation.Diagnostics, d => d.RuleId == "KQLT003");
        var sentinel = Validator().Validate(new("SigninLogs | where UserPrincipalName has_all ('test')", KqlEnvironment.Sentinel,
            LintProfile.Detection, Target: KqlTarget.SentinelNrt), TestContext.Current.CancellationToken);
        Assert.DoesNotContain(sentinel.Diagnostics, d => d.RuleId == "KQLN004");
    }

    [Fact]
    public void Two_independent_sessions_and_two_repeats_are_required_for_promotion()
    {
        var manifest = SmallManifest();
        var first = Batch(manifest, true);
        Assert.All(ProbeReport.Build(manifest, [first, first]), f => Assert.Equal("inconclusive", f.Status));
        var second = Batch(manifest, true);
        var finding = Assert.Single(ProbeReport.Build(manifest, [first, second]));
        Assert.Equal("supported", finding.Status);
        Assert.Equal(2, finding.Sessions);
        Assert.True(finding.StreamingSupported);
    }

    [Theory]
    [InlineData("failed-control")]
    [InlineData("missing-control")]
    [InlineData("stale-manifest")]
    [InlineData("bad-query-hash")]
    [InlineData("invalid-response")]
    [InlineData("one-repeat")]
    public void Inconclusive_batches_cannot_override_the_baseline(string fault)
    {
        var manifest = SmallManifest();
        var good = Batch(manifest, false);
        var bad = Batch(manifest, false);
        var records = bad.Observations.ToArray();
        bad = fault switch
        {
            "failed-control" => bad with { Observations = records.Select(o => o.FixtureId == "control-negative" ? o with { StreamingSupported = true } : o).ToArray() },
            "missing-control" => bad with { Observations = records.Where(o => o.Phase != "after").ToArray() },
            "stale-manifest" => bad with { ManifestHash = "stale" },
            "bad-query-hash" => bad with { Observations = records.Select(o => o.Phase == "candidate" ? o with { QueryHash = "different" } : o).ToArray() },
            "invalid-response" => bad with { Observations = records.Select(o => o.Phase == "candidate" ? o with { Status = "invalid-response", StreamingSupported = null } : o).ToArray() },
            "one-repeat" => bad with { Observations = records.Where(o => o.Phase != "candidate" || o.Repeat == 1).ToArray() },
            _ => throw new InvalidOperationException(),
        };
        var finding = Assert.Single(ProbeReport.Build(manifest, [good, bad]));
        Assert.Equal("inconclusive", finding.Status);
        Assert.Null(finding.StreamingSupported);
        var baseline = new NrtFeatureSnapshot(1, DefenderNrtFeatures.Endpoint, []);
        Assert.Empty(ProbeReport.Merge(baseline, [finding]).Overrides);
    }

    [Fact]
    public void Conflicting_tenant_or_session_observations_remain_inconclusive()
    {
        var manifest = SmallManifest();
        var finding = Assert.Single(ProbeReport.Build(manifest, [Batch(manifest, true), Batch(manifest, false)]));
        Assert.Equal("conflicting", finding.Status);
        Assert.Null(finding.StreamingSupported);
    }

    [Fact]
    public void Consistent_false_responses_produce_scoped_exclusions()
    {
        var manifest = SmallManifest();
        var finding = Assert.Single(ProbeReport.Build(manifest, [Batch(manifest, false), Batch(manifest, false)]));
        Assert.Equal("unsupported", finding.Status);
        var entry = Assert.Single(ProbeReport.Merge(new(1, DefenderNrtFeatures.Endpoint, []), [finding]).Overrides);
        Assert.False(entry.Supported);
        Assert.Equal("literal-list", entry.Shape);
        Assert.All(finding.Evidence, e => Assert.Equal("endpoint", e.Kind));
        Assert.False(JsonSerializer.SerializeToElement(entry, DefenderNrtFeatures.JsonOptions).TryGetProperty("evidence", out _));
    }

    [Fact]
    public void Bundled_snapshot_contains_every_probe_form_without_evidence()
    {
        var snapshot = JsonSerializer.Deserialize<NrtFeatureSnapshot>(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Schemas", "defender-nrt-overrides.json")), DefenderNrtFeatures.JsonOptions)!;
        var shipped = snapshot.Overrides.ToDictionary(e => DefenderNrtFeatures.Key(e.Kind, e.Name, e.Shape, e.ArgumentTypes));
        var groups = Inventory.Value.Fixtures.Where(f => f.Feature is not null).GroupBy(f => f.Feature!.Key).ToArray();
        Assert.Equal(207, shipped.Count);
        Assert.Equal(205, groups.Length);
        Assert.All(groups, group => Assert.True(shipped.ContainsKey(group.Key), group.Key));
        var json = JsonSerializer.SerializeToElement(snapshot, DefenderNrtFeatures.JsonOptions);
        Assert.All(json.GetProperty("overrides").EnumerateArray(), entry => Assert.False(entry.TryGetProperty("evidence", out _)));
    }

    [Theory]
    [InlineData(KqlEnvironment.Xdr)]
    [InlineData(KqlEnvironment.Unified)]
    public void Validator_feature_decisions_match_every_recorded_query_form(KqlEnvironment environment)
    {
        var catalog = new DefenderNrtFeatures();
        var validator = Validator(catalog);
        foreach (var fixture in Inventory.Value.Fixtures.Where(f => f.Feature is not null))
        {
            var feature = fixture.Feature!;
            var observed = catalog.ObservedSupport(feature);
            Assert.NotNull(observed);
            var result = validator.Validate(new(fixture.Query, environment, LintProfile.Detection,
                Target: KqlTarget.DefenderNrt), TestContext.Current.CancellationToken);
            var rejected = result.Diagnostics.Any(d => d.RuleId == "KQLN004" && d.Span.Start == feature.Start);
            Assert.Equal(!observed!.Value, rejected);
        }
    }

    private static ProbeManifest SmallManifest() => Inventory.Value with
    {
        Fixtures = Inventory.Value.Fixtures.Where(f => f.ExpectedStreaming.HasValue || f.Id == "issue-50").ToArray(),
    };

    private static ProbeBatch Batch(ProbeManifest manifest, bool supported)
    {
        var time = DateTimeOffset.UtcNow;
        var observations = new List<ProbeObservation>();
        foreach (var phase in new[] { "before", "candidate", "after" })
            foreach (var fixture in manifest.Fixtures.Where(f => phase == "candidate" ? f.Feature is not null : f.ExpectedStreaming.HasValue))
                for (var repeat = 1; repeat <= (phase == "candidate" ? 2 : 1); repeat++)
                    observations.Add(new(fixture.Id, fixture.QueryHash, phase, repeat, time = time.AddSeconds(1), "ok",
                        fixture.ExpectedStreaming ?? supported, true, 200));
        return new(1, Guid.NewGuid().ToString(), "0001", ProbeReport.ManifestHash(manifest), manifest.ParserVersion,
            "1.0.23", new string('a', 64), observations);
    }

    private static void WithSnapshot(NrtFeatureSnapshot snapshot, Action<DefenderNrtFeatures> action)
    {
        var path = Path.Combine(Path.GetTempPath(), $"nrt-{Guid.NewGuid():N}.json");
        try
        {
            File.WriteAllText(path, JsonSerializer.Serialize(snapshot, DefenderNrtFeatures.JsonOptions));
            action(new(path));
        }
        finally { File.Delete(path); }
    }

    private static KqlValidationService Validator(DefenderNrtFeatures? features = null)
    {
        var catalog = TestSchemaCatalog.Bundled;
        var rules = new LintRuleCatalog();
        return new(catalog, new GlobalStateFactory(), new RequestValidator(catalog, rules), new KqlLinter(catalog, rules),
            new DefenderNrtValidator(rules, features), rules);
    }
}
