using KqlValidator.Contracts;
using KqlValidator.SchemaSync;
using KqlValidator.Validation;

namespace KqlValidator.Tests;

public sealed class ValidationTests
{
    private readonly KqlValidationService validator;
    private readonly LintRuleCatalog lintRules;

    public ValidationTests()
    {
        var catalog = new SchemaCatalog();
        lintRules = new LintRuleCatalog();
        validator = new KqlValidationService(
            catalog,
            new GlobalStateFactory(),
            new RequestValidator(catalog, lintRules),
            new KqlLinter(catalog, lintRules),
            new DefenderNrtValidator(lintRules),
            lintRules);
    }

    [Fact]
    public void Valid_xdr_query_reports_shape_and_references()
    {
        var result = Validate("DeviceProcessEvents | where Timestamp > ago(1h) | project Timestamp, DeviceId, FileName");

        Assert.True(result.Valid, Messages(result));
        Assert.Contains("DeviceProcessEvents", result.ReferencedTables);
        Assert.Contains(result.OutputColumns, x => x.Name == "FileName" && x.Type == "string");
    }

    [Fact]
    public void Official_license_gated_xdr_tables_are_available_offline()
    {
        var expected = new Dictionary<string, (string Column, string Type)>
        {
            ["DeviceTvmBrowserExtensions"] = ("InstallationTime", "datetime"),
            ["DeviceTvmBrowserExtensionsKB"] = ("ExtensionVersion", "dynamic"),
            ["DeviceTvmCertificateInfo"] = ("IssuedTo", "dynamic"),
            ["DeviceTvmHardwareFirmware"] = ("AdditionalFields", "dynamic"),
            ["DeviceTvmInfoGathering"] = ("LastSeenTime", "datetime"),
            ["DeviceTvmInfoGatheringKB"] = ("Categories", "dynamic"),
            ["DeviceTvmSecureConfigurationAssessment"] = ("Context", "dynamic"),
            ["DeviceTvmSecureConfigurationAssessmentKB"] = ("ConfigurationBenchmarks", "dynamic"),
            ["DeviceTvmSoftwareEvidenceBeta"] = ("DiskPaths", "dynamic"),
            ["DeviceTvmSoftwareInventory"] = ("EndOfSupportDate", "datetime"),
            ["DeviceTvmSoftwareVulnerabilities"] = ("CveTags", "dynamic"),
            ["DeviceTvmSoftwareVulnerabilitiesKB"] = ("IsExploitAvailable", "bool"),
        };

        foreach (var environment in new[] { KqlEnvironment.Xdr, KqlEnvironment.Unified })
        {
            foreach (var (table, expectedColumn) in expected)
            {
                var result = Validate($"{table} | project {expectedColumn.Column}", environment);

                Assert.True(result.Valid, $"{environment}/{table}: {Messages(result)}");
                Assert.Contains(result.OutputColumns, column => column.Name == expectedColumn.Column && column.Type == expectedColumn.Type);
            }
        }
    }

    [Theory]
    [InlineData(KqlEnvironment.Xdr)]
    [InlineData(KqlEnvironment.Unified)]
    public void Newly_discovered_official_xdr_table_is_available_offline(KqlEnvironment environment)
    {
        var result = Validate("AADSignInEventsBeta | project Timestamp, AccountUpn", environment);

        Assert.True(result.Valid, Messages(result));
        Assert.Contains(result.OutputColumns, column => column.Name == "AccountUpn" && column.Type == "string");
    }

    [Fact]
    public void Semantic_error_invalidates_query()
    {
        var result = Validate("DeviceEvents | project DoesNotExist");

        Assert.False(result.Valid);
        Assert.Contains(result.Diagnostics, x => x.Severity == DiagnosticSeverity.Error);
    }

    [Fact]
    public void Assigned_ip_addresses_has_documented_output()
    {
        var result = Validate("AssignedIPAddresses('device-id')");

        Assert.True(result.Valid, Messages(result));
        Assert.Contains(result.OutputColumns, x => x.Name == "ConnectedNetworks" && x.Type == "dynamic");
    }

    [Theory]
    [InlineData(KqlEnvironment.Xdr, "FileProfile(SHA1)")]
    [InlineData(KqlEnvironment.Xdr, "FileProfile(SHA1, 1000)")]
    [InlineData(KqlEnvironment.Unified, "FileProfile(SHA1)")]
    [InlineData(KqlEnvironment.Unified, "FileProfile(SHA1, 1000)")]
    public void File_profile_invoke_preserves_detection_row_scope(KqlEnvironment environment, string invocation)
    {
        var result = Validate(
            $"DeviceFileEvents | where Timestamp > ago(1h) | invoke {invocation} | project Timestamp, ReportId, DeviceId, SHA1, ProfileAvailability",
            environment,
            LintProfile.Detection,
            target: KqlTarget.DefenderScheduled);

        Assert.True(result.Valid, Messages(result));
        Assert.Contains(result.OutputColumns, column => column.Name == "Timestamp" && column.Type == "datetime");
        Assert.Contains(result.OutputColumns, column => column.Name == "ProfileAvailability" && column.Type == "string");
    }

    [Fact]
    public void File_profile_supports_documented_default_arguments_and_live_output_schema()
    {
        var result = Validate("DeviceFileEvents | project SHA1 | invoke FileProfile()", KqlEnvironment.Xdr);
        var expected = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SHA1"] = "string",
            ["SHA256"] = "string",
            ["MD5"] = "string",
            ["FileSize"] = "long",
            ["GlobalPrevalence"] = "long",
            ["GlobalFirstSeen"] = "datetime",
            ["GlobalLastSeen"] = "datetime",
            ["Signer"] = "string",
            ["Issuer"] = "string",
            ["SignerHash"] = "string",
            ["IsCertificateValid"] = "bool",
            ["IsRootSignerMicrosoft"] = "bool",
            ["SignatureState"] = "string",
            ["IsExecutable"] = "bool",
            ["ThreatName"] = "string",
            ["Publisher"] = "string",
            ["SoftwareName"] = "string",
            ["ProfileAvailability"] = "string",
        };

        Assert.True(result.Valid, Messages(result));
        foreach (var (name, type) in expected)
            Assert.Contains(result.OutputColumns, column => column.Name == name && column.Type == type);
    }

    [Theory]
    [InlineData(KqlEnvironment.Xdr)]
    [InlineData(KqlEnvironment.Unified)]
    public void File_profile_accepts_renamed_string_source_column(KqlEnvironment environment)
    {
        var result = Validate(
            "DeviceImageLoadEvents | where Timestamp > ago(1h) | summarize by LoadedDLLSHA1 = SHA1 | invoke FileProfile(LoadedDLLSHA1, 1000) | project LoadedDLLSHA1, ProfileAvailability",
            environment);

        Assert.True(result.Valid, Messages(result));
        Assert.Contains(result.OutputColumns, column => column.Name == "LoadedDLLSHA1" && column.Type == "string");
    }

    [Theory]
    [InlineData("DeviceEvents | invoke FileProfile(DoesNotExist, 1)")]
    [InlineData("DeviceEvents | extend NumericValue = 1 | invoke FileProfile(NumericValue, 1)")]
    public void File_profile_rejects_unknown_or_non_string_source_column(string query)
    {
        var result = Validate(query, KqlEnvironment.Xdr);

        Assert.False(result.Valid);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.RuleId == "KS142");
    }

    [Fact]
    public void Unified_detection_uses_defender_targets_and_advertises_detection_profile()
    {
        var result = Validate("DeviceEvents | project Timestamp, DeviceId", KqlEnvironment.Unified, LintProfile.Detection);
        var environments = new SchemaCatalog().List();

        Assert.True(result.Valid, Messages(result));
        Assert.Contains("detection", environments.Single(environment => environment.Name == "unified").Profiles);
    }

    [Fact]
    public void Unified_detection_rejects_sentinel_target()
    {
        Assert.Throws<RequestValidationException>(() => Validate(
            "DeviceEvents | project Timestamp, DeviceId",
            KqlEnvironment.Unified,
            LintProfile.Detection,
            target: KqlTarget.SentinelScheduled));
    }

    [Theory]
    [InlineData("GetFirstSeenBehaviors")]
    [InlineData("GetUncommonValueBehaviors")]
    [InlineData("GetHighVolumeAnomalyBehaviors")]
    public void Parameterless_behavior_functions_preserve_row_scope(string function)
    {
        var result = Validate($"BehaviorInfo | invoke {function}() | project BehaviorId, Insights");

        Assert.True(result.Valid, Messages(result));
        Assert.Contains(result.OutputColumns, x => x.Name == "BehaviorId");
    }

    [Fact]
    public void Behavior_function_requires_insights_string()
    {
        var result = Validate("DeviceEvents | invoke GetFirstSeenBehaviors()");

        Assert.False(result.Valid);
    }

    [Theory]
    [InlineData("GetAnomalousBehaviorsByKind('Account')")]
    [InlineData("GetAnomalousBehaviorsByKind('Account', 'FirstSeen')")]
    [InlineData("GetAnomalousBehaviorsByValue('alice@example.test')")]
    [InlineData("GetAnomalousBehaviorsByValue('alice@example.test', 'UncommonValue')")]
    public void Behavior_selector_overloads_validate(string invocation)
    {
        var result = Validate($"BehaviorInfo | invoke {invocation}");
        Assert.True(result.Valid, Messages(result));
    }

    [Fact]
    public void About_function_rejects_invalid_constant_structure()
    {
        var result = Validate("BehaviorInfo | invoke GetAnomalousBehaviorsAbout(dynamic([]))");

        Assert.False(result.Valid);
        var diagnostic = Assert.Single(result.Diagnostics, x => x.RuleId == "KQLX002");
        Assert.Equal(DiagnosticSeverity.Error, diagnostic.Severity);
        Assert.Contains("dynamic([{\"Kind\":\"Account\",\"Value\":\"example\"}])", diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("one to three", diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("Kind is required", diagnostic.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void About_function_accepts_valid_constant_structure()
    {
        var result = Validate("BehaviorInfo | invoke GetAnomalousBehaviorsAbout(dynamic([{\"Kind\":\"Account\",\"Value\":\"alice\"}]))");

        Assert.True(result.Valid, Messages(result));
    }

    [Fact]
    public void Hunting_profile_reports_unscoped_search_without_invalidating_query()
    {
        var result = Validate("search \"powershell\" | take 10", profile: LintProfile.Hunting);

        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLH001" && x.Severity == DiagnosticSeverity.Warning);
    }

    [Fact]
    public void Hunting_only_bounds_do_not_leak_into_detection_profile()
    {
        var result = Validate(
            "DeviceEvents | where ActionType == 'ProcessCreated' | project Timestamp, ReportId, DeviceId",
            profile: LintProfile.Detection);

        Assert.DoesNotContain(result.Diagnostics, x => x.RuleId is "KQLH010" or "KQLH013");
    }

    [Fact]
    public void Detection_row_limit_is_distinct_from_hunting_result_bound()
    {
        var result = Validate(
            "DeviceEvents | where ActionType == 'ProcessCreated' | take 10 | project Timestamp, ReportId, DeviceId",
            profile: LintProfile.Detection);

        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLD006");
        Assert.DoesNotContain(result.Diagnostics, x => x.RuleId == "KQLH013");
    }

    [Fact]
    public void Lint_can_be_disabled_without_disabling_semantic_validation()
    {
        var request = new ValidateRequest(
            "search 'powershell' | project MissingColumn",
            KqlEnvironment.Xdr,
            LintProfile.Hunting,
            Lint: new LintOptions(Enabled: false));

        var result = validator.Validate(request, TestContext.Current.CancellationToken);

        Assert.DoesNotContain(result.Diagnostics, x => x.RuleId.StartsWith("KQL", StringComparison.Ordinal));
        Assert.Contains(result.Diagnostics, x => x.Severity == DiagnosticSeverity.Error);
    }

    [Fact]
    public void Caller_can_select_community_rules_without_default_rule_sets()
    {
        var result = validator.Validate(new ValidateRequest(
            "DeviceProcessEvents | where FileName =~ 'powershell.exe' | project Timestamp, DeviceId, FileName",
            KqlEnvironment.Xdr,
            LintProfile.Detection,
            Target: KqlTarget.DefenderScheduled,
            Lint: new LintOptions(RuleSets: ["community-detection"])), TestContext.Current.CancellationToken);

        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLQ002" && x.RuleSet == "community-detection" && x.SourceKind == "community");
        Assert.DoesNotContain(result.Diagnostics, x => x.RuleId == "KQLD003");
    }

    [Fact]
    public void Disable_rule_wins_over_selected_rule_set()
    {
        var result = validator.Validate(new ValidateRequest(
            "DeviceEvents | where ActionType contains 'ProcessCreated' | take 10",
            KqlEnvironment.Xdr,
            LintProfile.Hunting,
            Lint: new LintOptions(RuleSets: ["microsoft-kusto"], DisableRules: ["KQLP001"])), TestContext.Current.CancellationToken);

        Assert.DoesNotContain(result.Diagnostics, x => x.RuleId == "KQLP001");
    }

    [Fact]
    public void Unknown_lint_rule_is_rejected()
    {
        var request = new ValidateRequest(
            "DeviceEvents | take 1",
            KqlEnvironment.Xdr,
            LintProfile.General,
            Lint: new LintOptions(EnableRules: ["NOT-A-RULE"]));

        Assert.Throws<RequestValidationException>(() => validator.Validate(request, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void Rule_catalog_has_unique_ids_metadata_and_documentation_entries()
    {
        var rules = lintRules.List();
        var docsPath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../docs/lint-rules.md"));
        var documentation = File.ReadAllText(docsPath);

        Assert.Equal(rules.Count, rules.Select(x => x.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(rules, rule =>
        {
            Assert.False(string.IsNullOrWhiteSpace(rule.DocumentationUrl));
            Assert.Contains($"`{rule.RuleId}`", documentation, StringComparison.Ordinal);
        });
    }

    [Theory]
    [InlineData("DeviceEvents | where ActionType contains 'ProcessCreated' | take 1", "KQLP001")]
    [InlineData("DeviceEvents | where ActionType =~ 'A' or ActionType =~ 'B' | take 1", "KQLP002")]
    [InlineData("DeviceEvents | where AdditionalFields != '' | take 1", "KQLP005")]
    public void Microsoft_kusto_pack_reports_high_confidence_patterns(string query, string ruleId)
    {
        var result = Validate(query, profile: LintProfile.Hunting);
        Assert.Contains(result.Diagnostics, x => x.RuleId == ruleId && x.RuleSet == "microsoft-kusto");
    }

    [Fact]
    public void Defender_nrt_rejects_multi_input_operators_and_comments()
    {
        var result = validator.Validate(new ValidateRequest(
            "// explanation\nDeviceEvents | join kind=inner (DeviceInfo) on DeviceId | project Timestamp, DeviceId",
            KqlEnvironment.Xdr,
            LintProfile.Detection,
            Target: KqlTarget.DefenderNrt), TestContext.Current.CancellationToken);

        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLN001" && x.Severity == DiagnosticSeverity.Error);
        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLN002" && x.Severity == DiagnosticSeverity.Error);
        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLN001" && x.Message.Contains("scheduled detection", StringComparison.Ordinal));
        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLN002" && x.Message.Contains("Remove the comment", StringComparison.Ordinal));
        Assert.DoesNotContain(result.Diagnostics, x => x.RuleId == "KQLH009");
    }

    [Fact]
    public void Defender_nrt_rejects_multiple_tables_referenced_through_let()
    {
        var result = Validate(
            """
            let Enrichment = DeviceInfo
            | where DeviceId == "ThisIsJustSomeTest"
            | distinct DeviceId;
            DeviceEvents
            | where DeviceId in (Enrichment)
            | project Timestamp, DeviceId
            """,
            KqlEnvironment.Xdr,
            LintProfile.Detection,
            target: KqlTarget.DefenderNrt);

        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLN001" && x.Severity == DiagnosticSeverity.Error);
        Assert.DoesNotContain(result.Diagnostics, x => x.RuleId == "KQLN004" && x.Message.Contains("'in()'", StringComparison.Ordinal));
        Assert.Contains("DeviceInfo", result.ReferencedTables);
        Assert.Contains("DeviceEvents", result.ReferencedTables);
    }

    [Theory]
    [InlineData(KqlEnvironment.Xdr, "DeviceEvents", "Timestamp")]
    [InlineData(KqlEnvironment.Unified, "SigninLogs", "TimeGenerated")]
    public void Defender_nrt_accepts_documented_table_in_its_environment(KqlEnvironment environment, string table, string timeColumn)
    {
        var result = Validate(
            $"{table} | where 1 == 1 | project {timeColumn}",
            environment,
            LintProfile.Detection,
            target: KqlTarget.DefenderNrt);

        Assert.DoesNotContain(result.Diagnostics, x => x.RuleId is "KQLN001" or "KQLN003" or "KQLN004");
    }

    [Fact]
    public void Defender_nrt_rejects_unsupported_table_and_email_columns()
    {
        var unsupportedTable = Validate(
            "DeviceTvmSoftwareInventory | project Timestamp",
            KqlEnvironment.Xdr,
            LintProfile.Detection,
            target: KqlTarget.DefenderNrt);
        var unsupportedColumn = Validate(
            "EmailEvents | project Timestamp, LatestDeliveryAction",
            KqlEnvironment.Unified,
            LintProfile.Detection,
            target: KqlTarget.DefenderNrt);

        Assert.Contains(unsupportedTable.Diagnostics, x => x.RuleId == "KQLN003");
        Assert.Contains(unsupportedColumn.Diagnostics, x => x.RuleId == "KQLN006");
    }

    [Fact]
    public void Defender_nrt_enforces_supported_features_and_regex_literals()
    {
        var validRegex = Validate(
            """DeviceEvents | where ActionType matches regex "\\AProcessCreated\\z" | project Timestamp, DeviceId""",
            KqlEnvironment.Xdr,
            LintProfile.Detection,
            target: KqlTarget.DefenderNrt);
        var invalidRegex = Validate(
            """DeviceEvents | where ActionType matches regex "\AProcessCreated" | project Timestamp, DeviceId""",
            KqlEnvironment.Xdr,
            LintProfile.Detection,
            target: KqlTarget.DefenderNrt);
        var unsupportedOperator = Validate(
            "DeviceEvents | summarize count() by DeviceId | project Timestamp = now(), DeviceId",
            KqlEnvironment.Xdr,
            LintProfile.Detection,
            target: KqlTarget.DefenderNrt);

        Assert.DoesNotContain(validRegex.Diagnostics, x => x.RuleId is "KQLN004" or "KQLN005");
        Assert.Contains(invalidRegex.Diagnostics, x => x.RuleId == "KQLN005");
        Assert.Contains(unsupportedOperator.Diagnostics, x => x.RuleId == "KQLN004");
    }

    [Fact]
    public void Defender_nrt_allows_scalar_argument_user_defined_functions()
    {
        var result = Validate(
            """
            let Normalize = (value:string) { tolower(value) };
            DeviceEvents
            | where Normalize(ActionType) == "processcreated"
            | project Timestamp, DeviceId
            """,
            KqlEnvironment.Xdr,
            LintProfile.Detection,
            target: KqlTarget.DefenderNrt);

        Assert.DoesNotContain(result.Diagnostics, x => x.RuleId == "KQLN004");
    }

    [Fact]
    public void Defender_nrt_warns_for_direct_and_aliased_time_filters_only()
    {
        var direct = Validate(
            "DeviceEvents | where Timestamp > ago(1h) | project Timestamp, DeviceId",
            KqlEnvironment.Xdr,
            LintProfile.Detection,
            target: KqlTarget.DefenderNrt);
        var alias = Validate(
            "DeviceEvents | extend EventTime = Timestamp | where EventTime between (ago(2h) .. ago(1h)) | project Timestamp, DeviceId",
            KqlEnvironment.Xdr,
            LintProfile.Detection,
            target: KqlTarget.DefenderNrt);
        var ingestion = Validate(
            "SigninLogs | where ingestion_time() between (ago(2h) .. ago(1h)) | project TimeGenerated",
            KqlEnvironment.Unified,
            LintProfile.Detection,
            target: KqlTarget.DefenderNrt);
        var scheduled = Validate(
            "DeviceEvents | where Timestamp > ago(1h) | project Timestamp, DeviceId",
            KqlEnvironment.Xdr,
            LintProfile.Detection,
            target: KqlTarget.DefenderScheduled);
        var sentinelNrt = Validate(
            "SigninLogs | where ingestion_time() between (ago(2h) .. ago(1h)) | project TimeGenerated",
            KqlEnvironment.Sentinel,
            LintProfile.Detection,
            target: KqlTarget.SentinelNrt);

        Assert.Contains(direct.Diagnostics, x => x.RuleId == "KQLN007" && x.Severity == DiagnosticSeverity.Warning);
        Assert.Contains(alias.Diagnostics, x => x.RuleId == "KQLN007" && x.Severity == DiagnosticSeverity.Warning);
        Assert.Contains(ingestion.Diagnostics, x => x.RuleId == "KQLN007" && x.Severity == DiagnosticSeverity.Warning);
        Assert.DoesNotContain(scheduled.Diagnostics, x => x.RuleId == "KQLN007");
        Assert.Contains(sentinelNrt.Diagnostics, x => x.RuleId == "KQLN007" && x.Severity == DiagnosticSeverity.Warning);
        Assert.DoesNotContain(sentinelNrt.Diagnostics, x => x.Severity == DiagnosticSeverity.Error);
        Assert.DoesNotContain(alias.Diagnostics, x => x.RuleId == "KQLN004" && x.Message.Contains("'between()'", StringComparison.Ordinal));
        Assert.DoesNotContain(ingestion.Diagnostics, x => x.RuleId == "KQLN004" && x.Message.Contains("'between()'", StringComparison.Ordinal));
        Assert.DoesNotContain(sentinelNrt.Diagnostics, x => x.RuleId == "KQLN004" && x.Message.Contains("'between()'", StringComparison.Ordinal));
    }

    [Fact]
    public void Sentinel_detection_length_diagnostic_reports_measurement_and_repair()
    {
        var query = "SecurityAlert | project TimeGenerated" + new string(' ', 10_001);
        var result = Validate(query, KqlEnvironment.Sentinel, LintProfile.Detection);

        var diagnostic = Assert.Single(result.Diagnostics, x => x.RuleId == "KQLS001");
        Assert.Contains("10,000", diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains(query.Length.ToString(), diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("watchlist", diagnostic.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Join_kind_rule_only_reports_an_implicit_join_kind()
    {
        var implicitKind = Validate(
            "DeviceEvents | join (DeviceInfo) on DeviceId | take 1",
            profile: LintProfile.Hunting);
        var explicitKind = Validate(
            "DeviceEvents | join kind=inner (DeviceInfo) on DeviceId | take 1",
            profile: LintProfile.Hunting);

        Assert.Contains(implicitKind.Diagnostics, x => x.RuleId == "KQLH009");
        Assert.DoesNotContain(explicitKind.Diagnostics, x => x.RuleId == "KQLH009");
    }

    [Fact]
    public void Native_xdr_accepts_time_generated_but_prefers_timestamp()
    {
        var result = Validate(
            "DeviceEvents | extend TimeGenerated = Timestamp | project TimeGenerated, DeviceId, ReportId",
            profile: LintProfile.Detection);

        Assert.DoesNotContain(result.Diagnostics, x => x.RuleId == "KQLD002");
        Assert.Contains(result.Diagnostics, x => x.RuleId == "KQLX003" && x.Severity == DiagnosticSeverity.Information);
    }

    [Fact]
    public void Sentinel_detection_requires_time_generated()
    {
        var result = Validate("SecurityAlert | project DisplayName", KqlEnvironment.Sentinel, LintProfile.Detection);

        Assert.False(result.Valid);
        var diagnostic = Assert.Single(result.Diagnostics, x => x.RuleId == "KQLD001");
        Assert.Contains("final output", diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("filtering on it alone is insufficient", diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("project TimeGenerated", diagnostic.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Sentinel_detection_requires_time_generated_in_output_not_only_filter()
    {
        var result = Validate("SecurityAlert | where TimeGenerated > ago(1h) | project DisplayName", KqlEnvironment.Sentinel, LintProfile.Detection);

        Assert.False(result.Valid);
        var diagnostic = Assert.Single(result.Diagnostics, x => x.RuleId == "KQLD001");
        Assert.Contains("final projection", diagnostic.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Xdr_detection_output_diagnostics_explain_required_fields()
    {
        var result = Validate("EmailEvents | project Timestamp", KqlEnvironment.Xdr, LintProfile.Detection);

        var reportId = Assert.Single(result.Diagnostics, x => x.RuleId == "KQLD003");
        var entity = Assert.Single(result.Diagnostics, x => x.RuleId == "KQLD004");
        Assert.Contains("ReportId", reportId.Message, StringComparison.Ordinal);
        Assert.Contains("final output", reportId.Message, StringComparison.Ordinal);
        Assert.Contains("DeviceId", reportId.Message, StringComparison.Ordinal);
        Assert.Contains("AccountObjectId", entity.Message, StringComparison.Ordinal);
        Assert.Contains("IPAddress", entity.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Xdr_event_time_diagnostic_explains_final_projection_requirement()
    {
        var result = Validate("DeviceEvents | project DeviceId", KqlEnvironment.Xdr, LintProfile.Detection);

        var diagnostic = Assert.Single(result.Diagnostics, x => x.RuleId == "KQLD002");
        Assert.Contains("Timestamp or TimeGenerated", diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("final output", diagnostic.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Unknown_schema_diagnostics_explain_lookup_and_extension_repairs()
    {
        var unknownTable = Validate("ExampleMissingTable | project Value");
        var tableDiagnostic = Assert.Single(unknownTable.Diagnostics, x => x.RuleId == "KS204");
        Assert.Contains("selected environment", tableDiagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("extensions.tables", tableDiagnostic.Message, StringComparison.Ordinal);

        var unknownFunction = Validate("ExampleMissingFunction()");
        var functionDiagnostic = Assert.Single(unknownFunction.Diagnostics, x => x.RuleId == "KS211");
        Assert.Contains("function name and signature", functionDiagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("extensions.functions", functionDiagnostic.Message, StringComparison.Ordinal);

        var unknownColumn = Validate("DeviceEvents | where MissingColumn == 'x'");
        var columnDiagnostic = Assert.Single(unknownColumn.Diagnostics, x => x.RuleId == "KS142");
        Assert.Contains("table schema", columnDiagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("spelling and scope", columnDiagnostic.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Seen_by_preserves_device_row_scope()
    {
        var result = Validate("DeviceInfo | invoke SeenBy() | project DeviceId, DeviceName");

        Assert.True(result.Valid, Messages(result));
    }

    [Fact]
    public void Request_scoped_watchlist_columns_are_available()
    {
        var extensions = new ValidationExtensions(Watchlists:
        [
            new WatchlistDeclaration("example_alias", [new ColumnDeclaration("CustomPattern", "string")])
        ]);

        var result = Validate("_GetWatchlist('example_alias') | project SearchKey, CustomPattern", KqlEnvironment.Sentinel, extensions: extensions);
        Assert.True(result.Valid, Messages(result));
    }

    [Fact]
    public void Unknown_workspace_watchlist_column_explains_request_extension()
    {
        var result = Validate("_GetWatchlist('example_alias') | project CustomPattern", KqlEnvironment.Sentinel);

        var diagnostic = Assert.Single(result.Diagnostics, x => x.RuleId == "KS142");
        Assert.Contains("workspace-specific", diagnostic.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("example_alias", diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("CustomPattern", diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("extensions", diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("\"type\": \"string\"", diagnostic.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Ordinary_unknown_column_keeps_generic_semantic_diagnostic()
    {
        var result = Validate("DeviceEvents | project CustomPattern", KqlEnvironment.Xdr);

        var diagnostic = Assert.Single(result.Diagnostics, x => x.RuleId == "KS142");
        Assert.Contains("table schema", diagnostic.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("known built-in watchlist column", diagnostic.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Sentinel_union_type_suffix_columns_are_available()
    {
        var result = Validate(
            "union AADNonInteractiveUserSignInLogs, SigninLogs | extend Status = iff(isempty(Status_dynamic), todynamic(Status_string), Status_dynamic) | project Status, Status_dynamic, Status_string",
            KqlEnvironment.Sentinel);

        Assert.True(result.Valid, Messages(result));
    }

    [Theory]
    [InlineData("Asset FQDN")]
    [InlineData("User Principal Name")]
    [InlineData("IP Subnet")]
    [InlineData("Termination date")]
    [InlineData("Associated Privileged Account")]
    [InlineData("Owner User Principal Name")]
    public void Built_in_watchlist_template_columns_are_available(string column)
    {
        var result = Validate($"_GetWatchlist('any_alias') | project ['{column}']", KqlEnvironment.Sentinel);

        Assert.True(result.Valid, Messages(result));
    }

    [Fact]
    public void Unknown_builtin_watchlist_template_column_is_rejected()
    {
        var result = Validate("_GetWatchlist('any_alias') | project ['Not a watchlist column']", KqlEnvironment.Sentinel);

        Assert.False(result.Valid);
    }

    [Fact]
    public void Watchlist_alias_function_is_available_in_sentinel()
    {
        var result = Validate("_GetWatchlistAlias | project WatchlistAlias", KqlEnvironment.Sentinel);

        Assert.True(result.Valid, Messages(result));
    }

    [Theory]
    [InlineData("_GetWatchlist('assets') | project Tags", "Tags")]
    [InlineData("_GetWatchlist('assets') | project ['IP Address']", "IP Address")]
    public void Optional_watchlist_column_requires_column_ifexists(string query, string column)
    {
        var result = Validate(query, KqlEnvironment.Sentinel);

        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.RuleId == "KQLS002" && diagnostic.Message.Contains(column, StringComparison.Ordinal));
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.RuleId == "KQLS002" && diagnostic.SourceName == "Fabian Bader");
    }

    [Fact]
    public void Column_ifexists_suppresses_optional_watchlist_column_rule()
    {
        var result = Validate("_GetWatchlist('assets') | extend Tags = column_ifexists('Tags', '') | project Tags", KqlEnvironment.Sentinel);

        Assert.DoesNotContain(result.Diagnostics, diagnostic => diagnostic.RuleId == "KQLS002");
    }

    [Fact]
    public void Native_watchlist_column_does_not_trigger_optional_column_rule()
    {
        var result = Validate("_GetWatchlist('assets') | project SearchKey", KqlEnvironment.Sentinel);

        Assert.DoesNotContain(result.Diagnostics, diagnostic => diagnostic.RuleId == "KQLS002");
    }

    [Fact]
    public void Watchlist_string_literal_does_not_trigger_optional_column_rule()
    {
        var result = Validate("_GetWatchlist('assets') | where SearchKey == 'Tags' | project SearchKey", KqlEnvironment.Sentinel);

        Assert.DoesNotContain(result.Diagnostics, diagnostic => diagnostic.RuleId == "KQLS002");
    }

    [Fact]
    public void Asim_scalar_lookup_function_is_available_in_sentinel()
    {
        var result = Validate("print ProtocolName = _ASIM_LookupNetworkProtocol(6)", KqlEnvironment.Sentinel);

        Assert.True(result.Valid, Messages(result));
        Assert.Contains(result.OutputColumns, column => column.Name == "ProtocolName" && column.Type == "string");
    }

    [Fact]
    public void Asim_resolver_preserves_the_pipeline_and_adds_documented_fields()
    {
        var result = Validate("SecurityEvent | invoke _ASIM_ResolveNetworkProtocol('EventID') | project EventID, NetworkProtocol", KqlEnvironment.Sentinel);

        Assert.True(result.Valid, Messages(result));
    }

    [Fact]
    public void Generated_asim_unifying_parser_is_available_in_unified()
    {
        var result = Validate("_Im_Authentication | project TimeGenerated, TargetUsername, SrcIpAddr", KqlEnvironment.Unified);

        Assert.True(result.Valid, Messages(result));
    }

    [Fact]
    public void Generated_asim_source_parser_accepts_its_documented_named_parameter()
    {
        var result = Validate("_Im_Dns_SentinelOne(starttime=ago(1h)) | project DnsQuery, DnsResponseCodeName", KqlEnvironment.Sentinel);

        Assert.True(result.Valid, Messages(result));
    }

    [Fact]
    public void Sentinel_metadata_normalizer_keeps_only_schema_in_stable_order()
    {
        var snapshot = SentinelMetadataNormalizer.Normalize("""
            {
              "functions": [{ "name": "SensitiveFunction", "body": "SecretTable" }],
              "tables": [
                { "name": "zTable", "columns": [{ "name": "Later", "type": "Int64" }, { "name": "First", "type": "boolean" }] },
                { "name": "ATable", "columns": [{ "name": "Payload", "type": "object" }] }
              ]
            }
            """);

        Assert.Equal("Azure Log Analytics Metadata API", snapshot["source"]!.GetValue<string>());
        var tables = snapshot["tables"]!.AsArray();
        Assert.Equal(["ATable", "zTable"], tables.Select(x => x!["name"]!.GetValue<string>()));
        Assert.Equal("dynamic", tables[0]!["columns"]![0]!["type"]!.GetValue<string>());
        Assert.Equal(["First", "Later"], tables[1]!["columns"]!.AsArray().Select(x => x!["name"]!.GetValue<string>()));
        Assert.Equal("long", tables[1]!["columns"]![1]!["type"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("""{ "tables": [] }""")]
    [InlineData("""{ "tables": [{ "name": "A", "columns": [] }, { "name": "a", "columns": [] }] }""")]
    [InlineData("""{ "tables": [{ "name": "A", "columns": [{ "name": "Value", "type": "string" }, { "name": "value", "type": "long" }] }] }""")]
    [InlineData("""{ "permissions": { "workspaces": [{ "denyTables": ["SecretTable"] }] }, "tables": [{ "name": "A", "columns": [] }] }""")]
    public void Sentinel_metadata_normalizer_rejects_incomplete_or_ambiguous_schema(string metadata)
    {
        Assert.Throws<InvalidDataException>(() => SentinelMetadataNormalizer.Normalize(metadata));
    }

    [Fact]
    public void Sentinel_metadata_normalizer_excludes_custom_log_tables_unless_requested()
    {
        const string metadata = """
            { "tables": [
              { "name": "SecurityEvent", "columns": [] },
              { "name": "PrivateEvents_CL", "columns": [] }
            ] }
            """;

        var defaultSnapshot = SentinelMetadataNormalizer.Normalize(metadata);
        var completeSnapshot = SentinelMetadataNormalizer.Normalize(metadata, includeCustomTables: true);

        Assert.Equal(["SecurityEvent"], defaultSnapshot["tables"]!.AsArray().Select(x => x!["name"]!.GetValue<string>()));
        Assert.Equal(["PrivateEvents_CL", "SecurityEvent"], completeSnapshot["tables"]!.AsArray().Select(x => x!["name"]!.GetValue<string>()));
    }

    [Fact]
    public void Official_xdr_table_normalizer_extracts_documented_browser_extension_schema()
    {
        var source = new OfficialXdrTableSource("DeviceTvmBrowserExtensions", "https://learn.microsoft.com/example", "https://raw.githubusercontent.com/example");
        const string markdown = """
            # DeviceTvmBrowserExtensions table

            | Column name | Data type | Description |
            | --- | --- | --- |
            | `DeviceId` | `string` | Device identifier |
            | `InstallationTime` | `datetime` | Installation time |
            """;

        var table = OfficialXdrTableNormalizer.Normalize(source, markdown);

        Assert.Equal("DeviceTvmBrowserExtensions", table["name"]!.GetValue<string>());
        Assert.Contains(table["columns"]!.AsArray(), column => column!["name"]!.GetValue<string>() == "InstallationTime" && column["type"]!.GetValue<string>() == "datetime");
    }

    [Fact]
    public void Official_xdr_table_normalizer_rejects_missing_schema()
    {
        var source = new OfficialXdrTableSource("Missing", "https://learn.microsoft.com/example", "https://raw.githubusercontent.com/example");

        Assert.Throws<InvalidDataException>(() => OfficialXdrTableNormalizer.Normalize(source, "# Missing\nNo column table."));
    }

    [Fact]
    public void Official_xdr_discovery_filters_non_table_documents_and_orders_the_catalog()
    {
        const string listing = """
            [
              { "type": "file", "name": "advanced-hunting-zebra-table.md", "download_url": "https://raw.example/zebra.md" },
              { "type": "file", "name": "advanced-hunting-overview.md", "download_url": "https://raw.example/overview.md" },
              { "type": "file", "name": "advanced-hunting-alpha-table.md", "download_url": "https://raw.example/alpha.md" },
              { "type": "file", "name": "advanced-hunting-functions.md", "download_url": "https://raw.example/functions.md" },
              { "type": "dir", "name": "nested", "download_url": "https://raw.example/nested" }
            ]
            """;

        var documents = OfficialXdrTableNormalizer.DiscoverDocuments(listing);

        Assert.Equal(["advanced-hunting-alpha-table.md", "advanced-hunting-zebra-table.md"], documents.Select(document => document.FileName));
        Assert.Equal("https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alpha-table", documents[0].DocumentationUrl);
    }

    [Fact]
    public void Official_xdr_discovery_derives_table_name_from_h1_and_normalizes_columns()
    {
        var document = new OfficialXdrTableDocument("advanced-hunting-devicesample-table.md", "https://raw.example/sample.md");
        const string markdown = """
            # DeviceSample table

            | Column name | Data type | Description |
            | --- | --- | --- |
            | `When` | `date` | Event time |
            | `Metadata` | `object` | Extra values |
            """;

        var source = OfficialXdrTableNormalizer.SourceFromDocument(document, markdown);
        var table = OfficialXdrTableNormalizer.Normalize(source, markdown);

        Assert.Equal("DeviceSample", source.TableName);
        Assert.Contains(table["columns"]!.AsArray(), column => column!["name"]!.GetValue<string>() == "When" && column["type"]!.GetValue<string>() == "datetime");
        Assert.Contains(table["columns"]!.AsArray(), column => column!["name"]!.GetValue<string>() == "Metadata" && column["type"]!.GetValue<string>() == "dynamic");
    }

    [Fact]
    public void Official_xdr_discovery_rejects_a_malformed_document_without_a_table_heading()
    {
        var document = new OfficialXdrTableDocument("advanced-hunting-sample-table.md", "https://raw.example/sample.md");

        Assert.Throws<InvalidDataException>(() => OfficialXdrTableNormalizer.SourceFromDocument(document, "## Columns\n| Column name | Data type |"));
    }

    [Fact]
    public void Sentinel_catalog_loads_a_generated_workspace_snapshot()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"kql-validator-schema-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllText(Path.Combine(directory, "sentinel.json"), """
                { "source": "Azure Log Analytics Metadata API", "tables": [
                  { "name": "WorkspaceAudit", "columns": [{ "name": "TimeGenerated", "type": "datetime" }, { "name": "ResultCode", "type": "long" }] }
                ] }
                """);

            var catalog = new SchemaCatalog(directory);
            var table = catalog.Get(KqlEnvironment.Sentinel).Tables["WorkspaceAudit"];

            Assert.Contains(table.Columns, column => column.Name == "ResultCode" && column.Type == "long");
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Official_xdr_snapshot_overrides_primary_feed_for_licensed_table()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"kql-validator-schema-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllText(Path.Combine(directory, "xdr.json"), """
                { "tables": [{ "name": "DeviceTvmBrowserExtensions", "columns": [{ "name": "OldColumn", "type": "string" }] }] }
                """);
            File.WriteAllText(Path.Combine(directory, "xdr-official-tables.json"), """
                { "tables": [{ "name": "DeviceTvmBrowserExtensions", "columns": [{ "name": "ExtensionName", "type": "string" }] }] }
                """);

            var table = new SchemaCatalog(directory).Get(KqlEnvironment.Xdr).Tables["DeviceTvmBrowserExtensions"];

            Assert.Equal(["ExtensionName"], table.Columns.Select(column => column.Name));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Sentinel_workspace_snapshot_is_authoritative_over_the_fallback_catalog()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"kql-validator-schema-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            File.WriteAllText(Path.Combine(directory, "sentinel.json"), """
                { "tables": [
                  { "name": "SecurityAlert", "columns": [{ "name": "LiveOnly", "type": "long" }] }
                ] }
                """);

            var table = new SchemaCatalog(directory).Get(KqlEnvironment.Sentinel).Tables["SecurityAlert"];

            Assert.Equal(["LiveOnly"], table.Columns.Select(column => column.Name));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Request_scoped_table_is_available_only_to_that_validation()
    {
        var extensions = new ValidationExtensions(Tables:
        [
            new TableDeclaration("MyEvents", [new ColumnDeclaration("TimeGenerated", "datetime"), new ColumnDeclaration("Value", "string")])
        ]);
        var custom = Validate("MyEvents | project Value", extensions: extensions);
        var builtInOnly = Validate("MyEvents | project Value");

        Assert.True(custom.Valid, Messages(custom));
        Assert.False(builtInOnly.Valid);
    }

    [Fact]
    public void Extension_cannot_shadow_builtin()
    {
        var extensions = new ValidationExtensions(Tables:
        [
            new TableDeclaration("DeviceEvents", [new ColumnDeclaration("Other", "string")])
        ]);

        Assert.Throws<RequestValidationException>(() => Validate("DeviceEvents", extensions: extensions));
    }

    [Fact]
    public void Schema_versions_are_deterministic_content_fingerprints()
    {
        var first = new SchemaCatalog().List();
        var second = new SchemaCatalog().List();

        Assert.Equal(first.Select(x => x.SchemaVersion), second.Select(x => x.SchemaVersion));
        Assert.All(first, environment => Assert.Matches("^sha256:[0-9a-f]{24}$", environment.SchemaVersion));
        Assert.Equal(3, first.Select(x => x.SchemaVersion).Distinct(StringComparer.Ordinal).Count());
    }

    private ValidationResponse Validate(
        string query,
        KqlEnvironment environment = KqlEnvironment.Xdr,
        LintProfile profile = LintProfile.General,
        ValidationExtensions? extensions = null,
        KqlTarget? target = null) =>
        validator.Validate(new ValidateRequest(query, environment, profile, extensions, target));

    private static string Messages(ValidationResponse response) =>
        string.Join(Environment.NewLine, response.Diagnostics.Select(x => $"{x.RuleId}: {x.Message}"));
}
