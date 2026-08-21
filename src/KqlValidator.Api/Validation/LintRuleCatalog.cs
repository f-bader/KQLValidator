using KqlValidator.Contracts;

namespace KqlValidator.Validation;

public sealed class LintRuleCatalog
{
    private const string DefenderBestPractices = "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices";
    private const string DefenderDetections = "https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules";
    private const string KustoBestPractices = "https://learn.microsoft.com/en-us/kusto/query/best-practices";
    private const string SentinelRules = "https://learn.microsoft.com/en-us/azure/sentinel/scheduled-rules-overview";
    private const string AlertQueries = "https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-log-query";
    private const string DxBp1 = "https://kqlquery.com/posts/dxbp-part1/";
    private const string DxBp2 = "https://kqlquery.com/posts/dxbp-part2/";
    private const string FalconNrt = "https://falconforce.nl/falconfriday-need-for-speed-going-underground-with-near-real-time-nrt-rules-0xff26/";
    private const string RepoDocs = "https://github.com/f-bader/KQLValidator/blob/main/docs/lint-rules.md";

    private static readonly string[] GeneralHuntingDetection = ["general", "hunting", "detection"];
    private static readonly string[] HuntingDetection = ["hunting", "detection"];
    private static readonly string[] Detection = ["detection"];
    private static readonly string[] XdrUnified = ["xdr", "unified"];
    private static readonly string[] Sentinel = ["sentinel"];

    private static readonly IReadOnlyList<LintRuleInfo> Rules =
    [
        Rule("KQLH001", "Unscoped search", DiagnosticSeverity.Warning, "performance", "baseline", "Scope search to explicit tables.", DefenderBestPractices, HuntingDetection),
        Rule("KQLH002", "Wildcard column search", DiagnosticSeverity.Warning, "performance", "baseline", "Search specific columns instead of every column.", DefenderBestPractices, HuntingDetection),
        Rule("KQLH003", "Broad union", DiagnosticSeverity.Warning, "performance", "baseline", "Enumerate only the required union inputs.", DefenderBestPractices, HuntingDetection),
        Rule("KQLH004", "Row-wise case transformation", DiagnosticSeverity.Warning, "performance", "baseline", "Avoid tolower or toupper on every row when an appropriate string operator preserves the intended semantics.", DefenderBestPractices, HuntingDetection),
        Rule("KQLH005", "Regex or extract parsing", DiagnosticSeverity.Information, "performance", "baseline", "Prefer structured parsing when the input format permits it.", DefenderBestPractices, HuntingDetection),
        Rule("KQLH006", "Short unindexed term", DiagnosticSeverity.Information, "performance", "baseline", "Terms of three characters or fewer are not term-indexed.", DefenderBestPractices, HuntingDetection),
        Rule("KQLH007", "Filter on calculated column", DiagnosticSeverity.Warning, "performance", "baseline", "Filter physical source columns before calculating derived values when semantics permit.", DefenderBestPractices, HuntingDetection),
        Rule("KQLH008", "Brittle hunting command line", DiagnosticSeverity.Warning, "detection-quality", "baseline", "Avoid exact command-line equality in hunting queries.", DefenderBestPractices, ["hunting"]),
        Rule("KQLH009", "Join without explicit kind", DiagnosticSeverity.Information, "correctness", "baseline", "Specify join kind so innerunique deduplication is intentional.", DefenderBestPractices, HuntingDetection),
        Rule("KQLH010", "Unbounded hunting time range", DiagnosticSeverity.Warning, "performance", "baseline", "Bound ad-hoc hunting queries with an early time predicate.", DefenderBestPractices, ["hunting"], ["interactive-hunting"]),
        Rule("KQLH011", "Unbounded hunting join branch", DiagnosticSeverity.Warning, "performance", "baseline", "Time-bound every join branch in ad-hoc hunting queries.", DefenderBestPractices, ["hunting"], ["interactive-hunting"]),
        Rule("KQLH012", "Late selective filter", DiagnosticSeverity.Warning, "performance", "baseline", "Apply selective filters before expensive parsing and transformation.", DefenderBestPractices, HuntingDetection),
        Rule("KQLH013", "Unbounded exploratory result", DiagnosticSeverity.Information, "performance", "baseline", "Bound result volume while developing an interactive hunting query.", DefenderBestPractices, ["hunting"], ["interactive-hunting"]),
        Rule("KQLH014", "Reused process identifier", DiagnosticSeverity.Warning, "correctness", "baseline", "Use a process unique ID or creation time with a process ID.", DefenderBestPractices, HuntingDetection),

        Rule("KQLD001", "Sentinel output omits TimeGenerated", DiagnosticSeverity.Error, "detection", "sentinel-detection", "Retain TimeGenerated in the final Sentinel scheduled/NRT detection projection; filtering on it alone is insufficient.", SentinelRules, Detection, ["sentinel-scheduled", "sentinel-nrt"], Sentinel),
        Rule("KQLD002", "XDR output omits event time", DiagnosticSeverity.Warning, "detection", "defender-xdr", "Retain Timestamp or TimeGenerated in the final projection so each Defender result identifies its event time.", DefenderDetections, Detection, ["defender-scheduled", "defender-nrt"], XdrUnified),
        Rule("KQLD003", "XDR output omits ReportId", DiagnosticSeverity.Warning, "detection", "defender-xdr", "Retain ReportId in the final projection for applicable non-endpoint Defender event tables so the source event can be identified.", DefenderDetections, Detection, ["defender-scheduled", "defender-nrt"], XdrUnified),
        Rule("KQLD004", "XDR output omits a strong entity", DiagnosticSeverity.Warning, "detection-quality", "defender-xdr", "Retain a strong device, account, IP, or file identifier such as DeviceId, AccountObjectId, IPAddress, or SHA256.", DefenderDetections, Detection, ["defender-scheduled", "defender-nrt"], XdrUnified),
        Rule("KQLD005", "Brittle detection command line", DiagnosticSeverity.Warning, "detection-quality", "defender-xdr", "Make command-line detection logic tolerant of benign representation changes.", DefenderBestPractices, Detection, ["defender-scheduled", "defender-nrt"], XdrUnified),
        Rule("KQLD006", "Row limit in alert query", DiagnosticSeverity.Warning, "reliability", "baseline", "Avoid take or limit in alert queries because results can be inconsistent.", AlertQueries, Detection),

        Rule("KQLX001", "Unknown XDR ActionType", DiagnosticSeverity.Warning, "xdr", "defender-xdr", "Verify ActionType literals against the bundled current catalog.", "https://xdrinternals.com/", GeneralHuntingDetection, environments: XdrUnified),
        Rule("KQLX002", "Invalid anomalous behavior literal", DiagnosticSeverity.Error, "xdr", "defender-xdr", "Use dynamic([...]) with one to three objects, each requiring a string Kind and allowing an optional string Value.", "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-getanomalousbehaviorsabout-function", GeneralHuntingDetection, environments: XdrUnified),
        Rule("KQLX003", "Prefer native XDR Timestamp", DiagnosticSeverity.Information, "xdr", "defender-xdr", "Timestamp is preferred for native Defender XDR output even though unified XDR also accepts TimeGenerated.", DefenderDetections, Detection, ["defender-scheduled", "defender-nrt"], ["xdr"]),

        Rule("KQLP001", "Consider has instead of contains", DiagnosticSeverity.Information, "performance", "microsoft-kusto", "Use has when full-term matching is intended so the term index can be used.", KustoBestPractices, HuntingDetection),
        Rule("KQLP002", "Repeated equality chain", DiagnosticSeverity.Information, "performance", "microsoft-kusto", "Use in or in~ for repeated equality comparisons on one column.", "https://learn.microsoft.com/en-us/kusto/query/in-cs-operator", HuntingDetection),
        Rule("KQLP003", "bag_unpack without OutputSchema", DiagnosticSeverity.Information, "performance", "microsoft-kusto", "Declare bag_unpack OutputSchema to avoid schema inference during execution.", "https://learn.microsoft.com/en-us/kusto/query/bag-unpack-plugin", HuntingDetection),
        Rule("KQLP004", "format_datetime in predicate", DiagnosticSeverity.Warning, "performance", "microsoft-kusto", "Filter datetime values directly instead of formatting each row in a predicate.", KustoBestPractices, HuntingDetection),
        Rule("KQLP005", "Null string comparison", DiagnosticSeverity.Warning, "correctness", "microsoft-kusto", "Use isempty or isnotempty instead of comparing a string with an empty literal.", "https://learn.microsoft.com/en-us/kusto/query/isempty-function", HuntingDetection),
        Rule("KQLP006", "Generic term operator for IPv4", DiagnosticSeverity.Information, "performance", "microsoft-kusto", "Use an IPv4-aware operator for IPv4 literals.", KustoBestPractices, HuntingDetection),

        Rule("KQLS001", "Sentinel detection exceeds query length", DiagnosticSeverity.Error, "sentinel", "sentinel-detection", "Sentinel analytics rule queries are limited to 10,000 characters; shorten large literals or move pattern data into a watchlist or other managed external source.", SentinelRules, Detection, ["sentinel-scheduled", "sentinel-nrt"], Sentinel),
        Rule("KQLS002", "Optional watchlist column", DiagnosticSeverity.Warning, "sentinel", "baseline", "Normalize optional _GetWatchlist columns with column_ifexists before using them.", RepoDocs, GeneralHuntingDetection, environments: ["sentinel", "unified"], sourceName: "Fabian Bader"),
        Rule("KQLN001", "Defender NRT single-table constraint", DiagnosticSeverity.Error, "nrt", "defender-nrt", "Defender continuous NRT rules must use exactly one table and do not support join, union, or externaldata.", DefenderDetections, Detection, ["defender-nrt"], XdrUnified),
        Rule("KQLN002", "Comment in Defender NRT query", DiagnosticSeverity.Error, "nrt", "defender-nrt", "Defender continuous NRT rules do not support comments in deployed KQL; remove them or use a scheduled target.", DefenderDetections, Detection, ["defender-nrt"], XdrUnified),
        Rule("KQLN003", "Unsupported Defender NRT table", DiagnosticSeverity.Error, "nrt", "defender-nrt", "Use one of the Microsoft-documented NRT tables for the selected XDR or unified environment.", DefenderDetections, Detection, ["defender-nrt"], XdrUnified),
        Rule("KQLN004", "Unsupported Defender NRT KQL feature", DiagnosticSeverity.Error, "nrt", "defender-nrt", "Use only the tabular operators, scalar functions, and scalar-argument user-defined functions documented for continuous NRT.", DefenderDetections, Detection, ["defender-nrt"], XdrUnified),
        Rule("KQLN005", "Invalid Defender NRT regex expression", DiagnosticSeverity.Error, "nrt", "defender-nrt", "Use matches regex with a correctly escaped KQL string literal.", DefenderDetections, Detection, ["defender-nrt"], XdrUnified),
        Rule("KQLN006", "Unsupported Defender NRT EmailEvents column", DiagnosticSeverity.Error, "nrt", "defender-nrt", "Do not use EmailEvents LatestDeliveryLocation or LatestDeliveryAction in a continuous NRT rule.", DefenderDetections, Detection, ["defender-nrt"], XdrUnified),
        Rule("KQLN007", "Time filter in NRT query", DiagnosticSeverity.Warning, "nrt", "defender-nrt", "Avoid Timestamp, TimeGenerated, and ingestion_time predicates because they can skip qualifying NRT events.", DefenderDetections, Detection, ["defender-nrt", "sentinel-nrt"], ["xdr", "unified", "sentinel"]),

        Rule("KQLQ001", "Display name used as detection identity", DiagnosticSeverity.Information, "detection-quality", "community-detection", "Prefer stable identifiers over account, device, or application display names when available.", DxBp1, Detection, defaultEnabled: false),
        Rule("KQLQ002", "Filename detection omits original filename", DiagnosticSeverity.Information, "detection-quality", "community-detection", "Consider original-file-name metadata to make renamed-binary detections more resilient.", DxBp1, Detection, defaultEnabled: false),
        Rule("KQLQ003", "Unexplained inline exclusion", DiagnosticSeverity.Information, "maintainability", "community-detection", "Document why an inline allowlist or exclusion is safe and who owns it.", DxBp2, Detection, defaultEnabled: false),
        Rule("KQLQ004", "Sentinel NRT multi-event correlation", DiagnosticSeverity.Warning, "detection-quality", "community-detection", "Sentinel NRT joins and unions can miss independently ingested events in its short window.", FalconNrt, Detection, ["sentinel-nrt"], Sentinel, defaultEnabled: false),
    ];

    private readonly IReadOnlyDictionary<string, LintRuleInfo> byId = Rules.ToDictionary(x => x.RuleId, StringComparer.OrdinalIgnoreCase);
    private readonly IReadOnlySet<string> ruleSets = Rules.Select(x => x.RuleSet).ToHashSet(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<LintRuleInfo> List(
        string? ruleSet = null,
        string? category = null,
        string? profile = null,
        string? target = null,
        string? environment = null) => Rules
        .Where(rule => ruleSet is null || rule.RuleSet.Equals(ruleSet, StringComparison.OrdinalIgnoreCase))
        .Where(rule => category is null || rule.Category.Equals(category, StringComparison.OrdinalIgnoreCase))
        .Where(rule => profile is null || rule.Profiles.Contains(profile, StringComparer.OrdinalIgnoreCase))
        .Where(rule => target is null || rule.Targets.Count == 0 || rule.Targets.Contains(target, StringComparer.OrdinalIgnoreCase))
        .Where(rule => environment is null || rule.Environments.Count == 0 || rule.Environments.Contains(environment, StringComparer.OrdinalIgnoreCase))
        .ToArray();
    public bool ContainsRule(string ruleId) => byId.ContainsKey(ruleId);
    public bool ContainsRuleSet(string ruleSet) => ruleSets.Contains(ruleSet);
    public LintRuleInfo Get(string ruleId) => byId[ruleId];

    public LintPolicy CreatePolicy(ValidateRequest request)
    {
        if (request.Lint is { Enabled: false })
            return LintPolicy.Disabled;

        var target = ResolveTarget(request);
        var selectedSets = request.Lint?.RuleSets is { } requestedSets
            ? requestedSets.ToHashSet(StringComparer.OrdinalIgnoreCase)
            : DefaultRuleSets(request, target);
        var explicitRuleSets = request.Lint?.RuleSets is not null;
        var explicitlyEnabled = request.Lint?.EnableRules?.ToHashSet(StringComparer.OrdinalIgnoreCase) ?? [];
        var disabled = request.Lint?.DisableRules?.ToHashSet(StringComparer.OrdinalIgnoreCase) ?? [];
        var enabled = Rules
            .Where(rule => ((explicitRuleSets || rule.DefaultEnabled) && selectedSets.Contains(rule.RuleSet)) || explicitlyEnabled.Contains(rule.RuleId))
            .Where(rule => !disabled.Contains(rule.RuleId))
            .Where(rule => Applies(rule, request, target))
            .Select(rule => rule.RuleId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return new LintPolicy(enabled, request.Lint?.MinimumSeverity, target);
    }

    public ValidationDiagnostic CreateDiagnostic(
        string query, string ruleId, string message, int start, int length = 1,
        DiagnosticSeverity? severity = null)
    {
        var rule = Get(ruleId);
        return new ValidationDiagnostic(
            ruleId,
            severity ?? rule.DefaultSeverity,
            message,
            KqlLinter.Span(query, start, length),
            rule.DocumentationUrl,
            rule.Category,
            rule.RuleSet,
            rule.SourceKind,
            rule.SourceName);
    }

    public static KqlTarget? ResolveTarget(ValidateRequest request) => request.Target ?? request.Profile switch
    {
        LintProfile.Hunting => KqlTarget.InteractiveHunting,
        LintProfile.Detection when request.Environment == KqlEnvironment.Sentinel => KqlTarget.SentinelScheduled,
        LintProfile.Detection when request.Environment is KqlEnvironment.Xdr or KqlEnvironment.Unified => KqlTarget.DefenderScheduled,
        _ => null,
    };

    private static HashSet<string> DefaultRuleSets(ValidateRequest request, KqlTarget? target)
    {
        var sets = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "baseline" };
        if (request.Environment is KqlEnvironment.Xdr or KqlEnvironment.Unified)
            sets.Add("defender-xdr");
        if (request.Profile == LintProfile.Hunting)
            sets.Add("microsoft-kusto");
        if (request.Profile == LintProfile.Detection && request.Environment == KqlEnvironment.Sentinel)
            sets.Add("sentinel-detection");
        if (target is KqlTarget.DefenderNrt or KqlTarget.SentinelNrt)
            sets.Add("defender-nrt");
        return sets;
    }

    private static bool Applies(LintRuleInfo rule, ValidateRequest request, KqlTarget? target)
    {
        var profile = request.Profile.ToString().ToLowerInvariant();
        var environment = request.Environment.ToString().ToLowerInvariant();
        if (rule.Profiles.Count > 0 && !rule.Profiles.Contains(profile, StringComparer.OrdinalIgnoreCase)) return false;
        if (rule.Environments.Count > 0 && !rule.Environments.Contains(environment, StringComparer.OrdinalIgnoreCase)) return false;
        if (rule.Targets.Count > 0 && (target is null || !rule.Targets.Contains(TargetName(target.Value), StringComparer.OrdinalIgnoreCase))) return false;
        return true;
    }

    private static string TargetName(KqlTarget target) => target switch
    {
        KqlTarget.InteractiveHunting => "interactive-hunting",
        KqlTarget.SentinelScheduled => "sentinel-scheduled",
        KqlTarget.SentinelNrt => "sentinel-nrt",
        KqlTarget.DefenderScheduled => "defender-scheduled",
        KqlTarget.DefenderNrt => "defender-nrt",
        _ => throw new ArgumentOutOfRangeException(nameof(target)),
    };

    private static LintRuleInfo Rule(
        string id, string title, DiagnosticSeverity severity, string category, string ruleSet,
        string description, string source, IReadOnlyList<string> profiles,
        IReadOnlyList<string>? targets = null, IReadOnlyList<string>? environments = null,
        bool defaultEnabled = true, string? sourceName = null) =>
        new(id, title, severity, category, ruleSet, defaultEnabled, description, source,
            source.Contains("learn.microsoft.com", StringComparison.OrdinalIgnoreCase) || source.Contains("github.com/Azure", StringComparison.OrdinalIgnoreCase)
                ? "microsoft" : "community",
            profiles, targets ?? [], environments ?? [], sourceName);
}

public sealed record LintPolicy(
    IReadOnlySet<string> EnabledRules,
    DiagnosticSeverity? MinimumSeverity,
    KqlTarget? Target)
{
    public static LintPolicy Disabled { get; } = new(new HashSet<string>(), null, null);

    public bool IsEnabled(string ruleId, DiagnosticSeverity severity)
    {
        if (!EnabledRules.Contains(ruleId)) return false;
        return MinimumSeverity is null || severity <= MinimumSeverity;
    }
}
