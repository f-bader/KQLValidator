using System.Text.Json;
using System.Text.RegularExpressions;
using KqlValidator.Contracts;

namespace KqlValidator.Validation;

public sealed partial class KqlLinter
{
    private static readonly HashSet<string> FallbackActionTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "AntivirusDetection", "AppControlCodeIntegrityPolicyBlocked", "AppControlExecutableAudited",
        "ConnectionFound", "CreateRemoteThreadApiCall", "FileCreated", "FileDeleted", "FileModified",
        "InboundConnectionAccepted", "LogonFailed", "LogonSuccess", "NetworkSignatureInspected",
        "OutboundConnectionAttempt", "ProcessCreated", "RegistryKeyCreated", "RegistryValueSet",
        "ScriptContent", "UsbDriveMount", "UserAccountAddedToLocalGroup"
    };

    private readonly IReadOnlySet<string> knownActionTypes;
    private readonly LintRuleCatalog rules;

    public KqlLinter(SchemaCatalog catalog, LintRuleCatalog rules)
    {
        knownActionTypes = catalog.ActionTypes.Count > 0 ? catalog.ActionTypes : FallbackActionTypes;
        this.rules = rules;
    }

    public IReadOnlyList<ValidationDiagnostic> Analyze(ValidateRequest request, LintPolicy policy)
    {
        var diagnostics = new List<ValidationDiagnostic>();
        var query = request.Query;
        var searchable = MaskComments(query);

        Match(diagnostics, policy, searchable, UnscopedSearch(), "KQLH001",
            "Scope search to explicit tables with 'search in (...)'.");
        Match(diagnostics, policy, searchable, WildcardSearch(), "KQLH002",
            "Search specific columns instead of using a wildcard column search.");
        Match(diagnostics, policy, searchable, UnscopedUnion(), "KQLH003",
            "Avoid broad union queries; enumerate only the required tables and time-bound each branch.");
        Match(diagnostics, policy, searchable, CaseTransformComparison(), "KQLH004",
            "Avoid transforming every row with tolower()/toupper(); use an appropriate string operator when its matching semantics are acceptable.");
        Match(diagnostics, policy, searchable, RegexUsage(), "KQLH005",
            "Prefer parse or parse_json for structured values; reserve regular expressions for cases that require them.");
        Match(diagnostics, policy, searchable, ShortTerm(), "KQLH006",
            "Terms of three characters or fewer are not indexed and can consume more resources.");
        Match(diagnostics, policy, searchable, CalculatedFilter(), "KQLH007",
            "Filter source columns before calculating derived values when the query can preserve the same semantics.");
        Match(diagnostics, policy, searchable, ExactCommandLine(), "KQLH008",
            "Exact command-line comparisons are brittle; scope by process filename and match or parse independent command-line components.");
        Match(diagnostics, policy, searchable, DefaultJoin(), "KQLH009",
            "The default join flavor is innerunique and deduplicates the left side; specify kind=inner when every left-side row must be retained.");

        AddTimeFilterDiagnostics(diagnostics, policy, searchable);
        AddLateFilterDiagnostics(diagnostics, policy, searchable);
        AddUnboundedResultDiagnostic(diagnostics, policy, searchable);
        AddProcessIdDiagnostic(diagnostics, policy, searchable);
        AddActionTypeDiagnostics(diagnostics, policy, searchable);
        AddAnomalousBehaviorLiteralDiagnostics(diagnostics, policy, searchable);
        AddDetectionTextDiagnostics(diagnostics, policy, searchable);
        AddMicrosoftKustoDiagnostics(diagnostics, policy, searchable);
        AddTargetDiagnostics(diagnostics, policy, query, searchable);
        AddCommunityDiagnostics(diagnostics, policy, query, searchable);
        return diagnostics;
    }

    private void AddTimeFilterDiagnostics(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query)
    {
        var hasXdrTable = Regex.IsMatch(query, @"(?im)^\s*(Device|Email|Identity|CloudApp|Alert|Behavior)[A-Za-z]+\b");
        var hasTimeFilter = Regex.IsMatch(query, @"(?i)\b(?:Timestamp|TimeGenerated)\s*(?:>|>=|between|in)\b");
        if (hasXdrTable && !hasTimeFilter)
            Add(diagnostics, policy, query, "KQLH010",
                "Add an early Timestamp or TimeGenerated filter to bound scanned data.", 0);

        foreach (Match join in JoinBranch().Matches(query))
        {
            if (!Regex.IsMatch(join.Value, @"(?i)\b(?:Timestamp|TimeGenerated)\s*(?:>|>=|between|in)\b"))
                Add(diagnostics, policy, query, "KQLH011",
                    "Apply a time filter inside this join branch as well as on the left input.", join.Index, join.Length);
        }
    }

    private void AddLateFilterDiagnostics(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query)
    {
        var expensive = ExpensiveOperation().Match(query);
        if (!expensive.Success)
            return;
        var filter = Regex.Match(query, @"(?i)\|\s*where\b");
        if (!filter.Success || filter.Index > expensive.Index)
            Add(diagnostics, policy, query, "KQLH012",
                "Apply selective filters before parsing, extraction, regex, or row-wise string transformations.", expensive.Index, expensive.Length);
    }

    private void AddUnboundedResultDiagnostic(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query)
    {
        if (!Regex.IsMatch(query, @"(?i)\b(?:take|limit|top|summarize|count)\b"))
            Add(diagnostics, policy, query, "KQLH013",
                "For exploratory hunting, use take, limit, top, count, or an aggregation to avoid unexpectedly large results.", Math.Max(0, query.Length - 1));
    }

    private void AddProcessIdDiagnostic(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query)
    {
        var pid = Regex.Match(query, @"(?i)\b(?:ProcessId|InitiatingProcessId)\b");
        if (pid.Success && !Regex.IsMatch(query, @"(?i)\b(?:ProcessUniqueId|InitiatingProcessUniqueId|ProcessCreationTime|InitiatingProcessCreationTime)\b"))
            Add(diagnostics, policy, query, "KQLH014",
                "Process IDs are reused; identify a process with its unique ID or creation time.", pid.Index, pid.Length);
    }

    private void AddActionTypeDiagnostics(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query)
    {
        foreach (Match match in ActionTypeLiteral().Matches(query))
        {
            var value = match.Groups[1].Value;
            if (!knownActionTypes.Contains(value))
                Add(diagnostics, policy, query, "KQLX001",
                    $"'{value}' is not in the bundled XDR ActionType catalog; verify it against the current schema.",
                    match.Groups[1].Index, match.Groups[1].Length);
        }
    }

    private void AddAnomalousBehaviorLiteralDiagnostics(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query)
    {
        foreach (Match invocation in AboutLiteral().Matches(query))
        {
            try
            {
                using var document = JsonDocument.Parse(invocation.Groups[1].Value);
                if (document.RootElement.ValueKind != JsonValueKind.Array || document.RootElement.GetArrayLength() is < 1 or > 3)
                    throw new JsonException("filters must be an array containing one to three objects");

                foreach (var filter in document.RootElement.EnumerateArray())
                {
                    if (filter.ValueKind != JsonValueKind.Object || !filter.TryGetProperty("Kind", out var kind) || kind.ValueKind != JsonValueKind.String)
                        throw new JsonException("each filter requires a string Kind property");
                    if (filter.TryGetProperty("Value", out var value) && value.ValueKind != JsonValueKind.String)
                        throw new JsonException("Value must be a string when supplied");
                }
            }
            catch (JsonException exception)
            {
                Add(diagnostics, policy, query, "KQLX002",
                    $"Invalid GetAnomalousBehaviorsAbout literal: {exception.Message}", invocation.Index, invocation.Length);
            }
        }
    }

    private void AddDetectionTextDiagnostics(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query)
    {
        Match(diagnostics, policy, query, ExactCommandLine(), "KQLD005",
            "Detection command-line logic should tolerate benign quoting, spacing, and argument ordering differences.");
        Match(diagnostics, policy, query, DetectionRowLimit(), "KQLD006",
            "Avoid take or limit in alert queries; use a deterministic filter or aggregation instead.");
    }

    private void Match(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query, Regex regex, string id, string message)
    {
        var severity = rules.Get(id).DefaultSeverity;
        if (!policy.IsEnabled(id, severity)) return;
        foreach (Match match in regex.Matches(query))
            diagnostics.Add(rules.CreateDiagnostic(query, id, message, match.Index, match.Length));
    }

    private void Add(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query, string id,
        string message, int start, int length = 1)
    {
        var severity = rules.Get(id).DefaultSeverity;
        if (policy.IsEnabled(id, severity))
            diagnostics.Add(rules.CreateDiagnostic(query, id, message, start, length));
    }

    private void AddMicrosoftKustoDiagnostics(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query)
    {
        Match(diagnostics, policy, query, ContainsTerm(), "KQLP001",
            "If full-term matching is intended, use has instead of contains so Kusto can use the term index.");
        Match(diagnostics, policy, query, RepeatedEquality(), "KQLP002",
            "Replace repeated equality comparisons on this column with in() or in~().");
        Match(diagnostics, policy, query, BagUnpackWithoutSchema(), "KQLP003",
            "Declare an OutputSchema after bag_unpack() to avoid schema inference during query execution.");
        Match(diagnostics, policy, query, FormatDateTimePredicate(), "KQLP004",
            "Compare datetime values directly instead of applying format_datetime() in a where predicate.");
        Match(diagnostics, policy, query, EmptyStringComparison(), "KQLP005",
            "Use isempty() or isnotempty() instead of comparing a string with an empty literal.");
        Match(diagnostics, policy, query, HasIpv4Literal(), "KQLP006",
            "Use has_ipv4() or has_any_ipv4() for an IPv4 literal.");
    }

    private void AddTargetDiagnostics(
        List<ValidationDiagnostic> diagnostics, LintPolicy policy, string originalQuery, string searchableQuery)
    {
        if (originalQuery.Length > 10_000)
            Add(diagnostics, policy, originalQuery, "KQLS001",
                "Sentinel analytics rule queries cannot exceed 10,000 characters.", 10_000,
                originalQuery.Length - 10_000);

        Match(diagnostics, policy, searchableQuery, DefenderNrtMultiInput(), "KQLN001",
            "Defender continuous NRT rules do not support join, union, or externaldata.");

        foreach (Match comment in Comment().Matches(originalQuery))
            Add(diagnostics, policy, originalQuery, "KQLN002",
                "Defender continuous NRT queries do not support comments.", comment.Index, comment.Length);
    }

    private void AddCommunityDiagnostics(
        List<ValidationDiagnostic> diagnostics, LintPolicy policy, string originalQuery, string searchableQuery)
    {
        Match(diagnostics, policy, searchableQuery, DisplayNameIdentity(), "KQLQ001",
            "Prefer a stable identifier over this display-name comparison when the source exposes one.");

        if (Regex.IsMatch(searchableQuery, @"(?i)\bDeviceProcessEvents\b") &&
            Regex.IsMatch(searchableQuery, @"(?i)\b(?:InitiatingProcess)?FileName\s*(?:==|=~|in~?)") &&
            !Regex.IsMatch(searchableQuery, @"(?i)\b(?:Initiating)?ProcessVersionInfoOriginalFileName\b"))
        {
            var fileName = Regex.Match(searchableQuery, @"(?i)\b(?:InitiatingProcess)?FileName\b");
            Add(diagnostics, policy, originalQuery, "KQLQ002",
                "Consider matching ProcessVersionInfoOriginalFileName as well as FileName to tolerate renamed binaries.",
                fileName.Index, fileName.Length);
        }

        foreach (Match exclusion in InlineExclusion().Matches(searchableQuery))
        {
            var lineStart = originalQuery.LastIndexOf('\n', Math.Max(0, exclusion.Index - 1)) + 1;
            var lineEnd = originalQuery.IndexOf('\n', exclusion.Index);
            if (lineEnd < 0) lineEnd = originalQuery.Length;
            var line = originalQuery[lineStart..lineEnd];
            if (!line.Contains("//", StringComparison.Ordinal))
                Add(diagnostics, policy, originalQuery, "KQLQ003",
                    "Document the reason and ownership for this inline exclusion or allowlist.", exclusion.Index, exclusion.Length);
        }

        Match(diagnostics, policy, searchableQuery, SentinelNrtCorrelation(), "KQLQ004",
            "Sentinel NRT joins and unions can miss events that arrive in different ingestion windows; prefer a single-event NRT rule when possible.");
    }

    internal static SourceSpan Span(string query, int start, int length)
    {
        start = Math.Clamp(start, 0, query.Length);
        var line = 1;
        var lastLine = -1;
        for (var i = 0; i < start; i++)
            if (query[i] == '\n') { line++; lastLine = i; }
        return new SourceSpan(start, Math.Max(0, Math.Min(length, query.Length - start)), line, start - lastLine);
    }

    private static string MaskComments(string query) => Regex.Replace(query, @"(?m)//[^\r\n]*|/\*[\s\S]*?\*/", m => new string(' ', m.Length));

    [GeneratedRegex(@"(?im)(?:^|;)\s*search\s+(?!in\s*\()")]
    private static partial Regex UnscopedSearch();
    [GeneratedRegex(@"(?i)\b(?:search|where)\b[^\r\n|;]*\*\s*(?:has|contains|matches|==|=~)")]
    private static partial Regex WildcardSearch();
    [GeneratedRegex(@"(?im)(?:^|\|)\s*union\s+(?:\*|withsource\s*=)")]
    private static partial Regex UnscopedUnion();
    [GeneratedRegex(@"(?i)\b(?:tolower|toupper)\s*\([^)]*\)\s*(?:==|=~|in~?)")]
    private static partial Regex CaseTransformComparison();
    [GeneratedRegex(@"(?i)\b(?:matches\s+regex|extract(?:_all)?\s*\()")]
    private static partial Regex RegexUsage();
    [GeneratedRegex("""(?i)\b(?:has|contains|==|=~)\s*["']\w{1,3}["']""")]
    private static partial Regex ShortTerm();
    [GeneratedRegex(@"(?is)\|\s*extend\s+(?<name>[A-Za-z_]\w*)\s*=.*?\|\s*where\s+\k<name>\b")]
    private static partial Regex CalculatedFilter();
    [GeneratedRegex("""(?i)\b(?:ProcessCommandLine|InitiatingProcessCommandLine)\s*==\s*["']""")]
    private static partial Regex ExactCommandLine();
    [GeneratedRegex(@"(?i)\|\s*join\s*(?!kind\s*=)")]
    private static partial Regex DefaultJoin();
    [GeneratedRegex(@"(?is)\|\s*join(?:\s+kind\s*=\s*\w+)?\s*\((.*?)\)\s*on\b")]
    private static partial Regex JoinBranch();
    [GeneratedRegex(@"(?i)\b(?:parse_json|extractjson|extract|replace|trim|substring|tolower|toupper)\s*\(|matches\s+regex")]
    private static partial Regex ExpensiveOperation();
    [GeneratedRegex("""(?i)\bActionType\s*(?:==|=~)\s*["']([^"']+)["']""")]
    private static partial Regex ActionTypeLiteral();
    [GeneratedRegex(@"(?is)GetAnomalousBehaviorsAbout\s*\(\s*dynamic\s*\(\s*(\[.*?\])\s*\)\s*\)")]
    private static partial Regex AboutLiteral();
    [GeneratedRegex(@"(?i)\b(?:take|limit)\s+(?:\d+|[A-Za-z_]\w*)")]
    private static partial Regex DetectionRowLimit();
    [GeneratedRegex("""(?i)\bcontains(?:_cs)?\s*["'][A-Za-z0-9_]{4,}["']""")]
    private static partial Regex ContainsTerm();
    [GeneratedRegex("""(?i)\b(?<column>[A-Za-z_]\w*)\s*(?<operator>==|=~)\s*["'][^"']+["'](?:\s+or\s+\k<column>\s*\k<operator>\s*["'][^"']+["'])+""")]
    private static partial Regex RepeatedEquality();
    [GeneratedRegex(@"(?i)\bevaluate\s+bag_unpack\s*\([^\r\n|;]*\)(?!\s*:)")]
    private static partial Regex BagUnpackWithoutSchema();
    [GeneratedRegex(@"(?i)\|\s*where\b[^\r\n|;]*\bformat_datetime\s*\(")]
    private static partial Regex FormatDateTimePredicate();
    [GeneratedRegex("""(?i)(?:==|!=|<>)\s*["']\s*["']""")]
    private static partial Regex EmptyStringComparison();
    [GeneratedRegex("""(?i)\bhas(?:_cs)?\s*["'](?:\d{1,3}\.){3}\d{1,3}["']""")]
    private static partial Regex HasIpv4Literal();
    [GeneratedRegex(@"(?im)(?:^|\|)\s*(?:join\b|union\b)|\bexternaldata\s*\(")]
    private static partial Regex DefenderNrtMultiInput();
    [GeneratedRegex(@"(?m)//[^\r\n]*|/\*[\s\S]*?\*/")]
    private static partial Regex Comment();
    [GeneratedRegex("""(?i)\b(?:AccountName|AccountDisplayName|DeviceName|ApplicationName|AppDisplayName)\s*(?:==|=~|in~?)\s*["']""")]
    private static partial Regex DisplayNameIdentity();
    [GeneratedRegex(@"(?i)\|\s*where\b[^\r\n|;]*(?:!=|!~|!in\b|!contains\b|!has\b)")]
    private static partial Regex InlineExclusion();
    [GeneratedRegex(@"(?im)(?:^|\|)\s*(?:join\b|union\b)")]
    private static partial Regex SentinelNrtCorrelation();
}
