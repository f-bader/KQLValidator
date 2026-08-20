using System.Text.Json;
using System.Text.RegularExpressions;
using KqlValidator.Contracts;

namespace KqlValidator.Validation;

public sealed partial class KqlLinter
{
    private const int RegexTimeoutMilliseconds = 250;
    private const int MaxLintDiagnostics = 500;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(RegexTimeoutMilliseconds);
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

    public IReadOnlyList<ValidationDiagnostic> Analyze(
        ValidateRequest request,
        LintPolicy policy,
        CancellationToken cancellationToken = default)
    {
        try
        {
            return AnalyzeCore(request, policy, cancellationToken);
        }
        catch (RegexMatchTimeoutException)
        {
            throw new RequestValidationException("query", "Query exceeds the lint analysis complexity limit.");
        }
    }

    private IReadOnlyList<ValidationDiagnostic> AnalyzeCore(
        ValidateRequest request,
        LintPolicy policy,
        CancellationToken cancellationToken)
    {
        var diagnostics = new List<ValidationDiagnostic>();
        var query = request.Query;
        var searchable = MaskComments(query);

        cancellationToken.ThrowIfCancellationRequested();
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

        cancellationToken.ThrowIfCancellationRequested();
        AddTimeFilterDiagnostics(diagnostics, policy, searchable);
        AddLateFilterDiagnostics(diagnostics, policy, searchable);
        AddUnboundedResultDiagnostic(diagnostics, policy, searchable);
        AddProcessIdDiagnostic(diagnostics, policy, searchable);
        AddActionTypeDiagnostics(diagnostics, policy, searchable);
        AddAnomalousBehaviorLiteralDiagnostics(diagnostics, policy, searchable);
        AddDetectionTextDiagnostics(diagnostics, policy, searchable);
        AddWatchlistColumnDiagnostics(diagnostics, policy, searchable);
        AddMicrosoftKustoDiagnostics(diagnostics, policy, searchable);
        cancellationToken.ThrowIfCancellationRequested();
        AddTargetDiagnostics(diagnostics, policy, query, searchable);
        AddCommunityDiagnostics(diagnostics, policy, query, searchable);
        return diagnostics;
    }

    private void AddTimeFilterDiagnostics(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query)
    {
        var hasXdrTable = IsMatch(query, @"(?im)^\s*(Device|Email|Identity|CloudApp|Alert|Behavior)[A-Za-z]+\b");
        var hasTimeFilter = IsMatch(query, @"(?i)\b(?:Timestamp|TimeGenerated)\s*(?:>|>=|between|in)\b");
        if (hasXdrTable && !hasTimeFilter)
            Add(diagnostics, policy, query, "KQLH010",
                "Add an early Timestamp or TimeGenerated filter to bound scanned data.", 0);

        foreach (Match join in JoinBranch().Matches(query))
        {
            if (!IsMatch(join.Value, @"(?i)\b(?:Timestamp|TimeGenerated)\s*(?:>|>=|between|in)\b"))
                Add(diagnostics, policy, query, "KQLH011",
                    "Apply a time filter inside this join branch as well as on the left input.", join.Index, join.Length);
        }
    }

    private void AddLateFilterDiagnostics(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query)
    {
        var expensive = ExpensiveOperation().Match(query);
        if (!expensive.Success)
            return;
        var filter = Find(query, @"(?i)\|\s*where\b");
        if (!filter.Success || filter.Index > expensive.Index)
            Add(diagnostics, policy, query, "KQLH012",
                "Apply selective filters before parsing, extraction, regex, or row-wise string transformations.", expensive.Index, expensive.Length);
    }

    private void AddUnboundedResultDiagnostic(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query)
    {
        if (!IsMatch(query, @"(?i)\b(?:take|limit|top|summarize|count)\b"))
            Add(diagnostics, policy, query, "KQLH013",
                "For exploratory hunting, use take, limit, top, count, or an aggregation to avoid unexpectedly large results.", Math.Max(0, query.Length - 1));
    }

    private void AddProcessIdDiagnostic(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query)
    {
        var pid = Find(query, @"(?i)\b(?:ProcessId|InitiatingProcessId)\b");
        if (pid.Success && !IsMatch(query, @"(?i)\b(?:ProcessUniqueId|InitiatingProcessUniqueId|ProcessCreationTime|InitiatingProcessCreationTime)\b"))
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
                    $"Invalid GetAnomalousBehaviorsAbout literal: {exception.Message}. Use dynamic([{{\"Kind\":\"Account\",\"Value\":\"example\"}}]) with one to three objects; Kind is required and Value is an optional string.", invocation.Index, invocation.Length);
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

    private void AddWatchlistColumnDiagnostics(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query)
    {
        foreach (Match watchlist in GetWatchlistPipeline().Matches(query))
        {
            var pipeline = watchlist.Groups["pipeline"];
            foreach (var column in OptionalWatchlistColumns)
            {
                if (HasColumnIfExists(pipeline.Value, column)) continue;
                var usage = WatchlistColumnUsage(column).Match(MaskStringLiterals(pipeline.Value));
                if (!usage.Success) continue;

                var preferred = IsSimpleIdentifier(column)
                    ? $"| extend {column} = column_ifexists('{column}', '')"
                    : $"| extend ['{column}'] = column_ifexists('{column}', '')";
                Add(diagnostics, policy, query, "KQLS002",
                    $"'{column}' is not native to the Watchlist table and can be absent at deployment. Add {preferred} before referencing it.",
                    pipeline.Index + usage.Index, usage.Length);
            }
        }
    }

    private static bool HasColumnIfExists(string pipeline, string column) =>
        IsMatch(pipeline, $"(?i)\\bcolumn_ifexists\\s*\\(\\s*['\"]{Regex.Escape(column)}['\"]\\s*,");

    private static Regex WatchlistColumnUsage(string column) => new(
        IsSimpleIdentifier(column)
            ? $"(?i)(?<!['\"])\\b{Regex.Escape(column)}\\b"
            : $"(?i)\\[\\s*['\"]{Regex.Escape(column)}['\"]\\s*\\]",
        RegexOptions.CultureInvariant, RegexTimeout);

    private static bool IsSimpleIdentifier(string value) => IsMatch(value, "^[A-Za-z_]\\w*$");

    private static readonly string[] OptionalWatchlistColumns =
    [
        "Asset Type", "Asset Id", "Asset Name", "Asset FQDN", "IP Address", "User Identifier", "User AAD Object Id",
        "User On-Prem Sid", "User Principal Name", "IP Subnet", "Range Name", "UserState", "Notification date",
        "Termination date", "Employee Id", "Email", "Associated Privileged Account ID", "Associated Privileged Account",
        "Service Identifier", "Service AAD Object Id", "Service On-Prem Sid", "Service Principal Name", "Owner User Identifier",
        "Owner User AAD Object Id", "Owner User On-Prem Sid", "Owner User Principal Name", "Tags",
    ];

    private void Match(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query, Regex regex, string id, string message)
    {
        var severity = rules.Get(id).DefaultSeverity;
        if (!policy.IsEnabled(id, severity)) return;
        foreach (Match match in regex.Matches(query))
        {
            if (diagnostics.Count >= MaxLintDiagnostics) break;
            diagnostics.Add(rules.CreateDiagnostic(query, id, message, match.Index, match.Length));
        }
    }

    private void Add(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query, string id,
        string message, int start, int length = 1)
    {
        var severity = rules.Get(id).DefaultSeverity;
        if (diagnostics.Count < MaxLintDiagnostics && policy.IsEnabled(id, severity))
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
                $"Sentinel analytics rule queries cannot exceed 10,000 characters; this query is {originalQuery.Length} characters. Shorten it or move large literal lists and pattern data into a watchlist or other managed external source.", 10_000,
                originalQuery.Length - 10_000);

        Match(diagnostics, policy, searchableQuery, DefenderNrtMultiInput(), "KQLN001",
            "Defender continuous NRT rules do not support join, union, or externaldata. Rewrite this as a single-input query, or use a scheduled detection when multi-input correlation is required.");

        foreach (Match comment in Comment().Matches(originalQuery))
            Add(diagnostics, policy, originalQuery, "KQLN002",
                "Defender continuous NRT rules do not support comments in deployed KQL. Remove the comment, or use a scheduled target if comments must remain.", comment.Index, comment.Length);
    }

    private void AddCommunityDiagnostics(
        List<ValidationDiagnostic> diagnostics, LintPolicy policy, string originalQuery, string searchableQuery)
    {
        Match(diagnostics, policy, searchableQuery, DisplayNameIdentity(), "KQLQ001",
            "Prefer a stable identifier over this display-name comparison when the source exposes one.");

        if (IsMatch(searchableQuery, @"(?i)\bDeviceProcessEvents\b") &&
            IsMatch(searchableQuery, @"(?i)\b(?:InitiatingProcess)?FileName\s*(?:==|=~|in~?)") &&
            !IsMatch(searchableQuery, @"(?i)\b(?:Initiating)?ProcessVersionInfoOriginalFileName\b"))
        {
            var fileName = Find(searchableQuery, @"(?i)\b(?:InitiatingProcess)?FileName\b");
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

    private static bool IsMatch(string input, string pattern) =>
        Regex.IsMatch(input, pattern, RegexOptions.CultureInvariant, RegexTimeout);

    private static Match Find(string input, string pattern) =>
        Regex.Match(input, pattern, RegexOptions.CultureInvariant, RegexTimeout);

    private static string MaskComments(string query) => Regex.Replace(
        query, @"(?m)//[^\r\n]*|/\*[\s\S]*?\*/", m => new string(' ', m.Length), RegexOptions.CultureInvariant, RegexTimeout);

    private static string MaskStringLiterals(string query) => Regex.Replace(
        query,
        "(?<!\\[)'(?:''|[^'])*'|(?<!\\[)\"(?:\"\"|[^\"])*\"",
        match => new string(' ', match.Length), RegexOptions.CultureInvariant, RegexTimeout);

    [GeneratedRegex(@"(?im)(?:^|;)\s*search\s+(?!in\s*\()", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex UnscopedSearch();
    [GeneratedRegex(@"(?i)\b(?:search|where)\b[^\r\n|;]*\*\s*(?:has|contains|matches|==|=~)", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex WildcardSearch();
    [GeneratedRegex(@"(?im)(?:^|\|)\s*union\s+(?:\*|withsource\s*=)", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex UnscopedUnion();
    [GeneratedRegex(@"(?i)\b(?:tolower|toupper)\s*\([^)]*\)\s*(?:==|=~|in~?)", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex CaseTransformComparison();
    [GeneratedRegex(@"(?i)\b(?:matches\s+regex|extract(?:_all)?\s*\()", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex RegexUsage();
    [GeneratedRegex("""(?i)\b(?:has|contains|==|=~)\s*["']\w{1,3}["']""", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex ShortTerm();
    [GeneratedRegex(@"(?is)\|\s*extend\s+(?<name>[A-Za-z_]\w*)\s*=.*?\|\s*where\s+\k<name>\b", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex CalculatedFilter();
    [GeneratedRegex("""(?i)\b(?:ProcessCommandLine|InitiatingProcessCommandLine)\s*==\s*["']""", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex ExactCommandLine();
    [GeneratedRegex(@"(?i)\|\s*join\b(?!\s+kind\s*=)", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex DefaultJoin();
    [GeneratedRegex(@"(?is)\|\s*join(?:\s+kind\s*=\s*\w+)?\s*\((.*?)\)\s*on\b", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex JoinBranch();
    [GeneratedRegex(@"(?i)\b(?:parse_json|extractjson|extract|replace|trim|substring|tolower|toupper)\s*\(|matches\s+regex", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex ExpensiveOperation();
    [GeneratedRegex("""(?i)\bActionType\s*(?:==|=~)\s*["']([^"']+)["']""", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex ActionTypeLiteral();
    [GeneratedRegex(@"(?is)GetAnomalousBehaviorsAbout\s*\(\s*dynamic\s*\(\s*(\[.*?\])\s*\)\s*\)", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex AboutLiteral();
    [GeneratedRegex(@"(?i)\b(?:take|limit)\s+(?:\d+|[A-Za-z_]\w*)", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex DetectionRowLimit();
    [GeneratedRegex("""(?i)\bcontains(?:_cs)?\s*["'][A-Za-z0-9_]{4,}["']""", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex ContainsTerm();
    [GeneratedRegex("""(?i)\b(?<column>[A-Za-z_]\w*)\s*(?<operator>==|=~)\s*["'][^"']+["'](?:\s+or\s+\k<column>\s*\k<operator>\s*["'][^"']+["'])+""", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex RepeatedEquality();
    [GeneratedRegex(@"(?i)\bevaluate\s+bag_unpack\s*\([^\r\n|;]*\)(?!\s*:)", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex BagUnpackWithoutSchema();
    [GeneratedRegex(@"(?i)\|\s*where\b[^\r\n|;]*\bformat_datetime\s*\(", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex FormatDateTimePredicate();
    [GeneratedRegex("""(?i)(?:==|!=|<>)\s*["']\s*["']""", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex EmptyStringComparison();
    [GeneratedRegex("""(?i)\bhas(?:_cs)?\s*["'](?:\d{1,3}\.){3}\d{1,3}["']""", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex HasIpv4Literal();
    [GeneratedRegex(@"(?im)(?:^|\|)\s*(?:join\b|union\b)|\bexternaldata\s*\(", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex DefenderNrtMultiInput();
    [GeneratedRegex(@"(?m)//[^\r\n]*|/\*[\s\S]*?\*/", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex Comment();
    [GeneratedRegex("""(?i)\b(?:AccountName|AccountDisplayName|DeviceName|ApplicationName|AppDisplayName)\s*(?:==|=~|in~?)\s*["']""", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex DisplayNameIdentity();
    [GeneratedRegex(@"(?i)\|\s*where\b[^\r\n|;]*(?:!=|!~|!in\b|!contains\b|!has\b)", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex InlineExclusion();
    [GeneratedRegex(@"(?is)_GetWatchlist\s*\([^)]*\)(?<pipeline>.*?)(?=;|$)", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex GetWatchlistPipeline();
    [GeneratedRegex(@"(?im)(?:^|\|)\s*(?:join\b|union\b)", RegexOptions.None, RegexTimeoutMilliseconds)]
    private static partial Regex SentinelNrtCorrelation();
}
