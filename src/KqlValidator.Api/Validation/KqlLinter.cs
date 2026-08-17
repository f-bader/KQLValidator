using System.Text.Json;
using System.Text.RegularExpressions;
using KqlValidator.Contracts;

namespace KqlValidator.Validation;

public sealed partial class KqlLinter
{
    private const string BestPractices = "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices";
    private const string AboutFunction = "https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-getanomalousbehaviorsabout-function";

    private static readonly HashSet<string> FallbackActionTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "AntivirusDetection", "AppControlCodeIntegrityPolicyBlocked", "AppControlExecutableAudited",
        "ConnectionFound", "CreateRemoteThreadApiCall", "FileCreated", "FileDeleted", "FileModified",
        "InboundConnectionAccepted", "LogonFailed", "LogonSuccess", "NetworkSignatureInspected",
        "OutboundConnectionAttempt", "ProcessCreated", "RegistryKeyCreated", "RegistryValueSet",
        "ScriptContent", "UsbDriveMount", "UserAccountAddedToLocalGroup"
    };

    private readonly IReadOnlySet<string> knownActionTypes;

    public KqlLinter(SchemaCatalog? catalog = null) =>
        knownActionTypes = catalog?.ActionTypes.Count > 0 ? catalog.ActionTypes : FallbackActionTypes;

    public IReadOnlyList<ValidationDiagnostic> Analyze(string query, KqlEnvironment environment, LintProfile profile)
    {
        var diagnostics = new List<ValidationDiagnostic>();
        var searchable = MaskComments(query);

        if (profile is LintProfile.Hunting or LintProfile.Detection)
        {
            Match(diagnostics, searchable, UnscopedSearch(), "KQLH001", DiagnosticSeverity.Warning,
                "Scope search to explicit tables with 'search in (...)'.", BestPractices);
            Match(diagnostics, searchable, WildcardSearch(), "KQLH002", DiagnosticSeverity.Warning,
                "Search specific columns instead of using a wildcard column search.", BestPractices);
            Match(diagnostics, searchable, UnscopedUnion(), "KQLH003", DiagnosticSeverity.Warning,
                "Avoid broad union queries; enumerate only the required tables and time-bound each branch.", BestPractices);
            Match(diagnostics, searchable, CaseTransformComparison(), "KQLH004", DiagnosticSeverity.Warning,
                "Avoid transforming every row with tolower()/toupper(); use an appropriate string operator when its matching semantics are acceptable.", BestPractices);
            Match(diagnostics, searchable, RegexUsage(), "KQLH005", DiagnosticSeverity.Information,
                "Prefer parse or parse_json for structured values; reserve regular expressions for cases that require them.", BestPractices);
            Match(diagnostics, searchable, ShortTerm(), "KQLH006", DiagnosticSeverity.Information,
                "Terms of three characters or fewer are not indexed and can consume more resources.", BestPractices);
            Match(diagnostics, searchable, CalculatedFilter(), "KQLH007", DiagnosticSeverity.Warning,
                "Filter source columns before calculating derived values when the query can preserve the same semantics.", BestPractices);
            Match(diagnostics, searchable, ExactCommandLine(), "KQLH008", DiagnosticSeverity.Warning,
                "Exact command-line comparisons are brittle; scope by process filename and match or parse independent command-line components.", BestPractices);
            Match(diagnostics, searchable, DefaultJoin(), "KQLH009", DiagnosticSeverity.Information,
                "The default join flavor is innerunique and deduplicates the left side; specify kind=inner when every left-side row must be retained.", BestPractices);

            AddTimeFilterDiagnostics(diagnostics, searchable);
            AddLateFilterDiagnostics(diagnostics, searchable);
            AddUnboundedResultDiagnostic(diagnostics, searchable);
            AddProcessIdDiagnostic(diagnostics, searchable);
        }

        AddActionTypeDiagnostics(diagnostics, searchable);
        AddAnomalousBehaviorLiteralDiagnostics(diagnostics, searchable);
        AddDetectionTextDiagnostics(diagnostics, searchable, environment, profile);
        return diagnostics;
    }

    private static void AddTimeFilterDiagnostics(List<ValidationDiagnostic> diagnostics, string query)
    {
        var hasXdrTable = Regex.IsMatch(query, @"(?im)^\s*(Device|Email|Identity|CloudApp|Alert|Behavior)[A-Za-z]+\b");
        var hasTimeFilter = Regex.IsMatch(query, @"(?i)\b(?:Timestamp|TimeGenerated)\s*(?:>|>=|between|in)\b");
        if (hasXdrTable && !hasTimeFilter)
            diagnostics.Add(Diagnostic(query, 0, "KQLH010", DiagnosticSeverity.Warning,
                "Add an early Timestamp or TimeGenerated filter to bound scanned data.", BestPractices));

        foreach (Match join in JoinBranch().Matches(query))
        {
            if (!Regex.IsMatch(join.Value, @"(?i)\b(?:Timestamp|TimeGenerated)\s*(?:>|>=|between|in)\b"))
                diagnostics.Add(Diagnostic(query, join.Index, "KQLH011", DiagnosticSeverity.Warning,
                    "Apply a time filter inside this join branch as well as on the left input.", BestPractices, join.Length));
        }
    }

    private static void AddLateFilterDiagnostics(List<ValidationDiagnostic> diagnostics, string query)
    {
        var expensive = ExpensiveOperation().Match(query);
        if (!expensive.Success)
            return;
        var filter = Regex.Match(query, @"(?i)\|\s*where\b");
        if (!filter.Success || filter.Index > expensive.Index)
            diagnostics.Add(Diagnostic(query, expensive.Index, "KQLH012", DiagnosticSeverity.Warning,
                "Apply selective filters before parsing, extraction, regex, or row-wise string transformations.", BestPractices, expensive.Length));
    }

    private static void AddUnboundedResultDiagnostic(List<ValidationDiagnostic> diagnostics, string query)
    {
        if (!Regex.IsMatch(query, @"(?i)\b(?:take|limit|top|summarize|count)\b"))
            diagnostics.Add(Diagnostic(query, Math.Max(0, query.Length - 1), "KQLH013", DiagnosticSeverity.Information,
                "For exploratory hunting, use take, limit, top, count, or an aggregation to avoid unexpectedly large results.", BestPractices));
    }

    private static void AddProcessIdDiagnostic(List<ValidationDiagnostic> diagnostics, string query)
    {
        var pid = Regex.Match(query, @"(?i)\b(?:ProcessId|InitiatingProcessId)\b");
        if (pid.Success && !Regex.IsMatch(query, @"(?i)\b(?:ProcessUniqueId|InitiatingProcessUniqueId|ProcessCreationTime|InitiatingProcessCreationTime)\b"))
            diagnostics.Add(Diagnostic(query, pid.Index, "KQLH014", DiagnosticSeverity.Warning,
                "Process IDs are reused; identify a process with its unique ID or creation time.", BestPractices, pid.Length));
    }

    private void AddActionTypeDiagnostics(List<ValidationDiagnostic> diagnostics, string query)
    {
        foreach (Match match in ActionTypeLiteral().Matches(query))
        {
            var value = match.Groups[1].Value;
            if (!knownActionTypes.Contains(value))
                diagnostics.Add(Diagnostic(query, match.Groups[1].Index, "KQLX001", DiagnosticSeverity.Warning,
                    $"'{value}' is not in the bundled XDR ActionType catalog; verify it against the current schema.",
                    "https://xdrinternals.com/", match.Groups[1].Length));
        }
    }

    private static void AddAnomalousBehaviorLiteralDiagnostics(List<ValidationDiagnostic> diagnostics, string query)
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
                diagnostics.Add(Diagnostic(query, invocation.Index, "KQLX002", DiagnosticSeverity.Error,
                    $"Invalid GetAnomalousBehaviorsAbout literal: {exception.Message}", AboutFunction, invocation.Length));
            }
        }
    }

    private static void AddDetectionTextDiagnostics(List<ValidationDiagnostic> diagnostics, string query, KqlEnvironment environment, LintProfile profile)
    {
        if (profile != LintProfile.Detection)
            return;

        if (environment == KqlEnvironment.Xdr)
        {
            Match(diagnostics, query, ExactCommandLine(), "KQLD005", DiagnosticSeverity.Warning,
                "Detection command-line logic should tolerate benign quoting, spacing, and argument ordering differences.", BestPractices);
        }
    }

    private static void Match(List<ValidationDiagnostic> diagnostics, string query, Regex regex, string id,
        DiagnosticSeverity severity, string message, string? documentation)
    {
        foreach (Match match in regex.Matches(query))
            diagnostics.Add(Diagnostic(query, match.Index, id, severity, message, documentation, match.Length));
    }

    private static ValidationDiagnostic Diagnostic(string query, int start, string id, DiagnosticSeverity severity,
        string message, string? documentation = null, int length = 1) =>
        new(id, severity, message, Span(query, start, length), documentation,
            id.StartsWith("KQLD", StringComparison.Ordinal) ? "detection" : "lint");

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
}
