using System.Text.RegularExpressions;
using KqlValidator.Contracts;

namespace KqlValidator.Validation;

/// <summary>Applies the Defender continuous-NRT constraints after semantic table/column binding.</summary>
public sealed class DefenderNrtValidator
{
    private const int RegexTimeoutMilliseconds = 250;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(RegexTimeoutMilliseconds);

    private static readonly HashSet<string> XdrTables = new(StringComparer.OrdinalIgnoreCase)
    {
        "AlertEvidence", "CloudAppEvents", "DeviceEvents", "DeviceFileCertificateInfo", "DeviceFileEvents",
        "DeviceImageLoadEvents", "DeviceLogonEvents", "DeviceNetworkEvents", "DeviceNetworkInfo", "DeviceInfo",
        "DeviceProcessEvents", "DeviceRegistryEvents", "EmailAttachmentInfo", "EmailEvents", "EmailPostDeliveryEvents",
        "EmailUrlInfo", "IdentityDirectoryEvents", "IdentityLogonEvents", "IdentityQueryEvents", "UrlClickEvents",
    };

    private static readonly HashSet<string> UnifiedOnlyTables = new(StringComparer.OrdinalIgnoreCase)
    {
        // The Microsoft NRT table list prints "ABAPAuditLog_C", a truncation of the SAP
        // connector table ABAPAuditLog_CL (docs feedback has been submitted).
        "ABAPAuditLog_CL", "ABAPChangeDocsLog_CL", "AuditLogs", "AWSCloudTrail", "AWSGuardDuty", "AzureActivity",
        "CommonSecurityLog", "GCPAuditLogs", "MicrosoftGraphActivityLogs", "OfficeActivity", "Okta_CL", "OktaV2_CL",
        "ProofpointPOD", "ProofPointTAPClicksPermitted_CL", "ProofPointTAPMessagesDelivered_CL", "SecurityAlert",
        "SecurityEvent", "SigninLogs",
    };

    private static readonly IReadOnlySet<string> AllowedPipeOperators = AzureMonitorTransformationFeatures.AllowedPipeOperators;

    // This mirrors the feature families enumerated by the Microsoft page linked from the NRT documentation.
    private static readonly IReadOnlySet<string> AllowedFunctions = AzureMonitorTransformationFeatures.AllowedFunctions;

    private static readonly IReadOnlySet<string> ScalarTypes = AzureMonitorTransformationFeatures.ScalarTypes;

    // These operators use parentheses around their operands, so the simple function-call
    // matcher below would otherwise misidentify them as unsupported scalar functions.
    private static readonly IReadOnlySet<string> ParenthesizedOperators = AzureMonitorTransformationFeatures.ParenthesizedOperators;

    private static readonly Regex Comment = new(@"(?m)//[^\r\n]*|/\*[\s\S]*?\*/", RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex StringLiteral = new("""@?(?:"(?:""|\\.|[^"])*"|'(?:''|\\.|[^'])*')""", RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex MultiInput = new(@"(?im)(?:^|[;|])\s*(?:join\b|union\b)|\bexternaldata\s*\(", RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex PipeOperator = new(@"(?im)\|\s*(?<operator>[A-Za-z][A-Za-z-]*)\b", RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex FunctionCall = new(@"\b(?<function>[A-Za-z_]\w*)\s*\(", RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex LocalFunction = new(@"(?im)(?:^|;)\s*let\s+(?<name>[A-Za-z_]\w*)\s*=\s*\((?<parameters>[^)]*)\)\s*\{", RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex RegexRhs = new("""(?is)\bmatches\s+regex\s+(?<value>@?(?:"(?:""|\\.|[^"])*"|'(?:''|\\.|[^'])*')|[A-Za-z_]\w*|[^\s|;]+)""", RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex UnsupportedStringOperator = new(@"(?i)\b(?:contains_any|has_all|has_any|hasprefix|hassuffix|in~|matches\b(?!\s+regex)|search)\b", RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex Alias = new(@"(?im)\|\s*(?:extend|project)\s+(?<alias>[A-Za-z_]\w*)\s*=\s*(?<source>Timestamp|TimeGenerated)\b", RegexOptions.CultureInvariant, RegexTimeout);
    private static readonly Regex WhereClause = new(@"(?im)\|\s*where\b(?<predicate>[^|;]*)", RegexOptions.CultureInvariant, RegexTimeout);

    private readonly LintRuleCatalog rules;

    public DefenderNrtValidator(LintRuleCatalog rules) => this.rules = rules;

    public IReadOnlyList<ValidationDiagnostic> Analyze(
        ValidateRequest request,
        LintPolicy policy,
        IReadOnlyList<string> referencedTables,
        IReadOnlyList<string> referencedColumns,
        CancellationToken cancellationToken = default)
    {
        var target = LintRuleCatalog.ResolveTarget(request);
        if (target is not (KqlTarget.DefenderNrt or KqlTarget.SentinelNrt))
            return [];

        var diagnostics = new List<ValidationDiagnostic>();
        var query = request.Query;
        var searchable = MaskCommentsAndStrings(query);

        // Sentinel NRT has separate constraints. The shared time-filter warning is
        // still useful because ingestion-time and event-time predicates can skip events.
        if (target == KqlTarget.SentinelNrt)
        {
            AddTimeFilterDiagnostics(diagnostics, policy, query, searchable, cancellationToken);
            return diagnostics;
        }

        AddTableDiagnostics(diagnostics, policy, query, referencedTables, referencedColumns, request.Environment);
        AddStructuralDiagnostics(diagnostics, policy, query, searchable, cancellationToken);
        AddFeatureDiagnostics(diagnostics, policy, query, searchable, cancellationToken);
        AddRegexDiagnostics(diagnostics, policy, query, cancellationToken);
        AddTimeFilterDiagnostics(diagnostics, policy, query, searchable, cancellationToken);
        return diagnostics;
    }

    private void AddTableDiagnostics(
        List<ValidationDiagnostic> diagnostics,
        LintPolicy policy,
        string query,
        IReadOnlyList<string> referencedTables,
        IReadOnlyList<string> referencedColumns,
        KqlEnvironment environment)
    {
        if (referencedTables.Count != 1)
        {
            var names = referencedTables.Count == 0 ? "no database table" : string.Join(", ", referencedTables);
            Add(diagnostics, policy, query, "KQLN001",
                $"Defender continuous NRT rules must reference exactly one table; this query references {names}.", 0);
        }

        var allowed = new HashSet<string>(XdrTables, StringComparer.OrdinalIgnoreCase);
        if (environment == KqlEnvironment.Unified)
            allowed.UnionWith(UnifiedOnlyTables);

        foreach (var table in referencedTables.Where(table => !allowed.Contains(table)))
        {
            var span = FindIdentifier(query, table);
            Add(diagnostics, policy, query, "KQLN003",
                $"'{table}' is not supported by Defender continuous NRT rules in the {environment.ToString().ToLowerInvariant()} environment.", span.Start, span.Length);
        }

        if (referencedTables.Contains("EmailEvents", StringComparer.OrdinalIgnoreCase))
        {
            foreach (var column in referencedColumns.Where(column => column is "LatestDeliveryLocation" or "LatestDeliveryAction"))
            {
                var span = FindIdentifier(query, column);
                Add(diagnostics, policy, query, "KQLN006",
                    $"EmailEvents column '{column}' is not supported by Defender continuous NRT rules.", span.Start, span.Length);
            }
        }
    }

    private void AddStructuralDiagnostics(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query, string searchable, CancellationToken cancellationToken)
    {
        foreach (Match match in MultiInput.Matches(searchable))
        {
            cancellationToken.ThrowIfCancellationRequested();
            Add(diagnostics, policy, query, "KQLN001",
                "Defender continuous NRT rules do not support join, union, or externaldata. Rewrite this as a single-input query or use a scheduled detection.", match.Index, match.Length);
        }

        foreach (Match match in Comment.Matches(MaskStringLiterals(query)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            Add(diagnostics, policy, query, "KQLN002",
                "Defender continuous NRT rules do not support comments in deployed KQL. Remove the comment or use a scheduled target if comments must remain.", match.Index, match.Length);
        }
    }

    private void AddFeatureDiagnostics(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query, string searchable, CancellationToken cancellationToken)
    {
        foreach (Match match in PipeOperator.Matches(searchable))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var operation = match.Groups["operator"].Value;
            if (!AllowedPipeOperators.Contains(operation))
                Add(diagnostics, policy, query, "KQLN004",
                    $"'{operation}' is not a supported KQL tabular operator for Defender continuous NRT rules.", match.Index, match.Length);
        }

        foreach (Match match in UnsupportedStringOperator.Matches(searchable))
        {
            cancellationToken.ThrowIfCancellationRequested();
            Add(diagnostics, policy, query, "KQLN004",
                $"'{match.Value}' is not a supported KQL string operator for Defender continuous NRT rules.", match.Index, match.Length);
        }

        var localFunctions = CollectLocalScalarFunctions(diagnostics, policy, query, cancellationToken);
        foreach (Match match in FunctionCall.Matches(searchable))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var function = match.Groups["function"].Value;
            if (AllowedFunctions.Contains(function) || localFunctions.Contains(function) || ParenthesizedOperators.Contains(function))
                continue;
            Add(diagnostics, policy, query, "KQLN004",
                $"'{function}()' is not a supported KQL scalar function for Defender continuous NRT rules.", match.Index, match.Length);
        }
    }

    private HashSet<string> CollectLocalScalarFunctions(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query, CancellationToken cancellationToken)
    {
        var functions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in LocalFunction.Matches(MaskCommentsAndStrings(query)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var parameters = match.Groups["parameters"].Value;
            var scalar = parameters.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .All(parameter => parameter.Split(':', 2) is [_, var type] && ScalarTypes.Contains(type.Trim()));
            if (scalar)
                functions.Add(match.Groups["name"].Value);
            else
                Add(diagnostics, policy, query, "KQLN004",
                    "Defender continuous NRT rules support user-defined functions only when every argument is scalar.", match.Index, match.Length);
        }
        return functions;
    }

    private void AddRegexDiagnostics(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query, CancellationToken cancellationToken)
    {
        foreach (Match match in RegexRhs.Matches(MaskComments(query)))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var value = match.Groups["value"];
            if (IsNrtRegexLiteral(value.Value))
                continue;
            Add(diagnostics, policy, query, "KQLN005",
                "The right side of matches regex must be a correctly escaped KQL string literal for Defender continuous NRT rules.", value.Index, value.Length);
        }
    }

    private void AddTimeFilterDiagnostics(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query, string searchable, CancellationToken cancellationToken)
    {
        var temporalNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Timestamp", "TimeGenerated", "ingestion_time" };
        foreach (Match alias in Alias.Matches(searchable))
        {
            cancellationToken.ThrowIfCancellationRequested();
            temporalNames.Add(alias.Groups["alias"].Value);
        }

        var alternatives = string.Join("|", temporalNames.Select(Regex.Escape).OrderByDescending(name => name.Length));
        var temporal = new Regex($@"(?i)\b(?<field>{alternatives})\b\s*(?:\(\s*\))?\s*(?:(?:==|=~|!=|!~|<=|>=|=|<|>)\s*|(?:between|in)\b)", RegexOptions.CultureInvariant, RegexTimeout);
        foreach (Match clause in WhereClause.Matches(searchable))
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (Match predicate in temporal.Matches(clause.Groups["predicate"].Value))
            {
                var start = clause.Groups["predicate"].Index + predicate.Index;
                Add(diagnostics, policy, query, "KQLN007",
                    "Time filters can skip qualifying events in continuous NRT rules; remove this temporal predicate or use a scheduled detection.", start, predicate.Length);
            }
        }
    }

    private void Add(List<ValidationDiagnostic> diagnostics, LintPolicy policy, string query, string ruleId, string message, int start, int length = 1)
    {
        var diagnostic = rules.CreateDiagnostic(query, ruleId, message, start, Math.Max(1, length));
        if (policy.IsEnabled(ruleId, diagnostic.Severity) && diagnostics.Count < 500)
            diagnostics.Add(diagnostic);
    }

    private static bool IsNrtRegexLiteral(string value)
    {
        if (value.Length < 2) return false;
        var verbatim = value[0] == '@';
        var offset = verbatim ? 1 : 0;
        if (value.Length < offset + 2 || (value[offset] is not '\'' and not '\"')) return false;
        if (verbatim) return true;

        var body = value[(offset + 1)..^1];
        for (var index = 0; index < body.Length; index++)
        {
            if (body[index] != '\\') continue;
            if (++index >= body.Length || body[index] != '\\') return false;
        }
        return true;
    }

    private static (int Start, int Length) FindIdentifier(string query, string identifier)
    {
        // An instance regex keeps per-request patterns out of the process-wide static regex cache.
        var match = new Regex($@"(?i)\b{Regex.Escape(identifier)}\b", RegexOptions.CultureInvariant, RegexTimeout).Match(query);
        return match.Success ? (match.Index, match.Length) : (0, 1);
    }

    private static string MaskCommentsAndStrings(string query) => MaskStringLiterals(MaskComments(query));

    private static string MaskComments(string query) => Comment.Replace(query, match => new string(' ', match.Length));

    private static string MaskStringLiterals(string query) => StringLiteral.Replace(query, match => new string(' ', match.Length));
}
