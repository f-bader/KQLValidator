using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace KqlValidator.Contracts;

[JsonConverter(typeof(JsonStringEnumConverter<KqlEnvironment>))]
public enum KqlEnvironment { Xdr, Sentinel, Unified }

[JsonConverter(typeof(JsonStringEnumConverter<LintProfile>))]
public enum LintProfile { General, Hunting, Detection }

[JsonConverter(typeof(JsonStringEnumConverter<KqlTarget>))]
public enum KqlTarget
{
    [JsonStringEnumMemberName("interactive-hunting")] InteractiveHunting,
    [JsonStringEnumMemberName("sentinel-scheduled")] SentinelScheduled,
    [JsonStringEnumMemberName("sentinel-nrt")] SentinelNrt,
    [JsonStringEnumMemberName("defender-scheduled")] DefenderScheduled,
    [JsonStringEnumMemberName("defender-nrt")] DefenderNrt,
}

[JsonConverter(typeof(JsonStringEnumConverter<DiagnosticSeverity>))]
public enum DiagnosticSeverity { Error, Warning, Information }

public sealed record ValidateRequest(
    [property: Required, MaxLength(65_536)] string Query,
    KqlEnvironment Environment,
    LintProfile Profile,
    ValidationExtensions? Extensions = null,
    KqlTarget? Target = null,
    LintOptions? Lint = null);

public sealed record LintOptions(
    bool Enabled = true,
    IReadOnlyList<string>? RuleSets = null,
    IReadOnlyList<string>? EnableRules = null,
    IReadOnlyList<string>? DisableRules = null,
    DiagnosticSeverity? MinimumSeverity = null);

public sealed record ValidationExtensions(
    IReadOnlyList<TableDeclaration>? Tables = null,
    IReadOnlyList<FunctionDeclaration>? Functions = null,
    IReadOnlyList<WatchlistDeclaration>? Watchlists = null);

public sealed record TableDeclaration(
    [property: Required] string Name,
    [property: Required] IReadOnlyList<ColumnDeclaration> Columns);

public sealed record ColumnDeclaration(
    [property: Required] string Name,
    [property: Required] string Type);

public sealed record FunctionDeclaration(
    [property: Required] string Name,
    IReadOnlyList<ParameterDeclaration>? Parameters,
    [property: Required] FunctionReturnDeclaration Returns);

public sealed record ParameterDeclaration(string Name, string Type, bool Optional = false);

public sealed record FunctionReturnDeclaration(
    string Kind,
    string? Type = null,
    IReadOnlyList<ColumnDeclaration>? Columns = null,
    bool PreserveInput = false);

public sealed record WatchlistDeclaration(string Name, IReadOnlyList<ColumnDeclaration> Columns);

public sealed record SourceSpan(int Start, int Length, int Line, int Column);

public sealed record ValidationDiagnostic(
    string RuleId,
    DiagnosticSeverity Severity,
    string Message,
    SourceSpan Span,
    string? DocumentationUrl = null,
    string Category = "semantic",
    string? RuleSet = null,
    string? SourceKind = null);

public sealed record LintRuleInfo(
    string RuleId,
    string Title,
    DiagnosticSeverity DefaultSeverity,
    string Category,
    string RuleSet,
    bool DefaultEnabled,
    string Description,
    string DocumentationUrl,
    string SourceKind,
    IReadOnlyList<string> Profiles,
    IReadOnlyList<string> Targets,
    IReadOnlyList<string> Environments);

public sealed record LintRuleListResponse(IReadOnlyList<LintRuleInfo> Items);

public sealed record ValidationResponse(
    bool Valid,
    string ServiceVersion,
    string SchemaVersion,
    IReadOnlyList<ValidationDiagnostic> Diagnostics,
    IReadOnlyList<ColumnDeclaration> OutputColumns,
    IReadOnlyList<string> ReferencedTables,
    IReadOnlyList<string> ReferencedColumns,
    IReadOnlyList<string> ReferencedFunctions,
    long ElapsedMilliseconds);

public sealed record EnvironmentSummary(
    string Name,
    string SchemaVersion,
    int TableCount,
    int FunctionCount,
    IReadOnlyList<string> Profiles);

public sealed record SchemaSearchResponse(
    IReadOnlyList<SchemaSearchResult> Items,
    string? NextCursor);

public sealed record SchemaSearchResult(
    string Kind,
    string Name,
    string? Parent,
    string? Type,
    string Environment);

public sealed record ServiceDiscovery(
    string Name,
    string Version,
    string Rest,
    string Mcp,
    string OpenApi,
    string Documentation);
