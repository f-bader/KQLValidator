using System.ComponentModel;
using KqlValidator.Contracts;
using KqlValidator.Operational;
using KqlValidator.Validation;
using ModelContextProtocol.Server;

namespace KqlValidator.Mcp;

[McpServerToolType]
public sealed class KqlTools
{
    [McpServerTool(Name = "validate_kql", Title = "Validate KQL", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Statically validate and lint a KQL query against Microsoft Defender XDR, Sentinel, or their unified schema. The query is never executed.")]
    public static Task<ValidationResponse> ValidateKql(
        AnalysisExecutor executor,
        [Description("KQL query, limited to 64 KiB.")] string query,
        [Description("Schema environment: xdr, sentinel, or unified.")] KqlEnvironment environment,
        [Description("Lint profile: general, hunting, or detection.")] LintProfile profile,
        [Description("Optional request-scoped table, function, and watchlist declarations.")] ValidationExtensions? extensions = null,
        CancellationToken cancellationToken = default) =>
        executor.ExecuteAsync(new ValidateRequest(query, environment, profile, extensions), cancellationToken);

    [McpServerTool(Name = "list_kql_environments", Title = "List KQL environments", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("List the built-in KQL schema environments and their versions.")]
    public static IReadOnlyList<EnvironmentSummary> ListKqlEnvironments(SchemaQueryService schemas) => schemas.ListEnvironments();

    [McpServerTool(Name = "search_kql_schema", Title = "Search KQL schema", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Search tables, columns, and functions in a KQL environment.")]
    public static SchemaSearchResponse SearchKqlSchema(
        SchemaQueryService schemas,
        KqlEnvironment environment,
        string? query = null,
        [Description("Optional kind: table, column, or function.")] string? kind = null,
        [Description("Page size from 1 to 100.")] int limit = 50,
        string? cursor = null) => schemas.Search(environment, query, kind, limit, cursor);

    [McpServerTool(Name = "get_kql_table", Title = "Get KQL table", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Get the typed columns for one table in a KQL environment.")]
    public static SchemaTable? GetKqlTable(SchemaQueryService schemas, KqlEnvironment environment, string table) =>
        schemas.GetTable(environment, table);
}
