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
    [Description("Use when writing, editing, debugging, or reviewing Microsoft Defender XDR or Sentinel KQL queries, advanced hunting, or detection rules. Statically checks syntax, schema, and lint rules without executing the query. Returns valid, diagnostics with source spans, and inferred output columns; a successful tool call can return valid=false. For DCR ingestion transformations, use validate_azure_monitor_transformation instead.")]
    public static Task<ValidationResponse> ValidateKql(
        IServiceProvider services,
        [Description("KQL query text, limited to 65,536 characters.")] string query,
        [Description("Schema environment: xdr for Microsoft Defender XDR, sentinel for Microsoft Sentinel, unified for the combined XDR and Sentinel catalog. Choose the intended platform; list_kql_environments discovers available catalogs and versions.")] KqlEnvironment environment,
        [Description("Use general for general-purpose queries, hunting for interactive investigations, or detection for alert/detection rule queries.")] LintProfile profile,
        [Description("Optional request-scoped declarations for known custom tables, function signatures/returns, and watchlist aliases with typed columns. Supply actual schemas missing from the effective catalog; do not invent declarations to silence errors. Does not persist changes.")] ValidationExtensions? extensions = null,
        [Description("Optional target: interactive-hunting requires hunting; sentinel-scheduled and sentinel-nrt require detection with sentinel; defender-scheduled and defender-nrt require detection with xdr or unified. If omitted, hunting infers interactive-hunting and detection infers the platform scheduled target; general has no target. NRT requires an explicit defender-nrt or sentinel-nrt target.")] KqlTarget? target = null,
        [Description("Optional lint controls; discover IDs and applicability with list_kql_lint_rules. Omit ruleSets for profile/target defaults; supplied ruleSets replace those defaults. enableRules adds rules, disableRules wins, minimumSeverity filters lint only, and enabled=false disables lint while preserving syntax and semantic checks.")] LintOptions? lint = null,
        CancellationToken cancellationToken = default) =>
        services.GetRequiredService<AnalysisExecutor>().ExecuteAsync(new ValidateRequest(query, environment, profile, extensions, target, lint), cancellationToken);

    [McpServerTool(Name = "validate_azure_monitor_transformation", Title = "Validate Azure Monitor transformation", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Use when writing, editing, or reviewing an Azure Monitor data collection rule (DCR) transformKql or transform.KQL ingestion transformation. Accepts one KQL expression, not a full DCR document, with typed virtual source columns. Checks supported transformation features, TimeGenerated, and optional destination compatibility without execution. Returns valid, diagnostics, and inferred output columns; valid=false is a validation result. For ordinary hunting or detection queries use validate_kql.")]
    public static Task<TransformationValidationResponse> ValidateAzureMonitorTransformation(
        IServiceProvider services,
        [Description("Transformation expression using the virtual source table, limited to 65,536 characters. Extract transformKql or transform.KQL from a DCR document before calling.")] string query,
        [Description("Required virtual source schema: objects with name and KQL scalar type, for example a column named Time with type string. Use actual incoming stream columns; obtain missing schema information before validating. Source and destination schemas are limited to 5,000 columns combined.")] IReadOnlyList<ColumnDeclaration> sourceColumns,
        [Description("Optional destination schema as name/type objects. Checks output type compatibility and warns about extra output columns that would be discarded. Omit to check only transformation semantics; output must still include TimeGenerated of type datetime.")] IReadOnlyList<ColumnDeclaration>? destinationColumns = null,
        CancellationToken cancellationToken = default) =>
        services.GetRequiredService<AnalysisExecutor>().ExecuteTransformationAsync(
            new TransformationValidationRequest(query, sourceColumns, destinationColumns), cancellationToken);

    [McpServerTool(Name = "list_kql_lint_rules", Title = "List KQL lint rules", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Use to discover lint rule IDs and rule sets before configuring validate_kql lint controls, or to explain a lint diagnostic and its source. Returns applicability, default severities, default-enabled flags, and source links. This lists rules; it does not validate a query. Omit filters to discover all rules, including Azure Monitor transformation rules.")]
    public static LintRuleListResponse ListKqlLintRules(
        IServiceProvider services,
        [Description("Optional rule-set name, for example baseline, defender-xdr, community-detection, or azure-monitor-transformation. Omit to include all sets.")] string? ruleSet = null,
        [Description("Optional category, for example performance, detection-quality, nrt, or transformation. Omit to discover all categories.")] string? category = null,
        [Description("Optional applicability filter: general, hunting, detection, or transformation.")] string? profile = null,
        [Description("Optional applicability filter: interactive-hunting, sentinel-scheduled, sentinel-nrt, defender-scheduled, defender-nrt, or azure-monitor-transformation. Also includes rules with no target restriction.")] string? target = null,
        [Description("Optional applicability filter: xdr, sentinel, unified, or azure-monitor. Also includes rules with no environment restriction.")] string? environment = null) =>
        new(services.GetRequiredService<LintRuleCatalog>().List(ruleSet, category, profile, target, environment));

    [McpServerTool(Name = "list_kql_environments", Title = "List KQL environments", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Use to discover available schema environments (xdr, sentinel, unified), versions, table/function counts, and profiles before choosing a validation or schema lookup environment. Describes the effective catalog, including mounted custom declarations; does not list tables or inspect a live workspace. Use search_kql_schema to find identifiers.")]
    public static IReadOnlyList<EnvironmentSummary> ListKqlEnvironments(IServiceProvider services) => services.GetRequiredService<SchemaQueryService>().ListEnvironments();

    [McpServerTool(Name = "search_kql_schema", Title = "Search KQL schema", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Use when a table, column, or catalog function name is unknown or uncertain while authoring KQL or resolving an unknown-identifier diagnostic. Searches the effective catalog, including mounted custom declarations. Returns matching names, kinds, parent tables, types, and nextCursor. For a known name use get_kql_table or get_kql_function to retrieve its full schema/signature.")]
    public static SchemaSearchResponse SearchKqlSchema(
        IServiceProvider services,
        [Description("Effective schema catalog: xdr for Defender XDR, sentinel for Sentinel, unified for their combined catalog.")] KqlEnvironment environment,
        [Description("Optional case-insensitive substring matched against names and parent table names. Omit or leave empty to browse the catalog.")] string? query = null,
        [Description("Optional exact kind: table, column, or function. Omit to search all three.")] string? kind = null,
        [Description("Page size; defaults to 50 and is clamped to 1 through 100.")] int limit = 50,
        [Description("Opaque nextCursor from the previous search response; reuse the same environment, query, kind, and limit. Omit for the first page; a null nextCursor means no more results.")] string? cursor = null) => services.GetRequiredService<SchemaQueryService>().Search(environment, query, kind, limit, cursor);

    [McpServerTool(Name = "get_kql_table", Title = "Get KQL table", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Use when a table name is known and you need its columns and types to write, repair, or validate KQL. Looks up the effective catalog, including mounted custom declarations; returns no result (null, represented as empty MCP content) if absent. Use search_kql_schema when the name is uncertain. This returns schema, not table rows.")]
    public static SchemaTable? GetKqlTable(
        IServiceProvider services,
        [Description("Effective schema catalog: xdr for Defender XDR, sentinel for Sentinel, unified for their combined catalog.")] KqlEnvironment environment,
        [Description("Exact table name, matched case-insensitively, for example DeviceProcessEvents. Use search_kql_schema if unknown.")] string table) =>
        services.GetRequiredService<SchemaQueryService>().GetTable(environment, table);

    [McpServerTool(Name = "get_kql_function", Title = "Get KQL function", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Use when a catalog function name is known and you need its typed parameters, optional arguments, return schema, or tabular input requirements to author or repair a call. Includes mounted custom functions; returns no result (null, represented as empty MCP content) if absent from the selected environment. Use search_kql_schema to discover names. This is catalog lookup, not an exhaustive reference for KQL built-in scalar functions.")]
    public static SchemaFunction? GetKqlFunction(
        IServiceProvider services,
        [Description("Effective schema catalog: xdr for Defender XDR, sentinel for Sentinel, unified for their combined catalog.")] KqlEnvironment environment,
        [Description("Exact catalog function name, matched case-insensitively, for example FileProfile or _Im_Dns. Use search_kql_schema if unknown.")] string function) =>
        services.GetRequiredService<SchemaQueryService>().GetFunction(environment, function);
}
