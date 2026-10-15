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
    [Description("Validate Microsoft Defender XDR or Sentinel KQL during writing, editing, debugging, or review, including hunting and detection rules. Checks syntax, schema, and lint without execution. Returns valid, diagnostics with source spans, and inferred output columns; successful calls can return valid=false. Use validate_azure_monitor_transformation for DCR ingestion transformations.")]
    public static Task<ValidationResponse> ValidateKql(
        IServiceProvider services,
        [Description("KQL query text, limited to 65,536 characters.")] string query,
        [Description("Choose the intended platform: xdr for Defender XDR, sentinel for Sentinel, or unified for their combined catalog. list_kql_environments lists catalogs and versions.")] KqlEnvironment environment,
        [Description("Query purpose: general for general-purpose queries, hunting for investigations, or detection for alert rules.")] LintProfile profile,
        [Description("Optional request-scoped contracts for custom tables, functions, and watchlist aliases with typed columns. Supply actual declarations missing from the effective catalog. Changes apply to this request only.")] ValidationExtensions? extensions = null,
        [Description("Optional target: interactive-hunting requires hunting; sentinel-scheduled and sentinel-nrt require detection with sentinel; defender-scheduled and defender-nrt require detection with xdr or unified. If omitted, hunting infers interactive-hunting and detection infers the platform scheduled target; general has no target. NRT requires an explicit defender-nrt or sentinel-nrt target.")] KqlTarget? target = null,
        [Description("Optional lint controls; discover IDs and applicability with list_kql_lint_rules. Omit ruleSets for profile/target defaults; supplied ruleSets replace those defaults. enableRules adds rules, disableRules wins, minimumSeverity filters lint only, and enabled=false disables lint while preserving syntax and semantic checks.")] LintOptions? lint = null,
        CancellationToken cancellationToken = default) =>
        services.GetRequiredService<AnalysisExecutor>().ExecuteAsync(new ValidateRequest(query, environment, profile, extensions, target, lint), cancellationToken);

    [McpServerTool(Name = "validate_azure_monitor_transformation", Title = "Validate Azure Monitor transformation", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Validate Azure Monitor ingestion transformations from a data collection rule (DCR). Extract the expression from transformKql or transform.KQL and supply typed source columns. Checks supported features, TimeGenerated, and optional destination compatibility without execution. Returns valid, diagnostics, and inferred output columns; successful calls can return valid=false. Use validate_kql for ordinary hunting or detection queries.")]
    public static Task<TransformationValidationResponse> ValidateAzureMonitorTransformation(
        IServiceProvider services,
        [Description("Transformation expression using the virtual source table, limited to 65,536 characters. Extract transformKql or transform.KQL from a DCR document before calling.")] string query,
        [Description("Required incoming stream schema: objects with name and KQL scalar type, such as Time with type string. Obtain actual columns before validating. Source and destination schemas allow 5,000 columns combined.")] IReadOnlyList<ColumnDeclaration> sourceColumns,
        [Description("Optional destination columns as name/type objects. Checks output types and warns about extra columns Azure discards. Output must include TimeGenerated:datetime even when this schema is omitted.")] IReadOnlyList<ColumnDeclaration>? destinationColumns = null,
        CancellationToken cancellationToken = default) =>
        services.GetRequiredService<AnalysisExecutor>().ExecuteTransformationAsync(
            new TransformationValidationRequest(query, sourceColumns, destinationColumns), cancellationToken);

    [McpServerTool(Name = "list_kql_lint_rules", Title = "List KQL lint rules", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Discover lint rule IDs, rule sets, and applicability before configuring validate_kql lint controls or explaining a diagnostic. Returns default severities, default-enabled flags, and source links. Omit filters for all rules, including Azure Monitor transformations.")]
    public static LintRuleListResponse ListKqlLintRules(
        IServiceProvider services,
        [Description("Optional rule-set name, for example baseline, defender-xdr, community-detection, or azure-monitor-transformation. Omit to include all sets.")] string? ruleSet = null,
        [Description("Optional category, for example performance, detection-quality, nrt, or transformation. Omit to discover all categories.")] string? category = null,
        [Description("Optional applicability filter: general, hunting, detection, or transformation.")] string? profile = null,
        [Description("Optional applicability filter: interactive-hunting, sentinel-scheduled, sentinel-nrt, defender-scheduled, defender-nrt, or azure-monitor-transformation. Also includes rules with no target restriction.")] string? target = null,
        [Description("Optional applicability filter: xdr, sentinel, unified, or azure-monitor. Also includes rules with no environment restriction.")] string? environment = null) =>
        new(services.GetRequiredService<LintRuleCatalog>().List(ruleSet, category, profile, target, environment));

    [McpServerTool(Name = "list_kql_environments", Title = "List KQL environments", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("List schema environments (xdr, sentinel, unified), versions, table/function counts, and profiles from the effective catalog, including mounted custom declarations. Use search_kql_schema to find identifiers. Catalog discovery runs locally without inspecting a live workspace.")]
    public static IReadOnlyList<EnvironmentSummary> ListKqlEnvironments(IServiceProvider services) => services.GetRequiredService<SchemaQueryService>().ListEnvironments();

    [McpServerTool(Name = "search_kql_schema", Title = "Search KQL schema", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Find unknown or uncertain table, column, or catalog function names by case-insensitive substring. Searches the effective catalog, including mounted custom declarations. Returns names, kinds, parent tables, types, and nextCursor. Fetch known definitions with get_kql_table or get_kql_function.")]
    public static SchemaSearchResponse SearchKqlSchema(
        IServiceProvider services,
        [Description("Effective schema catalog: xdr (Defender XDR), sentinel (Sentinel), or unified (combined).")] KqlEnvironment environment,
        [Description("Optional case-insensitive substring matched against names and parent table names. Omit or leave empty to browse the catalog.")] string? query = null,
        [Description("Optional exact kind: table, column, or function. Omit to search all three.")] string? kind = null,
        [Description("Page size; defaults to 50 and is clamped to 1 through 100.")] int limit = 50,
        [Description("Opaque nextCursor from the previous search response; reuse the same environment, query, kind, and limit. Omit for the first page; a null nextCursor means no more results.")] string? cursor = null) => services.GetRequiredService<SchemaQueryService>().Search(environment, query, kind, limit, cursor);

    [McpServerTool(Name = "get_kql_table", Title = "Get KQL table", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Get a known table's columns and types from the effective catalog, including mounted custom declarations. Missing tables return null (empty MCP content). Use search_kql_schema for uncertain names. For nested fields in a known column, use get_kql_structured_column; discover available structured columns with list_kql_structured_columns.")]
    public static SchemaTable? GetKqlTable(
        IServiceProvider services,
        [Description("Effective schema catalog: xdr (Defender XDR), sentinel (Sentinel), or unified (combined).")] KqlEnvironment environment,
        [Description("Exact table name, matched case-insensitively, for example DeviceProcessEvents. Use search_kql_schema if unknown.")] string table) =>
        services.GetRequiredService<SchemaQueryService>().GetTable(environment, table);

    [McpServerTool(Name = "get_kql_column_relations", Title = "Get KQL column relations", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Inspect join keys for a known table using bundled community relations: identifier families, nested paths, timing guidance, caveats, notes, and examples. Both endpoints are filtered against the effective schema. An empty result leaves join validity unchanged; live matches need verification. Enable community-correlations through validate_kql for related lint checks.")]
    public static ColumnRelationResponse GetKqlColumnRelations(
        IServiceProvider services,
        [Description("Effective schema catalog: xdr, sentinel, or unified. Both relation endpoints must exist in the selected catalog.")] KqlEnvironment environment,
        [Description("Exact known table name, matched case-insensitively. Returns relations in either direction; unknown tables return an empty items list.")] string table,
        [Description("Optional exact column name on the requested table, matched case-insensitively, for example RawEventData. Matches either relation endpoint; nested paths are included in results.")] string? column = null) =>
        services.GetRequiredService<SchemaQueryService>().GetRelations(environment, table, column);

    [McpServerTool(Name = "list_kql_structured_columns", Title = "List KQL structured columns", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Find table columns with cataloged nested structures and discover their discriminator keys. Returns coverage summaries filtered against the effective schema. For a known table and column, call get_kql_structured_column directly for nested fields, variants, and parsing guidance. Captured and illustrative shapes are incomplete; missing evidence leaves KQL validity unchanged.")]
    public static StructuredListResponse ListKqlStructuredColumns(
        IServiceProvider services,
        [Description("Effective schema environment: xdr, sentinel, or unified.")] KqlEnvironment environment,
        [Description("Optional exact table name, matched case-insensitively.")] string? table = null,
        [Description("Optional exact column name, matched case-insensitively.")] string? column = null,
        [Description("Page size in columns, defaults to 50, clamped to 1 through 100.")] int limit = 50,
        [Description("Opaque nextCursor; reuse the same filters, environment, and limit. Null means no further pages.")] string? cursor = null) =>
        services.GetRequiredService<SchemaQueryService>().ListStructures(environment, table, column, limit, cursor);

    [McpServerTool(Name = "get_kql_structured_column", Title = "Get KQL structured column", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Get nested fields, types, discriminator variants, and parsing guidance for a known table and column. Use list_kql_structured_columns to discover available columns or discriminator keys. Captured shapes and illustrative examples are incomplete; fields may be missing or have other types. Includes known combinations without shapes. Missing evidence leaves KQL validity unchanged. Translate descriptive paths into KQL before use.")]
    public static StructuredDetailResponse GetKqlStructuredColumn(
        IServiceProvider services,
        [Description("Effective schema environment: xdr, sentinel, or unified.")] KqlEnvironment environment,
        [Description("Exact table name, matched case-insensitively.")] string table,
        [Description("Exact column name, matched case-insensitively.")] string column,
        [Description("Optional discriminator key/value object, such as OperationName mapped to Add service principal. Omit for all variants; discover keys with list_kql_structured_columns. All filters must match; keys and values are case-sensitive and whitespace is significant. An absent key does not match.")] Dictionary<string, string>? discriminators = null,
        [Description("Include captured or illustrative upstream examples; defaults to false. Verify examples against actual payloads.")] bool includeExamples = false,
        [Description("Page size in discriminator combinations, defaults to 10, clamped to 1 through 100. Status and totalCount cover the full filtered result.")] int limit = 10,
        [Description("Opaque nextCursor; reuse all filters and options. Null means no further pages.")] string? cursor = null) =>
        services.GetRequiredService<SchemaQueryService>().GetStructure(environment, table, column, discriminators, includeExamples, limit, cursor);

    [McpServerTool(Name = "get_kql_function", Title = "Get KQL function", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false, UseStructuredContent = true)]
    [Description("Get a known catalog function's typed parameters, optional arguments, return schema, and tabular input requirements, for example FileProfile or _Im_Dns. Includes mounted custom functions; missing functions return null (empty MCP content). Use search_kql_schema to find names. Use validate_kql to check calls to built-in scalar functions such as parse_json.")]
    public static SchemaFunction? GetKqlFunction(
        IServiceProvider services,
        [Description("Effective schema catalog: xdr (Defender XDR), sentinel (Sentinel), or unified (combined).")] KqlEnvironment environment,
        [Description("Exact catalog function name, matched case-insensitively, for example FileProfile or _Im_Dns. Use search_kql_schema if unknown.")] string function) =>
        services.GetRequiredService<SchemaQueryService>().GetFunction(environment, function);
}
