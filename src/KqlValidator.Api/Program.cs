using System.Threading.RateLimiting;
using KqlValidator.Contracts;
using KqlValidator.Mcp;
using KqlValidator.Operational;
using KqlValidator.Validation;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
// The optional overlay is intentionally read once, before the server starts accepting
// traffic. A bad mounted file is a deployment failure rather than a partially ready API.
var schemaCatalog = new SchemaCatalog(overlayPath: builder.Configuration["SchemaOverlay:Path"]);
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 262_144);
builder.Services.Configure<FormOptions>(options => options.MultipartBodyLengthLimit = 262_144);
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<ApiExceptionHandler>();
builder.Services.AddOpenApi("v1", options => options.AddDocumentTransformer((document, _, _) =>
{
    document.Info = new()
    {
        Title = "KQL Validator",
        Version = ThisAssembly.Version,
        Description = "Unauthenticated, stateless static analysis for Microsoft Defender XDR, Microsoft Sentinel, and Azure Monitor transformation KQL. Queries are never executed, logged, or persisted.",
        License = new() { Name = "MIT", Url = new Uri("https://github.com/f-bader/KQLValidator/blob/main/LICENSE") },
    };
    return Task.CompletedTask;
}));
builder.Services.AddSingleton(schemaCatalog);
builder.Services.AddSingleton<LintRuleCatalog>();
builder.Services.AddSingleton<GlobalStateFactory>();
builder.Services.AddSingleton<RequestValidator>();
builder.Services.AddSingleton<KqlLinter>();
builder.Services.AddSingleton<DefenderNrtValidator>();
builder.Services.AddSingleton<DefenderNrtFeatures>();
builder.Services.AddSingleton<KqlValidationService>();
builder.Services.AddSingleton<AzureMonitorTransformationValidationService>();
builder.Services.AddSingleton<SchemaQueryService>();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<AnalysisHealthState>();
builder.Services.AddSingleton<AnalysisMetrics>();
builder.Services.AddSingleton<AnalysisExecutor>();
builder.Services.AddHealthChecks()
    .AddCheck<AnalysisReadinessHealthCheck>("analysis-ready", tags: ["ready"])
    .AddCheck<AnalysisLivenessHealthCheck>("analysis-live", tags: ["live"]);
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    // Exactly one hop: behind an appending ingress (Container Apps ingress appends the
    // observed client address as the rightmost X-Forwarded-For entry) only that entry is
    // trusted, so a client-supplied header cannot spoof the rate-limit partition key.
    options.ForwardLimit = 1;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
    var knownNetworks = builder.Configuration.GetSection("ReverseProxy:KnownNetworks").Get<string[]>() ?? [];
    foreach (var network in knownNetworks)
        options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(network));
});
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = (context, _) =>
    {
        context.HttpContext.Response.Headers.RetryAfter = "1";
        return ValueTask.CompletedTask;
    };
    static TimeSpan ReplenishmentPeriod(IConfiguration configuration) =>
        TimeSpan.FromSeconds(configuration.GetValue<int?>("RateLimiting:ReplenishmentPeriodSeconds") ?? 1);
    options.AddPolicy("public-api", context =>
    {
        var configuration = context.RequestServices.GetRequiredService<IConfiguration>();
        var environment = context.RequestServices.GetRequiredService<IHostEnvironment>();
        var tokenLimit = configuration.GetValue<int?>("RateLimiting:TokenLimit")
            ?? (environment.IsDevelopment() ? 100 : 10);
        var tokensPerSecond = configuration.GetValue<int?>("RateLimiting:TokensPerSecond") ?? 1;
        return
        RateLimitPartition.GetTokenBucketLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new TokenBucketRateLimiterOptions
            {
                TokenLimit = tokenLimit,
                TokensPerPeriod = tokensPerSecond,
                ReplenishmentPeriod = ReplenishmentPeriod(configuration),
                AutoReplenishment = true,
                QueueLimit = 0,
            });
    });
    // Per-address partitions are spoofable when forwarded headers are trusted and idle
    // partitions are purged but still cost memory while active, so a single global bucket
    // bounds total throughput no matter how many partitions a caller manufactures.
    // Health probes stay exempt so an attack cannot starve the container probes.
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        if (context.Request.Path.StartsWithSegments("/health"))
            return RateLimitPartition.GetNoLimiter("health");

        var configuration = context.RequestServices.GetRequiredService<IConfiguration>();
        var environment = context.RequestServices.GetRequiredService<IHostEnvironment>();
        var tokenLimit = configuration.GetValue<int?>("RateLimiting:GlobalTokenLimit")
            ?? (environment.IsDevelopment() ? 10_000 : 100);
        var tokensPerSecond = configuration.GetValue<int?>("RateLimiting:GlobalTokensPerSecond") ?? 25;
        return RateLimitPartition.GetTokenBucketLimiter(
            "global",
            _ => new TokenBucketRateLimiterOptions
            {
                TokenLimit = tokenLimit,
                TokensPerPeriod = tokensPerSecond,
                ReplenishmentPeriod = ReplenishmentPeriod(configuration),
                AutoReplenishment = true,
                QueueLimit = 0,
            });
    });
});
builder.Services.AddMcpServer(options =>
    {
        options.ServerInfo = new() { Name = "kql-validator", Version = ThisAssembly.Version };
        options.ServerInstructions = """
            Use this server while writing, editing, debugging, or reviewing Microsoft Defender XDR,
            Microsoft Sentinel, and Azure Monitor transformation KQL. Validate new or changed supported
            KQL before presenting it as checked, and revalidate after repairs. Analysis is static:
            queries are never executed, stored, or logged, and catalogs do not inspect a live workspace.
            Choose the intended platform and purpose from the user's context; ask when ambiguous rather
            than using unified to hide schema errors. Discover environments when needed. Search for
            uncertain schema identifiers, then fetch known table/function definitions as needed;
            skip discovery calls when the required schema is already known. Catalogs include mounted
            custom declarations. Request missing custom schemas rather than inventing them.
            Route ordinary queries and hunting/detection rules to validate_kql; route DCR transformKql
            or transform.KQL expressions to validate_azure_monitor_transformation with actual source
            columns. Extract the expression from a full DCR document. NRT detection needs an explicit
            platform-specific target. Use get_kql_column_relations when choosing correlation keys;
            these community relationships are guidance, not an exhaustive join allowlist.
            Before accessing nested fields, use list_kql_structured_columns and get_kql_structured_column.
            Captured and illustrative shapes are incomplete, not vendor contracts. Missing fields or variants
            never imply invalid KQL; handle absent values and explain these limits to the user.
            Use list_kql_lint_rules to discover lint controls or explain rules.
            Inspect valid and diagnostics even when the tool call succeeds: valid=false means validation
            failed; warnings can remain when valid=true. Report remaining diagnostics and the limits of
            static validation; it does not prove runtime success or detection effectiveness.
            """;
    })
    .WithHttpTransport(options => options.Stateless = true)
    .WithTools<KqlTools>();

var app = builder.Build();
// OnStarting survives the response reset the exception handler performs, so every
// response - including Problem Details - carries nosniff.
app.Use((context, next) =>
{
    context.Response.OnStarting(static state =>
    {
        ((HttpContext)state).Response.Headers.XContentTypeOptions = "nosniff";
        return Task.CompletedTask;
    }, context);
    return next(context);
});
app.UseExceptionHandler(new ExceptionHandlerOptions
{
    // Request-scoped failures embed user-submitted identifiers in their messages;
    // suppressing their diagnostics keeps the "no query logging" guarantee while
    // unexpected 500s remain fully logged.
    SuppressDiagnosticsCallback = context => context.Exception
        is RequestValidationException
        or AnalysisQueueFullException
        or AnalysisDeadlineExceededException
        or ArgumentException
        or BadHttpRequestException
        or OperationCanceledException,
});
// Minimal-API body reading turns an oversized payload into a bare 413 without ever
// reaching the exception handler, and the rate limiter rejects with a bare 429; this
// middleware upgrades any empty-bodied error status to Problem Details.
app.UseStatusCodePages();
#if STATUS_SITE_ENABLED
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/status"))
    {
        context.Response.Headers["X-Robots-Tag"] = "noindex, nofollow, noarchive";
        context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
        context.Response.Headers["Referrer-Policy"] = "no-referrer";
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["Cache-Control"] = "no-store";
    }

    await next();
});
app.UseDefaultFiles();
app.UseStaticFiles();
#endif
if (app.Configuration.GetValue<bool>("ReverseProxy:TrustForwardedHeaders"))
    app.UseForwardedHeaders();
app.UseRateLimiter();

app.MapGet("/", () => new ServiceDiscovery(
    "kql-validator",
    ThisAssembly.Version,
    "/api/v1",
    "/mcp",
    "/openapi/v1.json",
    "https://github.com/f-bader/KQLValidator"));

var api = app.MapGroup("/api/v1").RequireRateLimiting("public-api");

api.MapPost("/validate", async (ValidateRequest request, AnalysisExecutor executor, CancellationToken cancellationToken) =>
    Results.Ok(await executor.ExecuteAsync(request, cancellationToken)))
    .Accepts<ValidateRequest>("application/json")
    .Produces<ValidationResponse>()
    .ProducesProblem(StatusCodes.Status400BadRequest)
    .ProducesProblem(StatusCodes.Status413PayloadTooLarge)
    .ProducesProblem(StatusCodes.Status429TooManyRequests)
    .ProducesProblem(StatusCodes.Status504GatewayTimeout);

api.MapPost("/validate-transformation", async (
    TransformationValidationRequest request,
    AnalysisExecutor executor,
    CancellationToken cancellationToken) =>
    Results.Ok(await executor.ExecuteTransformationAsync(request, cancellationToken)))
    .Accepts<TransformationValidationRequest>("application/json")
    .Produces<TransformationValidationResponse>()
    .ProducesProblem(StatusCodes.Status400BadRequest)
    .ProducesProblem(StatusCodes.Status413PayloadTooLarge)
    .ProducesProblem(StatusCodes.Status429TooManyRequests)
    .ProducesProblem(StatusCodes.Status504GatewayTimeout);

api.MapGet("/environments", (SchemaQueryService schemas) => schemas.ListEnvironments());
api.MapGet("/lint-rules", (
    string? ruleSet, string? category, string? profile, string? target, string? environment, LintRuleCatalog rules) =>
    new LintRuleListResponse(rules.List(ruleSet, category, profile, target, environment)));
api.MapGet("/environments/{environment}/schema", (
    string environment, string? query, string? kind, int? limit, string? cursor, SchemaQueryService schemas) =>
    TryEnvironment(environment, out var parsed)
        ? Results.Ok(schemas.Search(parsed, query, kind, limit ?? 50, cursor))
        : UnknownEnvironment())
    .Produces<SchemaSearchResponse>()
    .ProducesProblem(StatusCodes.Status400BadRequest)
    .ProducesProblem(StatusCodes.Status429TooManyRequests);
api.MapGet("/environments/{environment}/tables/{table}", (
    string environment, string table, SchemaQueryService schemas) =>
    !TryEnvironment(environment, out var parsed)
        ? UnknownEnvironment()
        : schemas.GetTable(parsed, table) is { } result
            ? Results.Ok(result)
            : Results.Problem(statusCode: StatusCodes.Status404NotFound, title: "Unknown table",
                detail: "The table does not exist in the selected environment."))
    .Produces<SchemaTable>()
    .ProducesProblem(StatusCodes.Status400BadRequest)
    .ProducesProblem(StatusCodes.Status404NotFound)
    .ProducesProblem(StatusCodes.Status429TooManyRequests);

api.MapGet("/environments/{environment}/tables/{table}/relations", (
    string environment, string table, string? column, SchemaQueryService schemas) =>
    TryEnvironment(environment, out var parsed)
        ? Results.Ok(schemas.GetRelations(parsed, table, column))
        : UnknownEnvironment())
    .Produces<ColumnRelationResponse>()
    .ProducesProblem(StatusCodes.Status400BadRequest)
    .ProducesProblem(StatusCodes.Status429TooManyRequests);

api.MapGet("/environments/{environment}/structured-columns", (
    string environment, string? table, string? column, int? limit, string? cursor, SchemaQueryService schemas) =>
    TryEnvironment(environment, out var parsed)
        ? Results.Ok(schemas.ListStructures(parsed, table, column, limit ?? 50, cursor))
        : UnknownEnvironment())
    .Produces<StructuredListResponse>()
    .ProducesProblem(StatusCodes.Status400BadRequest)
    .ProducesProblem(StatusCodes.Status429TooManyRequests);

api.MapGet("/environments/{environment}/tables/{table}/columns/{column}/structures", (
    string environment, string table, string column, string? discriminators, bool? includeExamples,
    int? limit, string? cursor, SchemaQueryService schemas) =>
    TryEnvironment(environment, out var parsed)
        ? Results.Ok(schemas.GetStructure(parsed, table, column,
            discriminators is null ? null : StructuredColumnCatalog.ParseDiscriminators(discriminators)
                ?? throw new ArgumentException("discriminators must be a JSON object."),
            includeExamples ?? false, limit ?? 10, cursor))
        : UnknownEnvironment())
    .Produces<StructuredDetailResponse>()
    .ProducesProblem(StatusCodes.Status400BadRequest)
    .ProducesProblem(StatusCodes.Status429TooManyRequests);

api.MapGet("/environments/{environment}/functions/{function}", (
    string environment, string function, SchemaQueryService schemas) =>
    !TryEnvironment(environment, out var parsed)
        ? UnknownEnvironment()
        : schemas.GetFunction(parsed, function) is { } result
            ? Results.Ok(result)
            : Results.Problem(statusCode: StatusCodes.Status404NotFound, title: "Unknown function",
                detail: "The function does not exist in the selected environment."))
    .Produces<SchemaFunction>()
    .ProducesProblem(StatusCodes.Status400BadRequest)
    .ProducesProblem(StatusCodes.Status404NotFound)
    .ProducesProblem(StatusCodes.Status429TooManyRequests);

app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = registration => registration.Tags.Contains("live") });
app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = registration => registration.Tags.Contains("ready") });
app.MapOpenApi("/openapi/{documentName}.json");
app.MapMcp("/mcp").RequireRateLimiting("public-api");
#if STATUS_SITE_ENABLED
app.MapGet("/robots.txt", () => Results.Text(
    "User-agent: *\nDisallow: /status\nDisallow: /status/\n",
    "text/plain; charset=utf-8"));
#endif

app.Run();

static bool TryEnvironment(string value, out KqlEnvironment environment) =>
    Enum.TryParse(value, ignoreCase: true, out environment) && Enum.IsDefined(environment);

static IResult UnknownEnvironment() =>
    Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "Unknown environment",
        detail: "environment must be xdr, sentinel, or unified");

public partial class Program;
