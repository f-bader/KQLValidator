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
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 262_144);
builder.Services.Configure<FormOptions>(options => options.MultipartBodyLengthLimit = 262_144);
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<ApiExceptionHandler>();
builder.Services.AddOpenApi("v1");
builder.Services.AddSingleton<SchemaCatalog>();
builder.Services.AddSingleton<LintRuleCatalog>();
builder.Services.AddSingleton<GlobalStateFactory>();
builder.Services.AddSingleton<RequestValidator>();
builder.Services.AddSingleton<KqlLinter>();
builder.Services.AddSingleton<DefenderNrtValidator>();
builder.Services.AddSingleton<KqlValidationService>();
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
    options.ForwardLimit = 1;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = (context, _) =>
    {
        context.HttpContext.Response.Headers.RetryAfter = "1";
        return ValueTask.CompletedTask;
    };
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
                ReplenishmentPeriod = TimeSpan.FromSeconds(1),
                AutoReplenishment = true,
                QueueLimit = 0,
            });
    });
});
builder.Services.AddMcpServer(options =>
    {
        options.ServerInfo = new() { Name = "kql-validator", Version = ThisAssembly.Version };
    })
    .WithHttpTransport(options => options.Stateless = true)
    .WithTools<KqlTools>();

var app = builder.Build();
app.UseExceptionHandler();
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

api.MapGet("/environments", (SchemaQueryService schemas) => schemas.ListEnvironments());
api.MapGet("/lint-rules", (
    string? ruleSet, string? category, string? profile, string? target, string? environment, LintRuleCatalog rules) =>
    new LintRuleListResponse(rules.List(ruleSet, category, profile, target, environment)));
api.MapGet("/environments/{environment}/schema", (
    string environment, string? query, string? kind, int? limit, string? cursor, SchemaQueryService schemas) =>
    TryEnvironment(environment, out var parsed)
        ? Results.Ok(schemas.Search(parsed, query, kind, limit ?? 50, cursor))
        : Results.BadRequest(new { error = "environment must be xdr, sentinel, or unified" }));
api.MapGet("/environments/{environment}/tables/{table}", (
    string environment, string table, SchemaQueryService schemas) =>
    !TryEnvironment(environment, out var parsed)
        ? Results.BadRequest(new { error = "environment must be xdr, sentinel, or unified" })
        : schemas.GetTable(parsed, table) is { } result ? Results.Ok(result) : Results.NotFound());

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

public partial class Program;
