using System.Threading.RateLimiting;
using KqlValidator.Contracts;
using KqlValidator.Mcp;
using KqlValidator.Operational;
using KqlValidator.Validation;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 262_144);
builder.Services.Configure<FormOptions>(options => options.MultipartBodyLengthLimit = 262_144);
builder.Services.AddProblemDetails();
builder.Services.AddExceptionHandler<ApiExceptionHandler>();
builder.Services.AddOpenApi("v1");
builder.Services.AddSingleton<SchemaCatalog>();
builder.Services.AddSingleton<GlobalStateFactory>();
builder.Services.AddSingleton<RequestValidator>();
builder.Services.AddSingleton<KqlLinter>();
builder.Services.AddSingleton<KqlValidationService>();
builder.Services.AddSingleton<SchemaQueryService>();
builder.Services.AddSingleton<AnalysisHealthState>();
builder.Services.AddSingleton<AnalysisExecutor>();
builder.Services.AddHealthChecks()
    .AddCheck<AnalysisHealthCheck>("analysis", tags: ["ready"]);
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetTokenBucketLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new TokenBucketRateLimiterOptions
            {
                TokenLimit = 10,
                TokensPerPeriod = 1,
                ReplenishmentPeriod = TimeSpan.FromSeconds(1),
                AutoReplenishment = true,
                QueueLimit = 0,
            }));
});
builder.Services.AddMcpServer(options =>
    {
        options.ServerInfo = new() { Name = "kql-validator", Version = ThisAssembly.Version };
    })
    .WithHttpTransport(options => options.Stateless = true)
    .WithTools<KqlTools>();

var app = builder.Build();
app.UseExceptionHandler();
app.UseRateLimiter();

app.MapGet("/", () => new ServiceDiscovery(
    "kql-validator",
    ThisAssembly.Version,
    "/api/v1",
    "/mcp",
    "/openapi/v1.json",
    "https://github.com/fabian/kql-validator"));

app.MapPost("/api/v1/validate", async (ValidateRequest request, AnalysisExecutor executor, CancellationToken cancellationToken) =>
    Results.Ok(await executor.ExecuteAsync(request, cancellationToken)))
    .Accepts<ValidateRequest>("application/json")
    .Produces<ValidationResponse>()
    .ProducesProblem(StatusCodes.Status400BadRequest)
    .ProducesProblem(StatusCodes.Status413PayloadTooLarge)
    .ProducesProblem(StatusCodes.Status429TooManyRequests)
    .ProducesProblem(StatusCodes.Status504GatewayTimeout);

app.MapGet("/api/v1/environments", (SchemaQueryService schemas) => schemas.ListEnvironments());
app.MapGet("/api/v1/environments/{environment}/schema", (
    string environment, string? query, string? kind, int? limit, string? cursor, SchemaQueryService schemas) =>
    TryEnvironment(environment, out var parsed)
        ? Results.Ok(schemas.Search(parsed, query, kind, limit ?? 50, cursor))
        : Results.BadRequest(new { error = "environment must be xdr, sentinel, or unified" }));
app.MapGet("/api/v1/environments/{environment}/tables/{table}", (
    string environment, string table, SchemaQueryService schemas) =>
    !TryEnvironment(environment, out var parsed)
        ? Results.BadRequest(new { error = "environment must be xdr, sentinel, or unified" })
        : schemas.GetTable(parsed, table) is { } result ? Results.Ok(result) : Results.NotFound());

app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false });
app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = registration => registration.Tags.Contains("ready") });
app.MapOpenApi("/openapi/{documentName}.json");
app.MapMcp("/mcp");

app.Run();

static bool TryEnvironment(string value, out KqlEnvironment environment) =>
    Enum.TryParse(value, ignoreCase: true, out environment);

public partial class Program;
