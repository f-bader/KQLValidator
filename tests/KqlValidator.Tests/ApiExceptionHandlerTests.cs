using System.Text.Json;
using KqlValidator.Operational;
using KqlValidator.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace KqlValidator.Tests;

public sealed class ApiExceptionHandlerTests
{
    [Fact]
    public async Task Oversized_body_maps_to_problem_details_413()
    {
        var (status, problem) = await Handle(new BadHttpRequestException(
            "Request body too large. The max request body size is 262144 bytes.", StatusCodes.Status413PayloadTooLarge));

        Assert.Equal(StatusCodes.Status413PayloadTooLarge, status);
        Assert.Equal("Request body too large", problem.GetProperty("title").GetString());
        Assert.Contains("262144", problem.GetProperty("detail").GetString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Malformed_request_maps_to_problem_details_400()
    {
        var (status, problem) = await Handle(new BadHttpRequestException("Unexpected end of request content."));

        Assert.Equal(StatusCodes.Status400BadRequest, status);
        Assert.Equal("Malformed request", problem.GetProperty("title").GetString());
    }

    [Fact]
    public async Task Bare_argument_exception_is_not_echoed_to_the_client()
    {
        var (status, problem) = await Handle(new ArgumentException("internal library wording with sensitive detail"));

        Assert.Equal(StatusCodes.Status400BadRequest, status);
        Assert.Equal("A request argument was invalid.", problem.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task Request_validation_exception_keeps_its_message_and_field()
    {
        var (status, problem) = await Handle(new RequestValidationException("query", "Query must not be empty."));

        Assert.Equal(StatusCodes.Status400BadRequest, status);
        Assert.Equal("Query must not be empty.", problem.GetProperty("detail").GetString());
        Assert.Equal("query", problem.GetProperty("field").GetString());
    }

    [Fact]
    public async Task Queue_full_and_deadline_map_to_429_and_504()
    {
        var (queueStatus, _) = await Handle(new AnalysisQueueFullException());
        var (deadlineStatus, _) = await Handle(new AnalysisDeadlineExceededException());

        Assert.Equal(StatusCodes.Status429TooManyRequests, queueStatus);
        Assert.Equal(StatusCodes.Status504GatewayTimeout, deadlineStatus);
    }

    [Fact]
    public async Task Unexpected_exception_returns_generic_500_outside_development()
    {
        var (status, problem) = await Handle(new InvalidOperationException("secret internal state"));

        Assert.Equal(StatusCodes.Status500InternalServerError, status);
        Assert.Equal("The request could not be processed.", problem.GetProperty("detail").GetString());
        Assert.DoesNotContain("secret", problem.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<(int Status, JsonElement Problem)> Handle(Exception exception)
    {
        var services = new ServiceCollection();
        services.AddProblemDetails();
        services.AddLogging();
        await using var provider = services.BuildServiceProvider();

        var handler = new ApiExceptionHandler(
            provider.GetRequiredService<IProblemDetailsService>(),
            new ProductionEnvironment());
        var context = new DefaultHttpContext { RequestServices = provider };
        using var body = new MemoryStream();
        context.Response.Body = body;

        var handled = await handler.TryHandleAsync(context, exception, TestContext.Current.CancellationToken);
        Assert.True(handled);

        body.Position = 0;
        using var document = await JsonDocument.ParseAsync(body, cancellationToken: TestContext.Current.CancellationToken);
        return (context.Response.StatusCode, document.RootElement.Clone());
    }

    private sealed class ProductionEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;
        public string ApplicationName { get; set; } = "KqlValidator.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
