using KqlValidator.Validation;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace KqlValidator.Operational;

public sealed class ApiExceptionHandler(IProblemDetailsService problemDetails, IHostEnvironment environment) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext context, Exception exception, CancellationToken cancellationToken)
    {
        var (status, title, detail) = exception switch
        {
            RequestValidationException validation => (StatusCodes.Status400BadRequest, "Invalid validation request", validation.Message),
            ArgumentException argument => (StatusCodes.Status400BadRequest, "Invalid validation request", argument.Message),
            AnalysisQueueFullException => (StatusCodes.Status429TooManyRequests, "Validation queue full", exception.Message),
            TimeoutException => (StatusCodes.Status504GatewayTimeout, "Validation deadline exceeded", "Static analysis did not finish within five seconds."),
            OperationCanceledException when context.RequestAborted.IsCancellationRequested => (499, "Request cancelled", "The client cancelled the request."),
            _ => (StatusCodes.Status500InternalServerError, "Unexpected validation failure",
                environment.IsDevelopment() ? exception.ToString() : "The request could not be processed."),
        };

        context.Response.StatusCode = status;
        return await problemDetails.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = context,
            ProblemDetails = new ProblemDetails
            {
                Status = status,
                Title = title,
                Detail = detail,
                Type = $"https://httpstatuses.com/{status}",
            },
            Exception = exception,
        });
    }
}
