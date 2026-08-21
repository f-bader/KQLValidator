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
            BadHttpRequestException badRequest => (badRequest.StatusCode,
                badRequest.StatusCode == StatusCodes.Status413PayloadTooLarge ? "Request body too large" : "Malformed request",
                badRequest.Message),
            // Arbitrary ArgumentException messages (including Kusto.Language internals) are
            // not part of the API contract; deliberate messages travel as RequestValidationException.
            ArgumentException => (StatusCodes.Status400BadRequest, "Invalid validation request", "A request argument was invalid."),
            AnalysisQueueFullException => (StatusCodes.Status429TooManyRequests, "Validation queue full", exception.Message),
            AnalysisDeadlineExceededException => (StatusCodes.Status504GatewayTimeout, "Validation deadline exceeded", exception.Message),
            OperationCanceledException when context.RequestAborted.IsCancellationRequested => (499, "Request cancelled", "The client cancelled the request."),
            _ => (StatusCodes.Status500InternalServerError, "Unexpected validation failure",
                environment.IsDevelopment() ? exception.ToString() : "The request could not be processed."),
        };

        context.Response.StatusCode = status;
        // Type is left unset so the problem-details writer applies the RFC 9110 reference
        // for known status codes instead of a third-party link.
        var details = new ProblemDetails
        {
            Status = status,
            Title = title,
            Detail = detail,
        };
        if (exception is RequestValidationException requestValidation)
            details.Extensions["field"] = requestValidation.Field;

        if (await problemDetails.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = context,
            ProblemDetails = details,
            Exception = exception,
        }))
        {
            return true;
        }

        // The writer declines when the Accept header excludes JSON; answer anyway so the
        // middleware never rethrows (a rethrow would log the user-submitted content).
        await context.Response.WriteAsJsonAsync(details, cancellationToken: cancellationToken);
        return true;
    }
}
