using System.Collections.Concurrent;
using KqlValidator.Contracts;
using KqlValidator.Validation;

namespace KqlValidator.Operational;

public sealed class AnalysisExecutor
{
    private readonly Func<ValidateRequest, CancellationToken, ValidationResponse> validate;
    private readonly Func<TransformationValidationRequest, CancellationToken, TransformationValidationResponse> validateTransformation;
    private readonly AnalysisHealthState health;
    private readonly AnalysisMetrics metrics;
    private readonly TimeProvider timeProvider;
    private readonly TimeSpan analysisDeadline;
    private readonly SemaphoreSlim concurrency = new(2, 2);
    private int queued;

    public AnalysisExecutor(
        KqlValidationService validator,
        AzureMonitorTransformationValidationService transformationValidator,
        AnalysisHealthState health,
        AnalysisMetrics metrics,
        TimeProvider timeProvider)
        : this(validator.Validate, transformationValidator.Validate, health, metrics, timeProvider, TimeSpan.FromSeconds(5))
    {
    }

    // Seam for tests: a stub analysis and a short deadline exercise the timeout paths quickly.
    public AnalysisExecutor(
        Func<ValidateRequest, CancellationToken, ValidationResponse> validate,
        AnalysisHealthState health,
        AnalysisMetrics metrics,
        TimeProvider timeProvider,
        TimeSpan analysisDeadline)
        : this(validate, (_, _) => throw new NotSupportedException(), health, metrics, timeProvider, analysisDeadline)
    {
    }

    public AnalysisExecutor(
        Func<ValidateRequest, CancellationToken, ValidationResponse> validate,
        Func<TransformationValidationRequest, CancellationToken, TransformationValidationResponse> validateTransformation,
        AnalysisHealthState health,
        AnalysisMetrics metrics,
        TimeProvider timeProvider,
        TimeSpan analysisDeadline)
    {
        this.validate = validate;
        this.validateTransformation = validateTransformation;
        this.health = health;
        this.metrics = metrics;
        this.timeProvider = timeProvider;
        this.analysisDeadline = analysisDeadline;
    }

    public async Task<ValidationResponse> ExecuteAsync(ValidateRequest request, CancellationToken cancellationToken)
        => await ExecuteCoreAsync(token => validate(request, token), cancellationToken);

    public async Task<TransformationValidationResponse> ExecuteTransformationAsync(
        TransformationValidationRequest request,
        CancellationToken cancellationToken)
        => await ExecuteCoreAsync(token => validateTransformation(request, token), cancellationToken);

    private async Task<TResponse> ExecuteCoreAsync<TResponse>(
        Func<CancellationToken, TResponse> analyze,
        CancellationToken cancellationToken)
    {
        var started = timeProvider.GetTimestamp();
        metrics.Request();
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(analysisDeadline);
        Task<TResponse>? work = null;

        try
        {
            if (Interlocked.Increment(ref queued) > 8)
            {
                Interlocked.Decrement(ref queued);
                metrics.QueueRejected();
                metrics.Duration(timeProvider.GetElapsedTime(started));
                throw new AnalysisQueueFullException();
            }

            try
            {
                await concurrency.WaitAsync(deadline.Token);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                metrics.DeadlineExceeded();
                metrics.Duration(timeProvider.GetElapsedTime(started));
                throw new AnalysisDeadlineExceededException();
            }
            finally
            {
                Interlocked.Decrement(ref queued);
            }

            var operation = health.Start();
            work = Task.Run(() =>
            {
                try { return analyze(deadline.Token); }
                finally
                {
                    health.Complete(operation);
                    concurrency.Release();
                }
            }, CancellationToken.None);

            try
            {
                var response = await work.WaitAsync(deadline.Token);
                metrics.Duration(timeProvider.GetElapsedTime(started));
                return response;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                metrics.DeadlineExceeded();
                metrics.Duration(timeProvider.GetElapsedTime(started));
                throw new AnalysisDeadlineExceededException();
            }
        }
        finally
        {
            // The source is disposed only after both sides are done with the token: this
            // method no longer awaits on it once the finally runs, and an abandoned work
            // task keeps observing it until the task completes. Attaching the disposal
            // continuation any earlier races a fast-failing worker against WaitAsync's
            // token registration and turns the failure into an ObjectDisposedException.
            // Observing completed.Exception also keeps the worker's cancellation from
            // surfacing as an unobserved task exception.
            if (work is null)
                deadline.Dispose();
            else
                _ = work.ContinueWith(
                    completed => { _ = completed.Exception; deadline.Dispose(); },
                    CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        }
    }
}

public sealed class AnalysisHealthState(TimeProvider timeProvider)
{
    private readonly ConcurrentDictionary<Guid, DateTimeOffset> active = new();

    public Guid Start()
    {
        var id = Guid.NewGuid();
        active[id] = timeProvider.GetUtcNow();
        return id;
    }

    public void Complete(Guid operation) => active.TryRemove(operation, out _);

    public bool IsReady => IsBelow(TimeSpan.FromSeconds(10));

    public bool IsLive => IsBelow(TimeSpan.FromSeconds(30));

    private bool IsBelow(TimeSpan threshold)
    {
        var now = timeProvider.GetUtcNow();
        return active.Values.All(started => now - started < threshold);
    }
}

public sealed class AnalysisQueueFullException : Exception
{
    public AnalysisQueueFullException() : base("The anonymous validation queue is full.") { }
}

public sealed class AnalysisDeadlineExceededException : Exception
{
    public AnalysisDeadlineExceededException() : base("Static analysis did not finish within five seconds.") { }
}
