using System.Collections.Concurrent;
using KqlValidator.Contracts;
using KqlValidator.Validation;

namespace KqlValidator.Operational;

public sealed class AnalysisExecutor(KqlValidationService validator, AnalysisHealthState health, AnalysisMetrics metrics)
{
    private static readonly TimeSpan AnalysisDeadline = TimeSpan.FromSeconds(5);
    private readonly SemaphoreSlim concurrency = new(2, 2);
    private int queued;

    public async Task<ValidationResponse> ExecuteAsync(ValidateRequest request, CancellationToken cancellationToken)
    {
        var started = TimeProvider.System.GetTimestamp();
        metrics.Request();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(AnalysisDeadline);

        if (Interlocked.Increment(ref queued) > 8)
        {
            Interlocked.Decrement(ref queued);
            metrics.QueueRejected();
            throw new AnalysisQueueFullException();
        }

        try
        {
            await concurrency.WaitAsync(deadline.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            metrics.DeadlineExceeded();
            throw new AnalysisDeadlineExceededException();
        }
        finally
        {
            Interlocked.Decrement(ref queued);
        }

        var operation = health.Start();
        var work = Task.Run(() =>
        {
            try { return validator.Validate(request, deadline.Token); }
            finally
            {
                health.Complete(operation);
                concurrency.Release();
            }
        }, CancellationToken.None);

        try
        {
            var response = await work.WaitAsync(deadline.Token);
            metrics.Duration(TimeProvider.System.GetElapsedTime(started));
            return response;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            metrics.DeadlineExceeded();
            metrics.Duration(TimeProvider.System.GetElapsedTime(started));
            throw new AnalysisDeadlineExceededException();
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
