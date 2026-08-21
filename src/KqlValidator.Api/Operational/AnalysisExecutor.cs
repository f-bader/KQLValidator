using System.Collections.Concurrent;
using KqlValidator.Contracts;
using KqlValidator.Validation;

namespace KqlValidator.Operational;

public sealed class AnalysisExecutor(KqlValidationService validator, AnalysisHealthState health, AnalysisMetrics metrics, TimeProvider timeProvider)
{
    private static readonly TimeSpan AnalysisDeadline = TimeSpan.FromSeconds(5);
    private readonly SemaphoreSlim concurrency = new(2, 2);
    private int queued;

    public async Task<ValidationResponse> ExecuteAsync(ValidateRequest request, CancellationToken cancellationToken)
    {
        var started = timeProvider.GetTimestamp();
        metrics.Request();
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(AnalysisDeadline);
        var workStarted = false;

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
            var work = Task.Run(() =>
            {
                try { return validator.Validate(request, deadline.Token); }
                finally
                {
                    health.Complete(operation);
                    concurrency.Release();
                }
            }, CancellationToken.None);
            workStarted = true;
            // An abandoned work task keeps observing the linked token after a deadline
            // response has already been sent, so the source must outlive this method;
            // observing t.Exception also keeps the worker's cancellation from surfacing
            // as an unobserved task exception.
            _ = work.ContinueWith(
                completed => { _ = completed.Exception; deadline.Dispose(); },
                CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);

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
            if (!workStarted)
                deadline.Dispose();
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
