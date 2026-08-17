using System.Collections.Concurrent;
using KqlValidator.Contracts;
using KqlValidator.Validation;

namespace KqlValidator.Operational;

public sealed class AnalysisExecutor(KqlValidationService validator, AnalysisHealthState health)
{
    private readonly SemaphoreSlim concurrency = new(2, 2);
    private int queued;

    public async Task<ValidationResponse> ExecuteAsync(ValidateRequest request, CancellationToken cancellationToken)
    {
        if (Interlocked.Increment(ref queued) > 10)
        {
            Interlocked.Decrement(ref queued);
            throw new AnalysisQueueFullException();
        }

        try
        {
            await concurrency.WaitAsync(cancellationToken);
        }
        finally
        {
            Interlocked.Decrement(ref queued);
        }

        var operation = health.Start();
        var work = Task.Run(() =>
        {
            try { return validator.Validate(request); }
            finally
            {
                health.Complete(operation);
                concurrency.Release();
            }
        }, CancellationToken.None);

        return await work.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);
    }
}

public sealed class AnalysisHealthState
{
    private readonly ConcurrentDictionary<Guid, DateTimeOffset> active = new();

    public Guid Start()
    {
        var id = Guid.NewGuid();
        active[id] = DateTimeOffset.UtcNow;
        return id;
    }

    public void Complete(Guid operation) => active.TryRemove(operation, out _);

    public bool IsHealthy => active.Values.All(x => DateTimeOffset.UtcNow - x < TimeSpan.FromSeconds(30));
}

public sealed class AnalysisQueueFullException : Exception
{
    public AnalysisQueueFullException() : base("The anonymous validation queue is full.") { }
}
