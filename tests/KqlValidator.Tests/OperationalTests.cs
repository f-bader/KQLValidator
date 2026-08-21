using KqlValidator.Contracts;
using KqlValidator.Operational;

namespace KqlValidator.Tests;

public sealed class OperationalTests
{
    private static readonly ValidateRequest AnyRequest = new("DeviceEvents | take 1", KqlEnvironment.Xdr, LintProfile.General);

    private static ValidationResponse FastResponse() =>
        new(true, "test", "test", [], [], [], [], [], 0);

    private static AnalysisExecutor Executor(
        Func<ValidateRequest, CancellationToken, ValidationResponse> validate,
        TimeSpan? deadline = null) =>
        new(validate, new AnalysisHealthState(TimeProvider.System), new AnalysisMetrics(), TimeProvider.System,
            deadline ?? TimeSpan.FromMilliseconds(250));

    [Fact]
    public async Task Deadline_cancels_spinning_analysis_and_frees_the_permit()
    {
        var calls = 0;
        var executor = Executor((_, token) =>
        {
            if (Interlocked.Increment(ref calls) <= 2)
            {
                while (true)
                {
                    token.ThrowIfCancellationRequested();
                    Thread.Sleep(10);
                }
            }

            return FastResponse();
        });

        await Assert.ThrowsAsync<AnalysisDeadlineExceededException>(
            () => executor.ExecuteAsync(AnyRequest, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<AnalysisDeadlineExceededException>(
            () => executor.ExecuteAsync(AnyRequest, TestContext.Current.CancellationToken));

        // Both abandoned analyses observe their tokens and release their permits, so a
        // subsequent fast request must find a free slot within the deadline.
        var response = await executor.ExecuteAsync(AnyRequest, TestContext.Current.CancellationToken);
        Assert.True(response.Valid);
    }

    [Fact]
    public async Task Queue_overflow_is_rejected_with_queue_full()
    {
        using var release = new ManualResetEventSlim();
        var executor = Executor((_, token) =>
        {
            release.Wait(token);
            return FastResponse();
        }, TimeSpan.FromSeconds(30));

        // Two analyses occupy the permits; eight more fill the queue.
        var inFlight = Enumerable.Range(0, 10)
            .Select(_ => executor.ExecuteAsync(AnyRequest, TestContext.Current.CancellationToken))
            .ToArray();

        await Assert.ThrowsAsync<AnalysisQueueFullException>(
            () => executor.ExecuteAsync(AnyRequest, TestContext.Current.CancellationToken));

        release.Set();
        await Task.WhenAll(inFlight);
        Assert.All(inFlight, task => Assert.True(task.Result.Valid));
    }

    [Fact]
    public async Task Client_cancellation_propagates_instead_of_reporting_a_deadline()
    {
        var executor = Executor((_, _) => FastResponse());
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => executor.ExecuteAsync(AnyRequest, cancelled.Token));
    }

    [Fact]
    public void Analysis_health_recovers_after_operation_completes()
    {
        var clock = new AdjustableTimeProvider();
        var state = new AnalysisHealthState(clock);
        var operation = state.Start();

        clock.Advance(TimeSpan.FromSeconds(11));
        Assert.False(state.IsReady);
        Assert.True(state.IsLive);
        clock.Advance(TimeSpan.FromSeconds(20));
        Assert.False(state.IsLive);

        state.Complete(operation);
        Assert.True(state.IsReady);
        Assert.True(state.IsLive);
    }

    private sealed class AdjustableTimeProvider : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.UnixEpoch;

        public override DateTimeOffset GetUtcNow() => now;

        public void Advance(TimeSpan duration) => now += duration;
    }
}
