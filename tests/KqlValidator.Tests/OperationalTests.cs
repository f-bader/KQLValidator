using KqlValidator.Operational;

namespace KqlValidator.Tests;

public sealed class OperationalTests
{
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
