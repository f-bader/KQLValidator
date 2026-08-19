using System.Diagnostics.Metrics;

namespace KqlValidator.Operational;

public sealed class AnalysisMetrics : IDisposable
{
    private readonly Meter meter = new("KqlValidator.Analysis", "1.0.0");
    private readonly Counter<long> requests;
    private readonly Counter<long> deadlineExceeded;
    private readonly Counter<long> queueRejected;
    private readonly Histogram<double> duration;

    public AnalysisMetrics()
    {
        requests = meter.CreateCounter<long>("kql.analysis.requests");
        deadlineExceeded = meter.CreateCounter<long>("kql.analysis.deadline_exceeded");
        queueRejected = meter.CreateCounter<long>("kql.analysis.queue_rejected");
        duration = meter.CreateHistogram<double>("kql.analysis.duration", "ms");
    }

    public void Request() => requests.Add(1);
    public void DeadlineExceeded() => deadlineExceeded.Add(1);
    public void QueueRejected() => queueRejected.Add(1);
    public void Duration(TimeSpan elapsed) => duration.Record(elapsed.TotalMilliseconds);
    public void Dispose() => meter.Dispose();
}
