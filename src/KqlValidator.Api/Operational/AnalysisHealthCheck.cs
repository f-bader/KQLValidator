using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace KqlValidator.Operational;

public sealed class AnalysisHealthCheck(AnalysisHealthState state) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default) =>
        Task.FromResult(state.IsHealthy
            ? HealthCheckResult.Healthy()
            : HealthCheckResult.Unhealthy("A KQL analysis has exceeded the 30-second safety threshold."));
}
