using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace KqlValidator.Operational;

public sealed class AnalysisReadinessHealthCheck(AnalysisHealthState state) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default) =>
        Task.FromResult(state.IsReady
            ? HealthCheckResult.Healthy()
            : HealthCheckResult.Unhealthy("A KQL analysis has exceeded the 10-second readiness threshold."));
}

public sealed class AnalysisLivenessHealthCheck(AnalysisHealthState state) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default) =>
        Task.FromResult(state.IsLive
            ? HealthCheckResult.Healthy()
            : HealthCheckResult.Unhealthy("A KQL analysis has exceeded the 30-second liveness threshold."));
}
