Set-StrictMode -Version Latest

function Get-NrtSessionId {
    # Reusing the same PowerShell process must not count as an independent session.
    $existing = Get-Variable -Name KqlValidatorNrtProbeSessionId -Scope Global -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        Set-Variable -Name KqlValidatorNrtProbeSessionId -Scope Global -Value ([guid]::NewGuid().ToString())
    }
    (Get-Variable -Name KqlValidatorNrtProbeSessionId -Scope Global).Value
}

function Get-NrtHash {
    param([Parameter(Mandatory)][string]$Text)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text))).ToLowerInvariant()
}

function Get-NrtHttpFailure {
    param([Parameter(Mandatory)]$Record)
    $status = $null
    $retryAfter = $null
    $exception = $Record.Exception
    while ($null -ne $exception) {
        if ($exception.PSObject.Properties['Response'] -and $exception.Response) {
            $response = $exception.Response
            if ($response.PSObject.Properties['StatusCode']) { $status = [int]$response.StatusCode }
            if ($response.PSObject.Properties['Headers'] -and $response.Headers) {
                try {
                    $header = $response.Headers.RetryAfter
                    if ($header.Delta) { $retryAfter = $header.Delta.TotalSeconds }
                    elseif ($header.Date) { $retryAfter = [Math]::Max(0, ($header.Date - [DateTimeOffset]::UtcNow).TotalSeconds) }
                } catch { }
            }
        }
        $exception = $exception.InnerException
    }
    @{ Status = $status; RetryAfter = $retryAfter }
}

function Invoke-NrtProbe {
    param(
        [Parameter(Mandatory)]$Fixture,
        [Parameter(Mandatory)][string]$Phase,
        [int]$Repeat = 1,
        [ValidateRange(1, 10)][int]$MaxAttempts = 3,
        [ValidateRange(0, 60)][double]$DelaySeconds = 1,
        [scriptblock]$Call = {
            param($body)
            # XDRInternals writes a nonterminating error before rethrowing the HTTP
            # exception. Keep that rethrow so status/Retry-After remain available.
            Invoke-XdrRestMethod -Uri 'https://security.microsoft.com/apiproxy/hunting/huntingService/rules/checkCompatibility' `
                -Method POST -ContentType 'application/json' -Body $body -ErrorAction SilentlyContinue -Verbose:$false -Debug:$false `
                -WarningAction SilentlyContinue -InformationAction Ignore 2>$null
        },
        [scriptblock]$Wait = { param($seconds) Start-Sleep -Seconds $seconds }
    )
    $body = @{ QueryText = $Fixture.query } | ConvertTo-Json -Compress
    $status = 'transport-error'
    $httpStatus = $null
    $streaming = $null
    $custom = $null
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        & $Wait $DelaySeconds
        try {
            $result = & $Call $body
            $httpStatus = 200
            if ($null -ne $result -and $result.PSObject.Properties['IsStreamingDetectionSupported'] -and
                $result.IsStreamingDetectionSupported -is [bool]) {
                $streaming = $result.IsStreamingDetectionSupported
                if ($result.PSObject.Properties['IsCustomFrequencySupported'] -and $result.IsCustomFrequencySupported -is [bool]) {
                    $custom = $result.IsCustomFrequencySupported
                }
                $status = 'ok'
            } else { $status = 'invalid-response' }
            break
        } catch {
            $failure = Get-NrtHttpFailure $_
            $httpStatus = $failure.Status
            if ($httpStatus -in 401, 403) {
                throw 'Authentication or permissions failed. Reconnect locally and resume the probe run.'
            }
            $status = if ($null -eq $httpStatus) { 'transport-error' } else { 'http-error' }
            if ($attempt -eq $MaxAttempts -or ($null -ne $httpStatus -and $httpStatus -ne 429 -and $httpStatus -lt 500)) { break }
            $seconds = if ($null -ne $failure.RetryAfter) { $failure.RetryAfter } else { [Math]::Pow(2, $attempt) }
            # Split long Retry-After intervals into interruptible waits.
            while ($seconds -gt 0) {
                $chunk = [Math]::Min(30, $seconds)
                & $Wait $chunk
                $seconds -= $chunk
            }
        }
    }
    [pscustomobject][ordered]@{
        fixtureId = $Fixture.id
        queryHash = $Fixture.queryHash
        phase = $Phase
        repeat = $Repeat
        observedAt = [DateTimeOffset]::UtcNow.ToString('O')
        status = $status
        streamingSupported = $streaming
        customFrequencySupported = $custom
        httpStatus = $httpStatus
    }
}

function Test-NrtControls {
    param([Parameter(Mandatory)][array]$Observations, [Parameter(Mandatory)][array]$Controls)
    foreach ($phase in 'before', 'after') {
        foreach ($control in $Controls) {
            $records = @($Observations | Where-Object { $_.fixtureId -eq $control.id -and $_.phase -eq $phase })
            if ($records.Count -ne 1 -or $records[0].status -ne 'ok' -or
                $records[0].httpStatus -ne 200 -or $records[0].streamingSupported -isnot [bool] -or
                $records[0].queryHash -ne $control.queryHash -or
                $records[0].streamingSupported -ne $control.expectedStreaming) { return $false }
        }
    }
    return $true
}
