# Credential-free tests for the PowerShell request and classification boundary.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/NrtProbe.Helpers.ps1"

function Assert-Nrt {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

Assert-Nrt ((Get-NrtSessionId) -eq (Get-NrtSessionId)) 'The same PowerShell process supplied two independent session IDs.'

Add-Type @'
public sealed class NrtProbeTestHttpException : System.Exception {
    public System.Net.Http.HttpResponseMessage Response { get; }
    public NrtProbeTestHttpException(int status, string message) : base(message) {
        Response = new System.Net.Http.HttpResponseMessage((System.Net.HttpStatusCode)status);
    }
}
'@

$fixture = [pscustomobject]@{ id = 'test'; query = "DeviceProcessEvents`n| where DeviceName has_any (`"test`", `"example`" )"; queryHash = 'synthetic' }
$noWait = { param($seconds) }
$script:calls = 0
$record = Invoke-NrtProbe -Fixture $fixture -Phase candidate -Wait $noWait -Call {
    param($body)
    $script:calls++
    Assert-Nrt (($body | ConvertFrom-Json).QueryText -ceq $fixture.query) 'JSON serialization changed query text.'
    [pscustomobject]@{ IsStreamingDetectionSupported = $false; IsCustomFrequencySupported = $true }
}
Assert-Nrt ($record.status -eq 'ok' -and $record.streamingSupported -ceq $false -and $record.customFrequencySupported -ceq $true) 'Custom frequency incorrectly established NRT support.'
Assert-Nrt ($script:calls -eq 1) 'A successful response was retried.'

foreach ($response in @(
    [pscustomobject]@{ IsStreamingDetectionSupported = 'true' },
    [pscustomobject]@{ IsCustomFrequencySupported = $true },
    '<html>sign in</html>'
)) {
    $call = { param($body) $response }.GetNewClosure()
    $record = Invoke-NrtProbe -Fixture $fixture -Phase candidate -Wait $noWait -Call $call
    Assert-Nrt ($record.status -eq 'invalid-response' -and $null -eq $record.streamingSupported) 'Malformed response established support.'
}

$script:calls = 0
$script:waits = [Collections.Generic.List[double]]::new()
$record = Invoke-NrtProbe -Fixture $fixture -Phase candidate -DelaySeconds 0 -Wait { param($seconds) $script:waits.Add($seconds) } -Call {
    param($body)
    $script:calls++
    if ($script:calls -eq 1) {
        $failure = [NrtProbeTestHttpException]::new(429, 'synthetic-secret')
        $failure.Response.Headers.RetryAfter = [Net.Http.Headers.RetryConditionHeaderValue]::new([TimeSpan]::FromSeconds(45))
        throw $failure
    }
    [pscustomobject]@{ IsStreamingDetectionSupported = $true }
}
Assert-Nrt ($record.status -eq 'ok' -and $script:calls -eq 2) 'Throttled request did not recover.'
Assert-Nrt ($script:waits.Contains(30) -and $script:waits.Contains(15)) 'Retry-After was not honored in bounded waits.'

$script:calls = 0
$record = Invoke-NrtProbe -Fixture $fixture -Phase candidate -Wait $noWait -Call {
    param($body)
    $script:calls++
    throw [NrtProbeTestHttpException]::new(503, 'synthetic-secret')
}
Assert-Nrt ($record.status -eq 'http-error' -and $record.httpStatus -eq 503 -and $null -eq $record.streamingSupported -and $script:calls -eq 3) 'Exhausted retries incorrectly established support.'
Assert-Nrt (($record | ConvertTo-Json) -notmatch 'synthetic-secret') 'Failure output contains raw exception text.'

foreach ($authenticationStatus in 401, 403) {
    $script:calls = 0
    $caught = $null
    try {
        $null = Invoke-NrtProbe -Fixture $fixture -Phase candidate -Wait $noWait -Call {
            param($body)
            $script:calls++
            throw [NrtProbeTestHttpException]::new($authenticationStatus, 'synthetic-secret')
        }
    } catch { $caught = $_.Exception.Message }
    Assert-Nrt ($script:calls -eq 1 -and $caught -match 'Reconnect locally' -and $caught -notmatch 'synthetic-secret') 'Authentication failure was retried or exposed raw exception text.'
}

# Exercise the production call adapter against the inspected module's error pattern.
function Invoke-XdrRestMethod {
    [CmdletBinding()]
    param($Uri, $Method, $ContentType, $Body)
    Assert-Nrt ($Uri -eq 'https://security.microsoft.com/apiproxy/hunting/huntingService/rules/checkCompatibility' -and $Method -eq 'POST') 'Production adapter used an unexpected endpoint or method.'
    try { throw [NrtProbeTestHttpException]::new(401, 'synthetic-secret') }
    catch { Write-Error "Module wrapper: $_"; throw }
}
$caught = $null
try { $null = Invoke-NrtProbe -Fixture $fixture -Phase candidate -Wait $noWait }
catch { $caught = $_.Exception.Message }
Assert-Nrt ($caught -match 'Reconnect locally' -and $caught -notmatch 'synthetic-secret') 'Module error wrapping lost the original HTTP exception or leaked error text.'


$tokens = $null
$errors = $null
$null = [Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot/Invoke-NrtComparisonProbes.ps1", [ref]$tokens, [ref]$errors)
Assert-Nrt ($errors.Count -eq 0) 'The probe runner has a PowerShell syntax error.'
$null = [Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot/Invoke-NrtFollowUpProbes.ps1", [ref]$tokens, [ref]$errors)
Assert-Nrt ($errors.Count -eq 0) 'The follow-up runner has a PowerShell syntax error.'
Write-Host 'PowerShell probe checks passed.'
