<#
.SYNOPSIS
Checks validated comparison fixtures against the Defender NRT compatibility endpoint.
.DESCRIPTION
Run in a dedicated local PowerShell 7 session. Authentication is entered through a
masked prompt, or reused with UseExistingConnection. Exports contain sanitized
compatibility observations. Complete batches can be resumed with OutputDirectory.
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [ValidateSet('comparison', 'follow-up')][string]$Suite = 'comparison',
    [switch]$UseExistingConnection,
    [ValidateRange(1, 100)][int]$BatchSize = 10,
    [ValidateRange(2, 10)][int]$Repeats = 2,
    [ValidateRange(0.1, 60)][double]$DelaySeconds = 1
)

$ErrorActionPreference = 'Stop'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
. "$PSScriptRoot/NrtProbe.Helpers.ps1"
$repoRoot = Split-Path $PSScriptRoot -Parent
$runId = Get-NrtSessionId
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repoRoot "artifacts/nrt/$runId" }
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$manifestPath = Join-Path $OutputDirectory 'manifest.json'
$freshManifestPath = Join-Path $OutputDirectory 'manifest.pending.json'

# Prepare and bind queries before asking for authentication.
$prepareCommand = if ($Suite -eq 'follow-up') { 'prepare-follow-up' } else { 'prepare' }
& dotnet run --project "$repoRoot/tools/KqlValidator.NrtProbe" -- $prepareCommand $freshManifestPath
if ($LASTEXITCODE -ne 0) { throw 'Local fixture validation failed. Authentication has not been requested.' }
$freshText = [IO.File]::ReadAllText($freshManifestPath)
if ((Test-Path $manifestPath) -and [IO.File]::ReadAllText($manifestPath) -cne $freshText) {
    Remove-Item $freshManifestPath
    throw 'The fixture inventory changed. Start a new output directory.'
}
Move-Item $freshManifestPath $manifestPath -Force
$manifest = $freshText | ConvertFrom-Json
$manifestHash = Get-NrtHash $freshText
$fixtures = @($manifest.fixtures | Where-Object { $null -ne $_.feature })
$controls = @($manifest.fixtures | Where-Object { $null -ne $_.expectedStreaming })

Import-Module XDRInternals -RequiredVersion 1.0.23 -ErrorAction Stop
if (-not $UseExistingConnection) {
    $sccauth = Read-Host 'Paste the sccauth cookie' -AsSecureString
    try {
        $null = Set-XdrConnectionSettings -SccAuth $sccauth -ErrorAction Stop -Verbose:$false -Debug:$false -InformationAction Ignore
    } catch {
        throw 'XDR authentication failed. Check the cookie in your local session and retry.'
    } finally {
        $sccauth.Dispose()
        Remove-Variable sccauth
    }
}

# Read only the active tenant identifier from the pinned module's connection headers.
# Hash it before writing any run metadata; connection headers and cookies stay in memory.
$module = Get-Module XDRInternals
try { $tenantId = & $module { $script:headers['x-tid'] } }
catch { throw 'The existing XDR connection is unavailable. Reconnect locally.' }
if ([string]::IsNullOrWhiteSpace($tenantId)) { throw 'The connection has no tenant context. Reconnect locally.' }
$tenantHash = Get-NrtHash $tenantId
Remove-Variable tenantId

for ($offset = 0; $offset -lt $fixtures.Count; $offset += $BatchSize) {
    $groupId = '{0:D4}' -f ($offset / $BatchSize)
    $path = Join-Path $OutputDirectory "batch-$groupId.json"
    $batchFixtures = @($fixtures | Select-Object -Skip $offset -First $BatchSize)
    if (Test-Path $path) {
        $existing = [IO.File]::ReadAllText($path) | ConvertFrom-Json
        if ($existing.manifestHash -ne $manifestHash -or $existing.tenantHash -ne $tenantHash -or
            $existing.moduleVersion -ne $module.Version.ToString()) { throw 'Resume metadata differs. Start a new output directory.' }
        $complete = Test-NrtControls -Observations $existing.observations -Controls $controls
        $expectedIds = @($batchFixtures.id | Sort-Object)
        $actualIds = @($existing.observations | Where-Object phase -eq 'candidate' | Select-Object -ExpandProperty fixtureId -Unique | Sort-Object)
        if (($expectedIds -join ';') -cne ($actualIds -join ';')) { $complete = $false }
        foreach ($fixture in $batchFixtures) {
            $samples = @($existing.observations | Where-Object {
                $_.fixtureId -eq $fixture.id -and $_.phase -eq 'candidate' -and $_.status -eq 'ok' -and $_.queryHash -eq $fixture.queryHash
            } | Select-Object -ExpandProperty repeat -Unique)
            if ($samples.Count -lt $Repeats) { $complete = $false }
        }
        if ($complete) { Write-Host "Batch $groupId already completed; skipping."; continue }
    }
    $observations = [Collections.Generic.List[object]]::new()
    foreach ($control in $controls) { $observations.Add((Invoke-NrtProbe -Fixture $control -Phase before -DelaySeconds $DelaySeconds)) }
    $startHealthy = $true
    foreach ($control in $controls) {
        $record = @($observations | Where-Object fixtureId -eq $control.id)[0]
        if ($record.status -ne 'ok' -or $record.streamingSupported -ne $control.expectedStreaming) { $startHealthy = $false }
    }
    if ($startHealthy) {
        foreach ($fixture in $batchFixtures) {
            for ($repeat = 1; $repeat -le $Repeats; $repeat++) {
                $observations.Add((Invoke-NrtProbe -Fixture $fixture -Phase candidate -Repeat $repeat -DelaySeconds $DelaySeconds))
            }
        }
    }
    foreach ($control in $controls) { $observations.Add((Invoke-NrtProbe -Fixture $control -Phase after -DelaySeconds $DelaySeconds)) }
    $batch = [ordered]@{
        version = 1; runId = $runId; groupId = $groupId; manifestHash = $manifestHash
        parserVersion = $manifest.parserVersion; moduleVersion = $module.Version.ToString()
        tenantHash = $tenantHash; observations = $observations.ToArray()
    }
    [IO.File]::WriteAllText("$path.pending", ($batch | ConvertTo-Json -Depth 20))
    Move-Item "$path.pending" $path -Force
    if (-not (Test-NrtControls -Observations $observations.ToArray() -Controls $controls)) {
        throw 'Compatibility controls failed. This batch is inconclusive. Reconnect or investigate the controls before resuming.'
    }
    Write-Host "Completed batch $groupId ($([Math]::Min($offset + $BatchSize, $fixtures.Count))/$($fixtures.Count) fixtures)."
}
Write-Host "Results saved to $OutputDirectory. Close this dedicated PowerShell process to release the authenticated session."
