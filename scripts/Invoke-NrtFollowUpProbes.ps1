<#
.SYNOPSIS
Runs twelve focused NRT variants with six control queries.
.DESCRIPTION
Run from a fresh local PowerShell 7 process. Enter sccauth at the masked prompt.
Run twice with separate output directories, then generate a review report with:
dotnet run --project tools/KqlValidator.NrtProbe -- report-follow-up artifacts/nrt/follow-up-report artifacts/nrt/follow-up-a artifacts/nrt/follow-up-b
Results require review of query context and operand details before updating the catalog.
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [switch]$UseExistingConnection,
    [ValidateRange(1, 100)][int]$BatchSize = 12,
    [ValidateRange(2, 10)][int]$Repeats = 2,
    [ValidateRange(0.1, 60)][double]$DelaySeconds = 1
)

$ErrorActionPreference = 'Stop'
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path (Split-Path $PSScriptRoot -Parent) "artifacts/nrt/follow-up/$([guid]::NewGuid())"
}
$parameters = @{
    Suite = 'follow-up'
    OutputDirectory = $OutputDirectory
    UseExistingConnection = $UseExistingConnection
    BatchSize = $BatchSize
    Repeats = $Repeats
    DelaySeconds = $DelaySeconds
}
& "$PSScriptRoot/Invoke-NrtComparisonProbes.ps1" @parameters
