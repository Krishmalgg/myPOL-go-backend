[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [int] $ServerPid,

    [string] $BaseUrl = "http://127.0.0.1:8080",
    [string] $Report = "..\docs\performance\canvas-realtime-load-test-report.md",
    [string[]] $LoadArgs = @()
)

$ErrorActionPreference = "Stop"
$goDir = Split-Path -Parent $PSScriptRoot
$reportPath = [System.IO.Path]::GetFullPath((Join-Path $goDir $Report))
$statsPath = "$reportPath.server-stats.json"
$server = Get-Process -Id $ServerPid -ErrorAction Stop

# Get-Process exposes cumulative CPU seconds and working-set bytes. Sampling
# those values while the Go runner is active gives a reproducible Windows-side
# CPU/RAM measurement without adding an OS-specific dependency to cmd/loadtest.
$sampleJob = Start-Job -ArgumentList $ServerPid -ScriptBlock {
    param($PidToSample)
    while ($true) {
        try {
            $process = Get-Process -Id $PidToSample -ErrorAction Stop
            [pscustomobject]@{
                timestamp = [DateTime]::UtcNow.ToString("o")
                cpuSeconds = [double]$process.CPU
                workingSetBytes = [int64]$process.WorkingSet64
            }
        } catch {
            break
        }
        Start-Sleep -Milliseconds 500
    }
}

$exitCode = 1
try {
    Push-Location $goDir
    $runnerArgs = @("run", "./cmd/loadtest", "-base-url", $BaseUrl, "-report", $reportPath) + $LoadArgs
    & go @runnerArgs
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
    Stop-Job $sampleJob -ErrorAction SilentlyContinue
    $samples = @(Receive-Job $sampleJob -ErrorAction SilentlyContinue)
    Remove-Job $sampleJob -Force -ErrorAction SilentlyContinue

    $cpuPercent = $null
    if ($samples.Count -ge 2) {
        $first = $samples[0]
        $last = $samples[$samples.Count - 1]
        $wallSeconds = ([DateTime]::Parse($last.timestamp) - [DateTime]::Parse($first.timestamp)).TotalSeconds
        if ($wallSeconds -gt 0) {
            $cpuPercent = (($last.cpuSeconds - $first.cpuSeconds) / $wallSeconds) / [Environment]::ProcessorCount * 100
        }
    }

    $stats = [pscustomobject]@{
        capturedAt = [DateTime]::UtcNow.ToString("o")
        processId = $ServerPid
        sampleCount = $samples.Count
        cpuPercentAverage = $cpuPercent
        peakRamBytes = if ($samples.Count -gt 0) { ($samples | Measure-Object -Property workingSetBytes -Maximum).Maximum } else { $null }
        samples = $samples
    }
    $stats | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statsPath -Encoding UTF8
    Write-Host "Server CPU/RAM samples: $statsPath"
}

exit $exitCode
