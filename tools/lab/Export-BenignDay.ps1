<#
.SYNOPSIS
    Exports one UTC day of benign telemetry and records whether it is a complete host-day
    (docs/validation-protocol.md, sections 6 and 10).

.DESCRIPTION
    UNUSED: round 1 was stopped before execution. This script has never been run against a real host; it is
    kept only as part of the documented plan in docs/validation-protocol.md.

    For the given UTC day (default: yesterday), exports the Sysmon, Security, System and PowerShell channels
    to <OutDir>\<COMPUTERNAME>\<yyyy-MM-dd>\*.evtx and writes host-day.json with the evidence for the
    protocol's completeness rule:

      - the oldest event still retained in each channel predates the start of the day (nothing rolled over);
      - no log-clear event during the day (Security 1102, System 104);
      - no Sysmon configuration change (Sysmon 16) during the day;
      - no Sysmon gap: every "Stopped" state change (Sysmon 4) is followed within 5 minutes by a Windows
        shutdown or restart (System 1074 or 6006). Shutting the machine down is not a gap; Sysmon stopping
        while Windows keeps running is;
      - at least 4 active hours: distinct UTC hours with at least one Sysmon event. A day the machine spent
        switched off is not a host-day.

    "complete" in host-day.json is true only if every condition holds. Incomplete days are kept and
    counted, never silently dropped.

    Run it daily as SYSTEM, shortly after 00:00 UTC, on the real endpoint and on every benign lab VM. The
    evtx files from the real endpoint contain personal activity and stay on that machine. Only the
    alert table derived from them is published.

    Windows PowerShell 5.1.
#>
param(
    [string] $Day = ([DateTime]::UtcNow.Date.AddDays(-1).ToString('yyyy-MM-dd')),
    [string] $OutDir = 'C:\round1-benign'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$start = [DateTime]::ParseExact($Day, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]'AssumeUniversal,AdjustToUniversal')
$end = $start.AddDays(1)
if ($end -gt [DateTime]::UtcNow) { throw "$Day has not ended yet (UTC)" }

$channels = @('Microsoft-Windows-Sysmon/Operational', 'Security', 'System', 'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell')
$target = Join-Path (Join-Path $OutDir $env:COMPUTERNAME) $Day
New-Item -ItemType Directory -Force -Path $target | Out-Null

$fmt = 'yyyy-MM-ddTHH:mm:ss.fffZ'
$window = "@SystemTime>='{0}' and @SystemTime<'{1}'" -f $start.ToString($fmt), $end.ToString($fmt)
$query = "*[System[TimeCreated[$window]]]"

function Count-Events($Log, [int[]] $Ids) {
    $idFilter = ($Ids | ForEach-Object { "EventID=$_" }) -join ' or '
    $xpath = "*[System[($idFilter) and TimeCreated[$window]]]"
    return @(Get-WinEvent -LogName $Log -FilterXPath $xpath -ErrorAction SilentlyContinue).Count
}

$logs = New-Object System.Collections.ArrayList
$complete = $true
foreach ($channel in $channels) {
    $file = Join-Path $target (($channel -replace '[/ ]', '_') + '.evtx')
    if (Test-Path $file) { Remove-Item $file -Force }
    & wevtutil epl $channel $file "/q:$query"
    if ($LASTEXITCODE -ne 0) { throw "wevtutil failed to export $channel" }
    $oldest = Get-WinEvent -LogName $channel -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue
    $oldestUtc = $(if ($oldest) { $oldest.TimeCreated.ToUniversalTime() } else { $null })
    $covers = [bool]($oldestUtc -and $oldestUtc -lt $start)
    # Windows PowerShell (classic) is exported for completeness but does not decide the host-day.
    if ($channel -ne 'Windows PowerShell' -and -not $covers) { $complete = $false }
    [void]$logs.Add([ordered]@{
        channel = $channel; file = (Split-Path $file -Leaf)
        sha256 = (Get-FileHash $file -Algorithm SHA256).Hash.ToLower()
        oldest_retained_utc = $(if ($oldestUtc) { $oldestUtc.ToString('o') } else { $null })
        covers_day = $covers
    })
}

$sysmon = 'Microsoft-Windows-Sysmon/Operational'
$clears = (Count-Events 'Security' @(1102)) + (Count-Events 'System' @(104))
$configChanges = Count-Events $sysmon @(16)

$gaps = 0
$stops = @(Get-WinEvent -LogName $sysmon -FilterXPath "*[System[EventID=4 and TimeCreated[$window]]]" -ErrorAction SilentlyContinue |
    Where-Object { $_.ToXml() -match 'Stopped' })
foreach ($stop in $stops) {
    $from = $stop.TimeCreated.ToUniversalTime()
    $shutdownWindow = "@SystemTime>='{0}' and @SystemTime<='{1}'" -f $from.ToString($fmt), $from.AddMinutes(5).ToString($fmt)
    $shutdown = Get-WinEvent -LogName System -MaxEvents 1 -ErrorAction SilentlyContinue `
        -FilterXPath "*[System[(EventID=1074 or EventID=6006) and TimeCreated[$shutdownWindow]]]"
    if (-not $shutdown) { $gaps++ }
}

$activeHours = 0
for ($hour = 0; $hour -lt 24; $hour++) {
    $h0 = $start.AddHours($hour); $h1 = $h0.AddHours(1)
    $hourWindow = "@SystemTime>='{0}' and @SystemTime<'{1}'" -f $h0.ToString($fmt), $h1.ToString($fmt)
    if (Get-WinEvent -LogName $sysmon -MaxEvents 1 -FilterXPath "*[System[TimeCreated[$hourWindow]]]" -ErrorAction SilentlyContinue) {
        $activeHours++
    }
}

if ($clears -gt 0 -or $configChanges -gt 0 -or $gaps -gt 0 -or $activeHours -lt 4) { $complete = $false }

$record = [ordered]@{
    computer = $env:COMPUTERNAME; day_utc = $Day; exported_utc = [DateTime]::UtcNow.ToString('o')
    complete = $complete; active_hours = $activeHours; log_clears = $clears
    sysmon_config_changes = $configChanges; sysmon_stops = $stops.Count; sysmon_gaps = $gaps
    w32tm = (& w32tm /query /status) -join "`n"; logs = $logs
}
$record | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 (Join-Path $target 'host-day.json')
Write-Host ("{0} {1}: {2}" -f $env:COMPUTERNAME, $Day, $(if ($complete) { 'complete host-day' } else { 'INCOMPLETE - kept and counted' }))
