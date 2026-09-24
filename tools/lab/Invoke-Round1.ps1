<#
.SYNOPSIS
    Runs round 1 of the validation protocol on the attack VM, one ART test at a time.

.DESCRIPTION
    Implements docs/validation-protocol.md, section 8, for every ART test of every sampled rule in
    docs/validation/sample.json:

      1. restore the clean snapshot, boot, settle 5 minutes
      2. -GetPrereqs, then -CheckPrereqs ("Prerequisites met" or the test is recorded as prerequisites failed)
      3. quiet period, 5 minutes (the null window is cut from it at analysis time)
      4. t0, run the test, t1 (guest clock); exit code from the runner's execution log
      5. wait until t1 + 60 s, then -Cleanup
      6. export the event logs and copy them to the host
      7. turn the VM off

    With no switch the script only prints the plan. -SmokeTest runs one cycle with a harmless command instead
    of an ART test, to prove the orchestration works. -Execute runs the protocol.

    Each test's record is written to <ResultsDir>\<rule rank and technique>\<test guid>\result.json. A test that
    already has a result.json is skipped, so an interrupted run can be resumed.

    The VM is controlled through a provider with five operations: restore snapshot, start, wait until ready
    (which returns a PowerShell session into the guest), stop, and a snapshot check. Everything that runs in
    the guest goes through that session, so the protocol steps are identical on every hypervisor.

      -Hypervisor VirtualBox  VBoxManage; guest commands over WinRM to -GuestAddress on a host-only network.
                              Works on Windows Home, which has no Hyper-V.
      -Hypervisor HyperV      Hyper-V cmdlets; guest commands over PowerShell Direct (no guest network needed).

    Written for Windows PowerShell 5.1 on the host (run elevated). Test arguments are passed as parameters,
    never embedded in the script block text, so the guest's script-block log does not carry the technique
    being tested.
#>
[CmdletBinding(DefaultParameterSetName = 'Plan')]
param(
    [ValidateSet('VirtualBox', 'HyperV')] [string] $Hypervisor,
    [string] $VMName = 'ROUND1-ATK',
    [string] $CheckpointName = 'round1-clean',
    [pscredential] $Credential,
    [string] $GuestAddress = '192.168.56.10',
    [string] $VBoxManage,
    [string] $SamplePath = (Join-Path $PSScriptRoot '..\..\docs\validation\sample.json'),
    [string] $ResultsDir = (Join-Path $PSScriptRoot '..\..\output\round1'),
    [string] $GuestAtomics = 'C:\AtomicRedTeam\atomics',
    [string] $GuestModule = 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1',
    [string] $GuestWork = 'C:\round1',
    [int] $SettleSeconds = 300,
    [int] $QuietSeconds = 300,
    [int] $TimeoutSeconds = 300,
    [int] $PostWindowSeconds = 65,
    [string[]] $Technique,
    [Parameter(ParameterSetName = 'Execute')] [switch] $Execute,
    [Parameter(ParameterSetName = 'Smoke')] [switch] $SmokeTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$Channels = @(
    'Microsoft-Windows-Sysmon/Operational',
    'Security',
    'System',
    'Microsoft-Windows-PowerShell/Operational',
    'Windows PowerShell'
)

function Get-Plan {
    $sample = Get-Content -Raw -Encoding UTF8 $SamplePath | ConvertFrom-Json
    $plan = New-Object System.Collections.ArrayList
    foreach ($tier in @('strong', 'moderate', 'weak')) {
        foreach ($rule in $sample.strata.$tier) {
            if (-not $rule.selected) { continue }
            if ($Technique -and ($Technique -notcontains $rule.technique_id)) { continue }
            foreach ($test in $rule.art_tests) {
                [void]$plan.Add([pscustomobject]@{
                    tier = $tier; rank = [int]$rule.rank; technique_id = $rule.technique_id
                    rule_id = $rule.rule_id; rule_file = $rule.rule_file
                    test_guid = $test.guid; test_name = $test.name; executor = $test.executor
                })
            }
        }
    }
    return @{ seed = $sample.seed; tests = $plan }
}

function Get-ResultPath($item) {
    $folder = '{0}-{1:D2}-{2}' -f $item.tier, $item.rank, $item.technique_id
    return Join-Path (Join-Path $ResultsDir $folder) $item.test_guid
}

# --------------------------------------------------------------------------- #
# Providers: restore snapshot, start, wait-ready (returns a guest session), stop
# --------------------------------------------------------------------------- #
function Invoke-VBoxManage {
    # VBoxManage writes progress to stderr; under 'Stop', Windows PowerShell 5.1 would throw on it.
    $ErrorActionPreference = 'Continue'
    $output = & $VBoxManage @args 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "VBoxManage $($args -join ' ') failed ($LASTEXITCODE): $output" }
    return $output
}

function Get-VBoxState {
    $info = Invoke-VBoxManage showvminfo $VMName --machinereadable
    if ($info -match '(?m)^VMState="([^"]+)"') { return $Matches[1] }
    throw "VBoxManage showvminfo did not report VMState for $VMName"
}

function New-LabProvider([string] $Name) {
    if ($Name -eq 'VirtualBox') {
        return @{
            Name = 'VirtualBox'
            Version = { (Invoke-VBoxManage --version).Trim() }
            SnapshotExists = {
                $ErrorActionPreference = 'Continue'
                & $VBoxManage snapshot $VMName showvminfo $CheckpointName *> $null
                return ($LASTEXITCODE -eq 0)
            }
            Stop = {
                if ((Get-VBoxState) -in @('running', 'paused', 'starting', 'stuck')) {
                    Invoke-VBoxManage controlvm $VMName poweroff | Out-Null
                }
                $deadline = (Get-Date).AddMinutes(2)
                while ((Get-VBoxState) -notin @('poweroff', 'aborted', 'saved')) {
                    if ((Get-Date) -gt $deadline) { throw "$VMName did not power off" }
                    Start-Sleep -Seconds 2
                }
            }
            Restore = { Invoke-VBoxManage snapshot $VMName restore $CheckpointName | Out-Null }
            Start = { Invoke-VBoxManage startvm $VMName --type headless | Out-Null }
            NewSession = { New-PSSession -ComputerName $GuestAddress -Credential $Credential -ErrorAction Stop }
        }
    }
    return @{
        Name = 'Hyper-V'
        Version = { (Get-CimInstance Win32_OperatingSystem).Version }
        SnapshotExists = { [bool](Get-VMCheckpoint -VMName $VMName -Name $CheckpointName -ErrorAction SilentlyContinue) }
        Stop = { Stop-VM -Name $VMName -TurnOff -Force -ErrorAction SilentlyContinue }
        Restore = { Restore-VMCheckpoint -VMName $VMName -Name $CheckpointName -Confirm:$false }
        Start = { Start-VM -Name $VMName }
        NewSession = { New-PSSession -VMName $VMName -Credential $Credential -ErrorAction Stop }
    }
}

function Wait-GuestSession($Provider) {
    $deadline = (Get-Date).AddMinutes(10)
    $last = ''
    while ((Get-Date) -lt $deadline) {
        try { return & $Provider.NewSession }
        catch { $last = $_.Exception.Message; Start-Sleep -Seconds 5 }
    }
    throw "No guest session to $VMName through $($Provider.Name) within 10 minutes: $last"
}

function Invoke-Guest($Session, [scriptblock] $Block, [object[]] $Arguments) {
    if ($Arguments) { return Invoke-Command -Session $Session -ScriptBlock $Block -ArgumentList $Arguments }
    return Invoke-Command -Session $Session -ScriptBlock $Block
}

$GuestNow = { [DateTime]::UtcNow.ToString('o') }
$GuestTime = { (& w32tm /query /status) -join "`n" }

$GuestPreflight = {
    param($Work)
    New-Item -ItemType Directory -Force -Path $Work | Out-Null
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $mp = Get-MpComputerStatus
    [pscustomobject]@{
        elevated              = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        realtime_protection   = [bool]$mp.RealTimeProtectionEnabled
        tamper_protection     = [bool]$mp.IsTamperProtected
        computer              = $env:COMPUTERNAME
        os_build              = [Environment]::OSVersion.Version.ToString()
    }
}

$GuestPrereqs = {
    param($Technique, $Guid, $Atomics, $Module, $Timeout)
    Import-Module $Module -Force
    $get = Invoke-AtomicTest $Technique -TestGuids $Guid -PathToAtomicsFolder $Atomics -GetPrereqs -TimeoutSeconds $Timeout *>&1 | Out-String
    $check = Invoke-AtomicTest $Technique -TestGuids $Guid -PathToAtomicsFolder $Atomics -CheckPrereqs -TimeoutSeconds $Timeout *>&1 | Out-String
    [pscustomobject]@{ get_output = $get; check_output = $check; met = [bool]($check -match 'Prerequisites met:') }
}

$GuestExecute = {
    param($Technique, $Guid, $Atomics, $Timeout, $Log)
    if (Test-Path $Log) { Remove-Item $Log -Force }
    $t0 = [DateTime]::UtcNow
    $output = Invoke-AtomicTest $Technique -TestGuids $Guid -PathToAtomicsFolder $Atomics -TimeoutSeconds $Timeout `
        -LoggingModule 'Default-ExecutionLogger' -ExecutionLogPath $Log *>&1 | Out-String
    $t1 = [DateTime]::UtcNow
    $row = $null
    if (Test-Path $Log) { $row = Import-Csv $Log | Where-Object { $_.GUID -eq $Guid } | Select-Object -Last 1 }
    [pscustomobject]@{
        t0 = $t0.ToString('o'); t1 = $t1.ToString('o'); output = $output
        exit_code = $(if ($row) { $row.ExitCode } else { $null })
        timed_out = [bool]($output -match 'Process Timed out')
    }
}

$GuestSmoke = {
    param($Log)
    $t0 = [DateTime]::UtcNow
    $output = & cmd.exe /c 'echo round1-smoke' 2>&1 | Out-String
    $t1 = [DateTime]::UtcNow
    [pscustomobject]@{ t0 = $t0.ToString('o'); t1 = $t1.ToString('o'); output = $output; exit_code = "$LASTEXITCODE"; timed_out = $false }
}

$GuestCleanup = {
    param($Technique, $Guid, $Atomics, $Timeout)
    Invoke-AtomicTest $Technique -TestGuids $Guid -PathToAtomicsFolder $Atomics -Cleanup -TimeoutSeconds $Timeout *>&1 | Out-String
}

$GuestExport = {
    param($Work, $Channels)
    $out = Join-Path $Work 'evtx'
    if (Test-Path $out) { Remove-Item $out -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    foreach ($channel in $Channels) {
        $file = Join-Path $out (($channel -replace '[/ ]', '_') + '.evtx')
        & wevtutil epl $channel $file
    }
    return $out
}

function Invoke-OneTest($item, [switch] $Smoke) {
    $resultPath = Get-ResultPath $item
    if (Test-Path (Join-Path $resultPath 'result.json')) {
        Write-Host "skip  $($item.technique_id) $($item.test_guid) (already recorded)"
        return
    }
    New-Item -ItemType Directory -Force -Path $resultPath | Out-Null
    $record = [ordered]@{
        protocol = 'docs/validation-protocol.md'; smoke_test = [bool]$Smoke
        tier = $item.tier; rank = $item.rank; technique_id = $item.technique_id; rule_id = $item.rule_id
        test_guid = $item.test_guid; test_name = $item.test_name; executor = $item.executor
        hypervisor = $Provider.Name; hypervisor_version = $HypervisorVersion
        vm = $VMName; snapshot = $CheckpointName
        host_started_utc = [DateTime]::UtcNow.ToString('o')
    }
    Write-Host "start $($item.tier) #$($item.rank) $($item.technique_id) $($item.test_guid) $($item.test_name)"

    & $Provider.Stop
    & $Provider.Restore
    & $Provider.Start
    $session = Wait-GuestSession $Provider
    try {
        $record.boot_utc = Invoke-Guest $session $GuestNow
        Start-Sleep -Seconds $SettleSeconds
        $hostBefore = [DateTime]::UtcNow
        $record.settled_utc = Invoke-Guest $session $GuestNow
        $hostAfter = [DateTime]::UtcNow
        # Guest minus host clock, host time taken as the midpoint of the round trip. Informational: the
        # detection windows use the guest clock only (protocol section 6).
        $hostMid = $hostBefore.AddTicks([long](($hostAfter - $hostBefore).Ticks / 2))
        $record.clock_skew_seconds = [math]::Round(([DateTimeOffset]::Parse($record.settled_utc).UtcDateTime - $hostMid).TotalSeconds, 3)
        $record.preflight = Invoke-Guest $session $GuestPreflight @($GuestWork)
        $record.w32tm_before = Invoke-Guest $session $GuestTime
        if (-not $record.preflight.elevated) { throw 'the guest session is not elevated' }
        if ($record.preflight.realtime_protection) { throw 'Defender real-time protection is on in the guest; rebuild the checkpoint' }

        if ($Smoke) {
            $record.prereq_status = 'met'
        } else {
            $pre = Invoke-Guest $session $GuestPrereqs @($item.technique_id, $item.test_guid, $GuestAtomics, $GuestModule, $TimeoutSeconds)
            $record.prereq_get_output = $pre.get_output
            $record.prereq_check_output = $pre.check_output
            $record.prereq_status = $(if ($pre.met) { 'met' } else { 'failed' })
        }

        if ($record.prereq_status -eq 'met') {
            $record.quiet_start_utc = Invoke-Guest $session $GuestNow
            Start-Sleep -Seconds $QuietSeconds
            $log = Join-Path $GuestWork 'execution-log.csv'
            if ($Smoke) {
                $run = Invoke-Guest $session $GuestSmoke @($log)
            } else {
                $run = Invoke-Guest $session $GuestExecute @($item.technique_id, $item.test_guid, $GuestAtomics, $TimeoutSeconds, $log)
            }
            $record.t0_utc = $run.t0
            $record.t1_utc = $run.t1
            $record.exit_code = $run.exit_code
            $record.timed_out = $run.timed_out
            $record.execution_output = $run.output
            $failed = $run.timed_out -or ($null -eq $run.exit_code) -or ("$($run.exit_code)" -eq '') -or ("$($run.exit_code)" -ne '0')
            $record.execution_status = $(if ($failed) { 'execution_failed' } else { 'executed' })

            Start-Sleep -Seconds $PostWindowSeconds
            $record.window_closed_utc = Invoke-Guest $session $GuestNow
            if (-not $Smoke) {
                $record.cleanup_output = Invoke-Guest $session $GuestCleanup @($item.technique_id, $item.test_guid, $GuestAtomics, $TimeoutSeconds)
            }
        }

        $record.w32tm_after = Invoke-Guest $session $GuestTime
        $guestEvtx = Invoke-Guest $session $GuestExport @($GuestWork, $Channels)
        Copy-Item -FromSession $session -Path (Join-Path $guestEvtx '*.evtx') -Destination $resultPath
        $record.evtx = @(Get-ChildItem $resultPath -Filter *.evtx | ForEach-Object {
            [ordered]@{ file = $_.Name; sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower() }
        })
    }
    catch {
        $record.harness_error = $_.Exception.Message
        throw
    }
    finally {
        $record.host_finished_utc = [DateTime]::UtcNow.ToString('o')
        $name = $(if ($record.Contains('harness_error')) { 'harness-error.json' } else { 'result.json' })
        $record | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 (Join-Path $resultPath $name)
        Remove-PSSession $session -ErrorAction SilentlyContinue
        & $Provider.Stop
    }
    Write-Host "done  $($item.technique_id) $($item.test_guid): prerequisites $($record.prereq_status), $($record['execution_status'])"
}

$plan = Get-Plan
$minutes = [math]::Round(($SettleSeconds + $QuietSeconds + $PostWindowSeconds) / 60 + 4, 0)
Write-Host ("Seed {0}; {1} ART test(s) planned; about {2} minutes each, about {3:N0} hours in total" -f `
    $plan.seed, $plan.tests.Count, $minutes, ($plan.tests.Count * $minutes / 60))

if ($PSCmdlet.ParameterSetName -eq 'Plan') {
    $plan.tests | Format-Table tier, rank, technique_id, test_guid, test_name -AutoSize | Out-String -Width 200 | Write-Host
    Write-Host 'Plan only. Run with -SmokeTest to check the orchestration, or -Execute to run the protocol.'
    return
}
if (-not $Hypervisor) { throw 'Pass -Hypervisor VirtualBox or -Hypervisor HyperV' }
if (-not $VBoxManage -and $env:ProgramFiles) { $VBoxManage = Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe' }
$Provider = New-LabProvider $Hypervisor
$HypervisorVersion = & $Provider.Version
Write-Host "Hypervisor: $($Provider.Name) $HypervisorVersion; VM $VMName; snapshot $CheckpointName"
if (-not $Credential) { $Credential = Get-Credential -Message "Local administrator on $VMName" }
if (-not (& $Provider.SnapshotExists)) { throw "Snapshot '$CheckpointName' not found on $VMName" }

if ($SmokeTest) {
    $smoke = [pscustomobject]@{ tier = 'smoke'; rank = 0; technique_id = 'SMOKE'; rule_id = ''; rule_file = ''
        test_guid = 'smoke-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'); test_name = 'cmd /c echo round1-smoke'; executor = 'command_prompt' }
    Invoke-OneTest $smoke -Smoke
    return
}

foreach ($item in $plan.tests) { Invoke-OneTest $item }
