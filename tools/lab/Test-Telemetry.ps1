<#
.SYNOPSIS
    Telemetry acceptance test for round 1 (docs/validation-protocol.md, section 6).

.DESCRIPTION
    UNUSED: round 1 was stopped before execution. This script has never been run against a real host; it is
    kept only as part of the documented plan in docs/validation-protocol.md.

    Checks that a host records every native log source the sampled rules depend on, before the attack
    checkpoint is taken, and on every benign host before its collection starts.

    Configuration checks run everywhere: Sysmon running, its configuration file's sha256, log sizes, the
    audit policy, process-creation command lines, and PowerShell logging policy under both registry views.

    Event checks trigger an action and look for the event it should produce, tagged with a unique marker.
    Actions that look like attack activity (a Run-key write, an lsass handle, a failed logon) only run with
    -Lab. On the real endpoint, run without -Lab. Those log sources are then checked only for having recorded
    anything in the last 24 hours.

    A FAIL on a required check must be fixed before the checkpoint is taken. A FAIL on an event that the
    pinned Sysmon configuration filters out is recorded as is: the protocol measures rules under that
    configuration, and must not tune it.

    Writes telemetry-check.json next to -OutDir. Windows PowerShell 5.1, run elevated.
#>
param(
    [string] $SysmonConfig = 'C:\round1\sysmonconfig-15.21.xml',
    [string] $ExpectedConfigSha256 = 'f115aac5770dae468e5cfb48c58a8b6e37588208a31f1b746812c534577a244b',
    [string] $OutDir = 'C:\round1',
    [switch] $Lab
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$marker = 'round1check' + [Guid]::NewGuid().ToString('N').Substring(0, 12)
$started = [DateTime]::UtcNow
$results = New-Object System.Collections.ArrayList

function Add-Result($Name, [bool] $Pass, [bool] $Required, $Detail) {
    [void]$results.Add([pscustomobject]@{ check = $Name; pass = $Pass; required = $Required; detail = "$Detail" })
}

function Find-Event($Log, [int] $Id, [string] $Text, [int] $Seconds = 60) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $Log; Id = $Id; StartTime = $started.ToLocalTime() } -ErrorAction SilentlyContinue
        if ($events) {
            if (-not $Text) { return $true }
            foreach ($e in $events) { if ($e.ToXml() -match [regex]::Escape($Text)) { return $true } }
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Test-Recent($Log, [int] $Id) {
    $e = Get-WinEvent -FilterHashtable @{ LogName = $Log; Id = $Id; StartTime = (Get-Date).AddHours(-24) } -MaxEvents 1 -ErrorAction SilentlyContinue
    return [bool]$e
}

$sysmonLog = 'Microsoft-Windows-Sysmon/Operational'
$psLog = 'Microsoft-Windows-PowerShell/Operational'

# -- configuration ------------------------------------------------------------ #
$service = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
Add-Result 'Sysmon64 service running' ([bool]($service -and $service.Status -eq 'Running')) $true $(if ($service) { $service.Status } else { 'not installed' })
$configHash = $(if (Test-Path $SysmonConfig) { (Get-FileHash $SysmonConfig -Algorithm SHA256).Hash.ToLower() } else { 'missing' })
Add-Result 'Sysmon configuration file is the pinned release asset' ($configHash -eq $ExpectedConfigSha256) $true $configHash
$sysmonExe = Join-Path $env:windir 'Sysmon64.exe'
if (Test-Path $sysmonExe) {
    Add-Result 'Sysmon binary' $true $false ("{0} sha256 {1}" -f (Get-Item $sysmonExe).VersionInfo.FileVersion, (Get-FileHash $sysmonExe).Hash.ToLower())
    $ErrorActionPreference = 'Continue'    # native stderr under 'Stop' throws in Windows PowerShell 5.1
    (& $sysmonExe -c 2>&1 | Out-String) | Set-Content -Encoding UTF8 (Join-Path $OutDir 'sysmon-active-config.txt')
    $ErrorActionPreference = 'Stop'
}

foreach ($size in @(@($sysmonLog, 1073741824), @('Security', 1073741824), @($psLog, 1073741824), @('System', 134217728))) {
    $log = Get-WinEvent -ListLog $size[0]
    Add-Result "log size $($size[0])" ($log.MaximumSizeInBytes -ge $size[1]) $true $log.MaximumSizeInBytes
}

$cmdline = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue
Add-Result 'process-creation command lines (4688) enabled' ([bool]($cmdline -and $cmdline.ProcessCreationIncludeCmdLine_Enabled -eq 1)) $true ''
foreach ($root in @('HKLM:\SOFTWARE\Policies', 'HKLM:\SOFTWARE\WOW6432Node\Policies')) {
    $sb = Get-ItemProperty "$root\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
    Add-Result "script-block logging policy under $root" ([bool]($sb -and $sb.EnableScriptBlockLogging -eq 1)) $true ''
    $ml = Get-ItemProperty "$root\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue
    Add-Result "module logging policy under $root" ([bool]($ml -and $ml.EnableModuleLogging -eq 1)) $true ''
}
(& auditpol /get /category:* | Out-String) | Set-Content -Encoding UTF8 (Join-Path $OutDir 'auditpol.txt')

# -- events -------------------------------------------------------------------- #
& cmd.exe /c "echo $marker" | Out-Null
Add-Result 'Sysmon 1 process creation' (Find-Event $sysmonLog 1 $marker) $true ''
Add-Result 'Security 4688 with command line' (Find-Event 'Security' 4688 $marker) $true ''

& "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Write-Output '$marker-x64'" | Out-Null
Add-Result 'PowerShell 4104 from 64-bit powershell.exe' (Find-Event $psLog 4104 "$marker-x64") $true ''
& "$env:windir\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Write-Output '$marker-x86'" | Out-Null
Add-Result 'PowerShell 4104 from 32-bit powershell.exe' (Find-Event $psLog 4104 "$marker-x86") $true ''

try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.Connect('example.com', 80); $client.Close()
    Add-Result 'Sysmon 3 network connection (any, since start)' (Find-Event $sysmonLog 3 '') $false ''
} catch { Add-Result 'Sysmon 3 network connection' $false $false "connect failed: $($_.Exception.Message)" }

$file = Join-Path $env:TEMP "$marker.ps1"
Set-Content -Path $file -Value '# round1 telemetry check'
Add-Result 'Sysmon 11 file create (script in %TEMP%)' (Find-Event $sysmonLog 11 $marker) $false ''
Remove-Item $file -Force

Add-Result 'Sysmon 7 image load (any in 24 h)' (Test-Recent $sysmonLog 7) $false 'no targeted trigger; the pinned configuration logs selected loads only'
Add-Result 'System channel (any in 24 h)' ([bool](Get-WinEvent -LogName System -MaxEvents 1 -ErrorAction SilentlyContinue)) $true ''

if ($Lab) {
    $run = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    New-Item -Path "$run\$marker" -Force | Out-Null
    Set-ItemProperty -Path $run -Name $marker -Value "$env:windir\System32\notepad.exe"
    Add-Result 'Sysmon 12 registry key create (Run key)' (Find-Event $sysmonLog 12 $marker) $false ''
    Add-Result 'Sysmon 13 registry value set (Run key)' (Find-Event $sysmonLog 13 $marker) $false ''
    Remove-ItemProperty -Path $run -Name $marker
    Remove-Item -Path "$run\$marker" -Force

    Add-Type -Namespace Round1 -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)] public static extern System.IntPtr OpenProcess(uint access, bool inherit, int pid);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(System.IntPtr handle);
'@
    $lsass = Get-Process -Name lsass
    $handle = [Round1.Native]::OpenProcess(0x1010, $false, $lsass.Id)
    if ($handle -ne [IntPtr]::Zero) { [void][Round1.Native]::CloseHandle($handle) }
    Add-Result 'Sysmon 10 process access (lsass, 0x1010)' (Find-Event $sysmonLog 10 'lsass.exe') $false ''

    $ErrorActionPreference = 'Continue'    # net use reports the failed logon on stderr
    & net.exe use \\127.0.0.1\IPC$ /user:$marker wrong-password 2>&1 | Out-Null
    $ErrorActionPreference = 'Stop'
    Add-Result 'Security 4625 failed logon' (Find-Event 'Security' 4625 $marker) $true ''
} else {
    foreach ($check in @(@($sysmonLog, 10), @($sysmonLog, 12), @($sysmonLog, 13), @('Security', 4625))) {
        Add-Result "$($check[0]) $($check[1]) (any in 24 h, passive)" (Test-Recent $check[0] $check[1]) $false ''
    }
}

$report = [ordered]@{
    computer = $env:COMPUTERNAME; lab_mode = [bool]$Lab; started_utc = $started.ToString('o')
    os_build = [Environment]::OSVersion.Version.ToString(); marker = $marker
    w32tm = (& w32tm /query /status) -join "`n"; checks = $results
}
$report | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 (Join-Path $OutDir 'telemetry-check.json')
$results | Format-Table check, pass, required, detail -AutoSize | Out-String -Width 200 | Write-Host
$failedRequired = @($results | Where-Object { $_.required -and -not $_.pass })
if ($failedRequired.Count) { Write-Host "$($failedRequired.Count) required check(s) failed."; exit 1 }
Write-Host 'All required checks passed.'
