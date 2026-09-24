# Lab build sheet, round 1

How to build the lab that [the protocol](../validation-protocol.md) assumes, and what to record while doing it.
Every command below is run in an **elevated** Windows PowerShell 5.1 prompt unless it says otherwise. Anything
recorded goes into `output/round1/lab-record/` on the Hyper-V host and is published with the results.

Nothing in this sheet executes an ART test. Execution starts only with `Invoke-Round1.ps1 -Execute` (step 8).

## 0. Order of operations

1. Set up the real endpoint's telemetry (step 7) and start its benign collection. It needs **at least 7 complete
   host-days** (protocol section 6).
2. Build the attack VM (steps 1–6), and prove the orchestration with the smoke test (step 8).
3. Run the protocol (step 8).

If the Hyper-V host **is** the real endpoint, the runner's own activity (Hyper-V, PowerShell Direct sessions,
`wevtutil`) lands in the endpoint's benign logs. In that case either finish the 7 benign days before building the
lab, or record the dates the runner was active. Days with runner activity are excluded from the real endpoint's
host-days and published as excluded, with that reason.

## 1. Hyper-V host

- Windows 10/11 Pro or Enterprise with Hyper-V enabled, at least 16 GB RAM and 150 GB free disk.
- Time: synchronise to the same NTP source as the real endpoint.

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All   # reboot afterwards
w32tm /config /manualpeerlist:"time.windows.com,0x8" /syncfromflags:manual /update
w32tm /resync
w32tm /query /status > output\round1\lab-record\host-w32tm.txt
```

**Isolated NAT switch.** The VM needs the internet to fetch ART prerequisites, but it should not reach your LAN:

```powershell
New-VMSwitch -SwitchName Round1NAT -SwitchType Internal
New-NetIPAddress -IPAddress 192.168.250.1 -PrefixLength 24 -InterfaceAlias 'vEthernet (Round1NAT)'
New-NetNat -Name Round1NAT -InternalIPInterfaceAddressPrefix 192.168.250.0/24
```

## 2. Attack VM specification

| Setting | Value |
|---|---|
| Name | `ROUND1-ATK` (also the guest hostname: the "attack host" in the protocol) |
| Generation / firmware | Generation 2, Secure Boot on, vTPM on (Windows 11 requires both) |
| CPU / memory | 4 vCPU, 8 GB static (dynamic memory off, so memory pressure does not vary between tests) |
| Disk | 80 GB dynamically expanding VHDX |
| OS | Windows 11 Enterprise evaluation (English, x64), fully updated once, then updates paused. Record the build. |
| Account | Local administrator `labadmin`, standalone **workgroup** (no domain in round 1) |
| Network | `Round1NAT`, static 192.168.250.10/24, gateway 192.168.250.1, DNS 1.1.1.1 |
| Checkpoints | Standard type, automatic checkpoints off |
| Time | Hyper-V time synchronisation integration service **on**. The checkpoint is taken with the VM off, so every restore cold-boots, and the guest takes the host's NTP-synchronised clock at boot. |

```powershell
$vm = 'ROUND1-ATK'
New-VM -Name $vm -Generation 2 -MemoryStartupBytes 8GB -NewVHDPath "D:\Hyper-V\$vm.vhdx" -NewVHDSizeBytes 80GB -SwitchName Round1NAT
Set-VMProcessor -VMName $vm -Count 4
Set-VMMemory -VMName $vm -DynamicMemoryEnabled $false
Set-VMKeyProtector -VMName $vm -NewLocalKeyProtector
Enable-VMTPM -VMName $vm
Set-VM -Name $vm -CheckpointType Standard -AutomaticCheckpointsEnabled $false
Add-VMDvdDrive -VMName $vm -Path 'D:\ISO\Win11_Enterprise_Eval_x64.iso'
Set-VMFirmware -VMName $vm -FirstBootDevice (Get-VMDvdDrive -VMName $vm)
Start-VM -Name $vm      # install Windows through the console, create labadmin, then continue in the guest
```

## 3. Guest base configuration (inside the VM)

```powershell
Rename-Computer -NewName ROUND1-ATK            # reboot afterwards
Set-TimeZone -Id 'UTC'
New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 192.168.250.10 -PrefixLength 24 -DefaultGateway 192.168.250.1
Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 1.1.1.1

# Keep the lab off the LAN: block private ranges except the NAT gateway.
New-NetFirewallRule -DisplayName 'Round1 block LAN' -Direction Outbound -Action Block `
    -RemoteAddress 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
New-NetFirewallRule -DisplayName 'Round1 allow gateway' -Direction Outbound -Action Allow -RemoteAddress 192.168.250.1

# A local administrator account gets a full token over remote sessions.
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

Run Windows Update to completion, then pause updates (Settings > Windows Update > Pause). Record the build:

```powershell
Get-ComputerInfo -Property OsName, OsVersion, OsBuildNumber, WindowsVersion | Out-File C:\round1\os.txt
```

**Defender off (attack VM only).** Tamper protection can only be turned off by hand: Windows Security > Virus &
threat protection > Manage settings > **Tamper Protection: Off**. Then:

```powershell
New-Item -Force 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' DisableRealtimeMonitoring 1
Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath 'C:\AtomicRedTeam'
Restart-Computer
# after the reboot, both must be False:
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, IsTamperProtected
```

The runner checks `RealTimeProtectionEnabled` before every test and stops if it is on.

## 4. Telemetry (every host: attack VM, lab VMs, real endpoint)

Sysmon 15.21 from Microsoft Sysinternals, and the pinned configuration:

```powershell
New-Item -ItemType Directory -Force C:\round1 | Out-Null
$rel = 'https://github.com/olafhartong/sysmon-modular/releases/download/configs-082cba578667'
Invoke-WebRequest "$rel/sysmonconfig-15.21.xml" -OutFile C:\round1\sysmonconfig-15.21.xml -UseBasicParsing
(Get-FileHash C:\round1\sysmonconfig-15.21.xml).Hash   # must be F115AAC5770DAE468E5CFB48C58A8B6E37588208A31F1B746812C534577A244B

# Sysmon.zip from https://learn.microsoft.com/sysinternals/downloads/sysmon, extracted to C:\round1\Sysmon
C:\round1\Sysmon\Sysmon64.exe -accepteula -i C:\round1\sysmonconfig-15.21.xml
(Get-Item C:\Windows\Sysmon64.exe).VersionInfo.FileVersion   # must be 15.21; record it and the hash below
(Get-FileHash C:\Windows\Sysmon64.exe).Hash
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824
```

Audit policy and log sizes from the pinned script, run from an elevated **cmd** prompt:

```bat
curl -L -o C:\round1\YamatoSecurityConfigureWinEventLogs.bat https://raw.githubusercontent.com/Yamato-Security/EnableWindowsLogSettings/6d2c0a15351650309d9bb325d63c5ef051a2157d/YamatoSecurityConfigureWinEventLogs.bat
C:\round1\YamatoSecurityConfigureWinEventLogs.bat
```

The script writes the PowerShell logging policy only under `Wow6432Node`. The protocol (amendment 1, item 5) adds
the native path:

```bat
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames /v * /t REG_SZ /d * /f
```

Copy `tools/lab/Test-Telemetry.ps1` to `C:\round1\` and run the acceptance test. Use `-Lab` on the attack VM and
the lab VMs, and **no switch on the real endpoint** (it then performs no attack-like actions):

```powershell
Set-ExecutionPolicy -Scope Process Bypass
C:\round1\Test-Telemetry.ps1 -Lab
```

Every required check must pass before the checkpoint is taken. `telemetry-check.json`, `auditpol.txt` and
`sysmon-active-config.txt` go into the lab record. A non-required check that fails because the pinned Sysmon
configuration filters that event is recorded, not fixed: the protocol measures rules under that configuration.

## 5. Test runner (attack VM only)

```powershell
Install-PackageProvider -Name NuGet -Force
Install-Module -Name powershell-yaml -Scope AllUsers -Force
$yaml = Get-Module powershell-yaml -ListAvailable | Select-Object -First 1
$yaml.Version.ToString()                                       # record
Get-ChildItem $yaml.ModuleBase -Recurse -File | Get-FileHash | Sort-Object Path | Out-File C:\round1\powershell-yaml-hashes.txt

New-Item -ItemType Directory -Force C:\AtomicRedTeam | Out-Null
Invoke-WebRequest https://github.com/redcanaryco/invoke-atomicredteam/archive/refs/tags/v2.3.0.zip -OutFile C:\round1\iart.zip -UseBasicParsing
Expand-Archive C:\round1\iart.zip C:\round1\iart -Force
Move-Item C:\round1\iart\invoke-atomicredteam-2.3.0 C:\AtomicRedTeam\invoke-atomicredteam

$art = '388942adbd9641f4dfdcf079d7efe9a75ec0ac43'
Invoke-WebRequest "https://github.com/redcanaryco/atomic-red-team/archive/$art.zip" -OutFile C:\round1\art.zip -UseBasicParsing
Expand-Archive C:\round1\art.zip C:\round1\art -Force
Move-Item "C:\round1\art\atomic-red-team-$art\atomics" C:\AtomicRedTeam\atomics
(Get-FileHash C:\AtomicRedTeam\atomics\Indexes\index.yaml).Hash
# must be 08F8BD071D96261E12E520A8BBA4EF85DF33E611491F2435671D4F8FE94C49A4 (the protocol's ART pin)

Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force
Invoke-AtomicTest T1112 -ShowDetailsBrief -PathToAtomicsFolder C:\AtomicRedTeam\atomics   # lists tests, runs nothing
```

The v2.3.0 manifest reports `2.1.0`. The runner is identified by the tag commit
`ad1356ae4fdeffa9e9a5f7e76af8310620af762c`, not by `Get-Module`.

Do **not** run `-GetPrereqs` for the sample here: prerequisites are fetched per test after each restore (protocol
section 8, step 2), and pre-fetching them would put their tools into the clean state.

## 6. Clean checkpoint

In the guest, clear the logs so each test's export holds only that test's run, then shut down:

```powershell
'Microsoft-Windows-Sysmon/Operational', 'Security', 'System', 'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell' |
    ForEach-Object { wevtutil cl $_ }
Remove-Item C:\round1\*.zip, C:\round1\iart, C:\round1\art -Recurse -Force
Stop-Computer
```

On the host:

```powershell
Checkpoint-VM -Name ROUND1-ATK -SnapshotName round1-clean
Get-VMCheckpoint -VMName ROUND1-ATK -Name round1-clean |
    Select-Object Name, Id, CreationTime | Out-File output\round1\lab-record\checkpoint.txt
```

Never boot the VM and change it outside the runner. If the checkpoint must change, create a new one under a new
name, and record the change as a deviation.

## 7. Benign hosts

**Real endpoint:** step 4 without `-Lab`, with Defender left on. **Lab VMs:** the step 2 image with Defender on,
then step 4 with `-Lab`. They are never used for attacks.

Schedule the daily export as SYSTEM, a few minutes after 00:00 UTC. Enter the local time that corresponds to
00:15 UTC:

```powershell
Copy-Item tools\lab\Export-BenignDay.ps1 C:\round1\
$action = New-ScheduledTaskAction -Execute powershell.exe `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\round1\Export-BenignDay.ps1 -OutDir C:\round1-benign'
$trigger = New-ScheduledTaskTrigger -Daily -At '02:15'      # local time for 00:15 UTC; adjust
Register-ScheduledTask -TaskName Round1BenignExport -Action $action -Trigger $trigger -User SYSTEM -RunLevel Highest
```

Each day's folder gets a `host-day.json` that says whether the day counts under the protocol's host-day definition,
and why. Exported logs from the real endpoint stay on that machine. Only the alert table derived from them is
published (protocol section 10).

## 8. Runner

`tools/lab/Invoke-Round1.ps1` runs on the Hyper-V host, from the repository root:

```powershell
# 1. The plan: lists all 280 tests with an estimate. Runs nothing.
.\tools\lab\Invoke-Round1.ps1

# 2. Smoke test: one full cycle (restore, boot, settle, quiet period, a harmless `cmd /c echo`, log export)
#    with no ART test. Proves the orchestration and writes output\round1\smoke-00-SMOKE\...
.\tools\lab\Invoke-Round1.ps1 -SmokeTest -Credential (Get-Credential ROUND1-ATK\labadmin)

# 3. The protocol. About 15 minutes per test, about 70 hours. Resumable: recorded tests are skipped.
.\tools\lab\Invoke-Round1.ps1 -Execute -Credential (Get-Credential ROUND1-ATK\labadmin)
```

Each test writes `output\round1\<tier>-<rank>-<technique>\<test guid>\` with the five `.evtx` exports (and their
sha256) and `result.json`: prerequisite output and status, guest timestamps for boot, settling, the quiet period's
start, `t0`, `t1` and the window close, the exit code, timeout, execution status, cleanup output, and `w32tm`
before and after. A harness failure writes `harness-error.json` and stops the run. Resolve it, delete that folder,
and rerun.

The runner reaches the guest through PowerShell Direct (`New-PSSession -VMName`), so tests run in a remote session
rather than an interactive desktop. The protocol lists this as a limitation.

## 9. Lab record checklist

Published with the results, from `output/round1/lab-record/` and each host's `C:\round1\`:

- [ ] host and guest `w32tm /query /status`
- [ ] guest OS build (`os.txt`)
- [ ] Sysmon version and `Sysmon64.exe` sha256, per host
- [ ] `telemetry-check.json`, `auditpol.txt`, `sysmon-active-config.txt`, per host
- [ ] `powershell-yaml` version and `powershell-yaml-hashes.txt`
- [ ] ART `index.yaml` sha256 as installed
- [ ] checkpoint name, ID and creation time
- [ ] smoke-test result
- [ ] dates on which the runner ran on the real endpoint, if it is the Hyper-V host
- [ ] number of lab VMs and a description of their activity
