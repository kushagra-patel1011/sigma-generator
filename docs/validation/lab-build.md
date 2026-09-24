# Lab build sheet, round 1

**Status: unused. Round 1 was stopped before the lab was built; nothing in this sheet or in `tools/lab/` has
been run.** It is kept as part of the documented plan in [the protocol](../validation-protocol.md).

How to build the lab that [the protocol](../validation-protocol.md) assumes, and what to record while doing it.
Every command below is run in an **elevated** Windows PowerShell 5.1 prompt unless it says otherwise. Anything
recorded goes into `output/round1/lab-record/` on the lab host and is published with the results.

The attack VM runs under **VirtualBox** (works on Windows Home) or **Hyper-V** (Windows Pro and Enterprise only).
The runner drives either through the same provider interface, and the results state which one was used (protocol
amendment 2). Steps marked **VirtualBox** or **Hyper-V** apply to that hypervisor only.

Nothing in this sheet executes an ART test. Execution starts only with `Invoke-Round1.ps1 -Execute` (step 8).

## 0. Order of operations

1. Set up the real endpoint's telemetry (step 7) and start its benign collection. It needs **at least 7 complete
   host-days** (protocol section 6).
2. Build the attack VM (steps 1–6), and prove the orchestration with the smoke test (step 8).
3. Run the protocol (step 8).

If the lab host **is** the real endpoint, a day is excluded from the endpoint's host-days, and published with that
reason, whenever lab work happens on it:

- installing or configuring the hypervisor, its host-only network or the WinRM client (steps 1–6);
- the runner running (step 8).

Building the lab after the 7 complete benign days are in avoids losing any of them.

## 1. Lab host

Time: synchronise to the same NTP source as the real endpoint (if they are the same machine, this is already done).

```powershell
w32tm /config /manualpeerlist:"time.windows.com,0x8" /syncfromflags:manual /update
w32tm /resync
New-Item -ItemType Directory -Force output\round1\lab-record | Out-Null
w32tm /query /status > output\round1\lab-record\host-w32tm.txt
```

### VirtualBox (Windows 11 Home and up)

- Install VirtualBox 7.2 from virtualbox.org. The Extension Pack is not needed: EFI, Secure Boot and TPM 2.0 are
  in the base package.
- The installer creates **VirtualBox Host-Only Ethernet Adapter** at 192.168.56.1/24. Check it:

```powershell
$vbm = Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe'
& $vbm --version > output\round1\lab-record\virtualbox-version.txt
& $vbm list hostonlyifs
```

- Set up the WinRM client, so the host can reach only the guest's host-only address:

```powershell
Start-Service WinRM
Set-Item WSMan:\localhost\Client\TrustedHosts -Value 192.168.56.10 -Force
```

After round 1, undo it with `Clear-Item WSMan:\localhost\Client\TrustedHosts -Force; Stop-Service WinRM`.

### Hyper-V (Windows Pro and Enterprise)

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All   # reboot afterwards
New-VMSwitch -SwitchName Round1NAT -SwitchType Internal
New-NetIPAddress -IPAddress 192.168.250.1 -PrefixLength 24 -InterfaceAlias 'vEthernet (Round1NAT)'
New-NetNat -Name Round1NAT -InternalIPInterfaceAddressPrefix 192.168.250.0/24
```

Hyper-V reaches the guest over PowerShell Direct, so it needs no WinRM setup.

## 2. Attack VM specification

| Setting | Value |
|---|---|
| Name | `ROUND1-ATK` (also the guest hostname: the "attack host" in the protocol) |
| Firmware | EFI, Secure Boot on, TPM 2.0 (Windows 11 requires all three) |
| CPU / memory | 4 vCPU, 8 GB fixed |
| Disk | 80 GB dynamically expanding |
| OS | Windows 11 Enterprise evaluation (English, x64), fully updated once, then updates paused. Record the build. |
| Account | Local administrator `labadmin`, standalone **workgroup** (no domain in round 1) |
| Snapshot | `round1-clean`, taken with the VM **powered off**, so every restore cold-boots |
| Guest time zone | UTC |

### VirtualBox

| Adapter | Type | Guest address | Purpose |
|---|---|---|---|
| 1 | NAT | 10.0.2.15/24, gateway 10.0.2.2, DNS 1.1.1.1 | Internet, for ART prerequisites |
| 2 | Host-only (VirtualBox Host-Only Ethernet Adapter) | 192.168.56.10/24, no gateway | WinRM from the host |

Time: the guest time zone is UTC and the virtual RTC runs in UTC (`--rtc-use-utc=on`), so the guest boots with
the correct time. The Guest Additions time synchronisation then keeps it on the host's clock.

Find the Windows 11 OS type ID first (`& $vbm list ostypes | Select-String -Context 0,1 'Windows 11'`, usually
`Windows11_64`), then:

```powershell
$vm = 'ROUND1-ATK'
$dir = Join-Path $env:USERPROFILE "VirtualBox VMs\$vm"
& $vbm createvm --name $vm --ostype Windows11_64 --register
& $vbm modifyvm $vm --firmware=efi --tpm-type=2.0 --memory=8192 --cpus=4 --rtc-use-utc=on `
    --graphicscontroller=vboxsvga --audio-enabled=off --clipboard-mode=disabled --drag-and-drop=disabled `
    --nic1=nat --nic2=hostonly --host-only-adapter2="VirtualBox Host-Only Ethernet Adapter"
& $vbm modifynvram $vm inituefivarstore
& $vbm modifynvram $vm enrollmssignatures
& $vbm modifynvram $vm enrollorclpk
& $vbm modifynvram $vm secureboot --enable
& $vbm createmedium disk --filename="$dir\$vm.vdi" --size=81920 --format=VDI
& $vbm storagectl $vm --name=SATA --add=sata --controller=IntelAhci
& $vbm storageattach $vm --storagectl=SATA --port=0 --device=0 --type=hdd --medium="$dir\$vm.vdi"
& $vbm storageattach $vm --storagectl=SATA --port=1 --device=0 --type=dvddrive --medium='D:\ISO\Win11_Enterprise_Eval_x64.iso'
& $vbm startvm $vm      # install Windows in the console window, create labadmin, then continue in the guest
```

### Hyper-V

Adapter on `Round1NAT`, static 192.168.250.10/24, gateway 192.168.250.1, DNS 1.1.1.1. The Hyper-V time
synchronisation integration service stays on.

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
Start-VM -Name $vm
```

## 3. Guest base configuration (inside the VM)

```powershell
Rename-Computer -NewName ROUND1-ATK            # reboot afterwards
Set-TimeZone -Id 'UTC'
New-Item -ItemType Directory -Force C:\round1 | Out-Null
# A local administrator account gets a full token over remote sessions.
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

**Network (VirtualBox).** `Get-NetAdapter` shows two adapters. Match them to adapters 1 and 2 by MAC address
(`& $vbm showvminfo ROUND1-ATK --machinereadable | Select-String macaddress` on the host). Then, with the
aliases you found:

```powershell
# Both adapters start on DHCP; clear that before assigning static addresses.
foreach ($alias in 'Ethernet', 'Ethernet 2') {
    Set-NetIPInterface -InterfaceAlias $alias -Dhcp Disabled
    Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
    Get-NetRoute -InterfaceAlias $alias -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false
}
New-NetIPAddress -InterfaceAlias 'Ethernet' -IPAddress 10.0.2.15 -PrefixLength 24 -DefaultGateway 10.0.2.2
Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses 1.1.1.1
New-NetIPAddress -InterfaceAlias 'Ethernet 2' -IPAddress 192.168.56.10 -PrefixLength 24
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private

# WinRM, reachable from the host-only address only
Enable-PSRemoting -Force
Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP' -RemoteAddress 192.168.56.1
Disable-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-PUBLIC' -ErrorAction SilentlyContinue
```

Install the Guest Additions (Devices > Insert Guest Additions CD image, run `VBoxWindowsAdditions.exe`) and
reboot. Record their version: `Get-ItemProperty 'HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions' | Select-Object Version`.

**Network (Hyper-V).**

```powershell
New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 192.168.250.10 -PrefixLength 24 -DefaultGateway 192.168.250.1
Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 1.1.1.1
```

**Keep the lab off the LAN (both).** This blocks new outbound connections to private ranges. Internet traffic
through the NAT gateway is unaffected, because its remote address is public. Replies to the host's inbound WinRM
connection are unaffected too, because they belong to an allowed inbound connection. In Windows Firewall a block
rule beats an allow rule, so no exceptions are added.

```powershell
New-NetFirewallRule -DisplayName 'Round1 block LAN' -Direction Outbound -Action Block `
    -RemoteAddress 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
```

**Check from the host (VirtualBox):**

```powershell
$cred = Get-Credential ROUND1-ATK\labadmin
Invoke-Command -ComputerName 192.168.56.10 -Credential $cred { $env:COMPUTERNAME; whoami /groups | Select-String 'High Mandatory' }
```

It must print `ROUND1-ATK` and the High Mandatory Level line, which shows the session is elevated.

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

Every required check must pass before the snapshot is taken. `telemetry-check.json`, `auditpol.txt` and
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

## 6. Clean snapshot

In the guest, clear the logs so each test's export holds only that test's run, then shut down:

```powershell
'Microsoft-Windows-Sysmon/Operational', 'Security', 'System', 'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell' |
    ForEach-Object { wevtutil cl $_ }
Remove-Item C:\round1\*.zip, C:\round1\iart, C:\round1\art -Recurse -Force
Stop-Computer
```

On the host, once the VM is off:

```powershell
# VirtualBox
& $vbm snapshot ROUND1-ATK take round1-clean --description="round 1 clean state, powered off"
& $vbm snapshot ROUND1-ATK list --machinereadable > output\round1\lab-record\snapshot.txt
& $vbm showvminfo ROUND1-ATK --machinereadable > output\round1\lab-record\vm.txt

# Hyper-V
Checkpoint-VM -Name ROUND1-ATK -SnapshotName round1-clean
Get-VMCheckpoint -VMName ROUND1-ATK -Name round1-clean |
    Select-Object Name, Id, CreationTime | Out-File output\round1\lab-record\snapshot.txt
```

Never boot the VM and change it outside the runner. If the snapshot must change, take a new one under a new name,
and record the change as a deviation.

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

Each day's folder gets a `host-day.json` with the evidence for the protocol's host-day definition: log coverage,
log clears, Sysmon configuration changes and gaps, and active hours. Days on which lab work happened on the
endpoint (step 0) are recorded in `output/round1/lab-record/lab-days.txt`, one UTC date and activity per line.
Exported logs from the real endpoint stay on that machine. Only the alert table derived from them is published
(protocol section 10).

## 8. Runner

`tools/lab/Invoke-Round1.ps1` runs on the lab host, from the repository root. The snapshot name, the steps and
the `-SmokeTest` path are the same for both hypervisors; only `-Hypervisor` differs.

```powershell
$cred = Get-Credential ROUND1-ATK\labadmin

# 1. The plan: lists all 280 tests with an estimate. Runs nothing, needs no hypervisor.
.\tools\lab\Invoke-Round1.ps1

# 2. Smoke test: one full cycle (restore, boot, settle, quiet period, a harmless `cmd /c echo`, log export)
#    with no ART test. Proves the orchestration and writes output\round1\smoke-00-SMOKE\...
.\tools\lab\Invoke-Round1.ps1 -Hypervisor VirtualBox -SmokeTest -Credential $cred

# 3. The protocol. About 15 minutes per test, about 70 hours. Resumable: recorded tests are skipped.
.\tools\lab\Invoke-Round1.ps1 -Hypervisor VirtualBox -Execute -Credential $cred
```

Use `-Hypervisor HyperV` on a Hyper-V host. For VirtualBox, `-GuestAddress` (default `192.168.56.10`) and
`-VBoxManage` (default under `Program Files\Oracle\VirtualBox`) can be overridden.

Each test writes `output\round1\<tier>-<rank>-<technique>\<test guid>\` with the five `.evtx` exports (and their
sha256) and `result.json`. The record holds:

- the hypervisor and its version;
- guest timestamps for boot, settling, the quiet period's start, `t0`, `t1` and the window close;
- the guest-minus-host clock offset measured after settling;
- prerequisite output and status;
- the exit code, timeout and execution status;
- cleanup output, and `w32tm` before and after.

A harness failure writes `harness-error.json` and stops the run. Resolve it, delete that folder, and rerun.

Tests run in a remote PowerShell session (WinRM on VirtualBox, PowerShell Direct on Hyper-V), not an interactive
desktop. The protocol lists this as a limitation.

## 9. Lab record checklist

Published with the results, from `output/round1/lab-record/` and each host's `C:\round1\`:

- [ ] hypervisor and version (`virtualbox-version.txt`, or the Hyper-V host's OS version)
- [ ] VirtualBox Guest Additions version (VirtualBox only)
- [ ] host and guest `w32tm /query /status`
- [ ] guest OS build (`os.txt`)
- [ ] Sysmon version and `Sysmon64.exe` sha256, per host
- [ ] `telemetry-check.json`, `auditpol.txt`, `sysmon-active-config.txt`, per host
- [ ] `powershell-yaml` version and `powershell-yaml-hashes.txt`
- [ ] ART `index.yaml` sha256 as installed
- [ ] `snapshot.txt` (and `vm.txt` on VirtualBox)
- [ ] smoke-test result
- [ ] `lab-days.txt`: UTC dates of lab work on the real endpoint, if it is the lab host
- [ ] number of lab VMs and a description of their activity
