# Round 1 results

**Status: not executed. No ART test has run and no benign telemetry has been evaluated.**

Every table below is empty on purpose. Fill it only from the files copied back in step 5, never by hand from
memory. The plan is in [pilot-plan.md](pilot-plan.md), the method in [the protocol](../validation-protocol.md),
and the lab build in [lab-build.md](lab-build.md).

## How to produce them

Run everything on the Windows lab host, in an **elevated Windows PowerShell 5.1** prompt at the repository root,
after building the lab with `lab-build.md`. Use `-Hypervisor HyperV` instead of `VirtualBox` on a Hyper-V host.

### 1. Set up the session

```powershell
Set-ExecutionPolicy -Scope Process Bypass
git pull
$cred   = Get-Credential ROUND1-ATK\labadmin
$phase1 = 'T1003.004','T1056.001','T1218.002','T1574.011','T1003.005','T1556.002','T1546.008','T1025','T1518','T1552','T1574.001'
$phase2 = 'T1112'
```

### 2. Plan, then smoke test (runs no ART test)

```powershell
.\tools\lab\Invoke-Round1.ps1 -Technique ($phase1 + $phase2)    # must report 125 ART tests
.\tools\lab\Invoke-Round1.ps1 -Hypervisor VirtualBox -SmokeTest -Credential $cred
```

The smoke test must finish with a `result.json` under `output\round1\smoke-00-SMOKE\`, five `.evtx` files and
no `harness-error.json`. **Do not continue until it does.** The next step executes ART tests, and from then on
the protocol can no longer be amended.

### 3. Pilot, phase 1: 33 ART tests, about 8 hours

```powershell
.\tools\lab\Invoke-Round1.ps1 -Hypervisor VirtualBox -Execute -Credential $cred -Technique $phase1
```

### 4. Pilot, phase 2: T1112, 92 ART tests, about 23 hours

```powershell
.\tools\lab\Invoke-Round1.ps1 -Hypervisor VirtualBox -Execute -Credential $cred -Technique $phase2
```

Both phases can resume: rerunning a command skips tests that already have a `result.json`. A `harness-error.json`
stops the run. Resolve the cause, delete that test's folder, and rerun.

With GNU make installed on Windows, steps 2–4 are `make pilot-plan`, `make pilot-smoke` and
`make pilot HYPERVISOR=VirtualBox`. Without `-Credential`, the runner asks for the password.

### 4b. Score (on the lab host, where the `.evtx` files are)

```powershell
python -m tools.score fetch       # pinned Hayabusa 4.1.0 (Windows build) and converter, checked by sha256
python -m tools.score convert     # converts the rules under test; writes the conversion manifest
python -m tools.score run         # Hayabusa over each executed test's logs, with only that test's rule loaded
python -m tools.score report      # writes output\round1-scores\ and prints the per-rule table
```

`python -m tools.score all` (or `make score`) runs the four in order. The converter needs Python 3.10 or newer. If
the `python` on the lab host is older, add `--converter-python C:\Path\To\python3.11.exe` to `fetch` or `all`.
Scoring reads files and runs no ART test, so it can be repeated, for example after phase 1 and again after phase 2.

### 5. Copy the outputs back into the repository

```powershell
$dest = 'docs\validation\results\pilot'

# Execution and scoring records: per test, result.json, hayabusa.json, alerts.jsonl and any
# harness-error.json. robocopy exit codes below 8 mean success.
robocopy output\round1 $dest result.json hayabusa.json alerts.jsonl harness-error.json /S /XD lab-record

# The scoring tables (step 4b).
robocopy output\round1-scores "$dest\scores" /S

# The lab record (text files).
robocopy output\round1\lab-record "$dest\lab-record" /S

# Event logs: binary and large, so not committed. Archive them, attach the archive to a
# GitHub release, and record its sha256 in the "Raw data" table below.
Compress-Archive -Path output\round1\* -DestinationPath round1-pilot-raw.zip
(Get-FileHash round1-pilot-raw.zip -Algorithm SHA256).Hash
```

The guest's own records live inside the VM. Copy them out **during the build**, before `lab-build.md` step 6
shuts the VM down for its snapshot. Never boot the snapshot outside the runner to fetch them later.

```powershell
$s = New-PSSession -ComputerName 192.168.56.10 -Credential $cred
New-Item -ItemType Directory -Force output\round1\lab-record\guest | Out-Null
Copy-Item -FromSession $s -Destination output\round1\lab-record\guest -Path `
    C:\round1\telemetry-check.json, C:\round1\auditpol.txt, C:\round1\sysmon-active-config.txt, `
    C:\round1\os.txt, C:\round1\powershell-yaml-hashes.txt
Remove-PSSession $s
```

### Files that must be in the repository afterwards

| Path under `docs/validation/results/pilot/` | Count | From |
|---|---|---|
| `smoke-00-SMOKE/smoke-<UTC time>/result.json` | 1 | smoke test |
| `<tier>-<rank>-<technique>/<test guid>/result.json` (e.g. `strong-01-T1003.004/55295ab0-…/result.json`) | 125, less any test that stopped on a harness error | pilot |
| `<tier>-<rank>-<technique>/<test guid>/harness-error.json` | one per harness error, if any | pilot |
| `<tier>-<rank>-<technique>/<test guid>/hayabusa.json`, `alerts.jsonl` | one each per executed test (`alerts.jsonl` only if Hayabusa wrote alerts) | step 4b |
| `scores/rules.csv`, `tests.csv`, `alerts.csv`, `rules.md`, `conversion-manifest.json` | 5 | step 4b |
| `lab-record/host-w32tm.txt` | 1 | `lab-build.md` step 1 |
| `lab-record/virtualbox-version.txt` (VirtualBox) | 1 | step 1 |
| `lab-record/snapshot.txt`, `lab-record/vm.txt` (VirtualBox) | 2 | step 6 |
| `lab-record/lab-days.txt` | 1, if the lab host is the real endpoint | steps 0 and 7 |
| `lab-record/guest/telemetry-check.json`, `auditpol.txt`, `sysmon-active-config.txt`, `os.txt`, `powershell-yaml-hashes.txt` | 5 | copied out during the build |

Do **not** commit `.evtx` files, or any exported logs from the real endpoint (protocol section 10).

When the outputs are committed, change the status line at the top of the protocol from "not executed" to state
that the pilot has run, with its UTC dates. That records status; it is not an amendment.

## Raw data

| Archive | sha256 | Release |
|---|---|---|
| `round1-pilot-raw.zip` | — | — |

## Execution (pilot)

| Tier | Rank | Technique | ART tests | Executed | Prerequisites failed | Execution failed | Harness errors |
|---|---|---|---|---|---|---|---|
| strong | 1 | T1003.004 | 2 | — | — | — | — |
| strong | 2 | T1056.001 | 1 | — | — | — | — |
| strong | 3 | T1218.002 | 1 | — | — | — | — |
| strong | 4 | T1574.011 | 2 | — | — | — | — |
| moderate | 1 | T1003.005 | 1 | — | — | — | — |
| moderate | 2 | T1112 | 92 | — | — | — | — |
| moderate | 3 | T1556.002 | 2 | — | — | — | — |
| moderate | 4 | T1546.008 | 10 | — | — | — | — |
| weak | 1 | T1025 | 1 | — | — | — | — |
| weak | 2 | T1518 | 5 | — | — | — | — |
| weak | 3 | T1552 | 1 | — | — | — | — |
| weak | 4 | T1574.001 | 7 | — | — | — | — |

## Substitutions

None recorded.

## Detection

Filled from `scores/rules.md`, which `python -m tools.score report` writes. The definitions are protocol section 8
and amendment 3:

- **Detected:** at least one alert from a rule derived from the rule under test, on the attack host, inside the
  execution window.
- **Confounded:** detected, but an alert meeting the first two conditions also fell inside the null window.
- **Detection rate:** detected ÷ executed. A conversion failure scores 0.
- **Null window truncated:** the test ran longer than the quiet period, so its null window is the whole quiet
  period.

Pilot numbers are not tier results (see [pilot-plan.md](pilot-plan.md)). The per-test outcomes and every alert are
in `scores/tests.csv` and `scores/alerts.csv`. Telemetry absent is not computed in round 1 (amendment 3).

| Tier | Rank | Technique | Conversion | Executed | Prerequisites failed | Execution failed | Detected | Confounded | Missed | Detection rate | Null window truncated |
|---|---|---|---|---|---|---|---|---|---|---|---|
| strong | 1 | T1003.004 | — | — | — | — | — | — | — | — | — |
| strong | 2 | T1056.001 | — | — | — | — | — | — | — | — | — |
| strong | 3 | T1218.002 | — | — | — | — | — | — | — | — | — |
| strong | 4 | T1574.011 | — | — | — | — | — | — | — | — | — |
| moderate | 1 | T1003.005 | — | — | — | — | — | — | — | — | — |
| moderate | 2 | T1112 | — | — | — | — | — | — | — | — | — |
| moderate | 3 | T1556.002 | — | — | — | — | — | — | — | — | — |
| moderate | 4 | T1546.008 | — | — | — | — | — | — | — | — | — |
| weak | 1 | T1025 | — | — | — | — | — | — | — | — | — |
| weak | 2 | T1518 | — | — | — | — | — | — | — | — | — |
| weak | 3 | T1552 | — | — | — | — | — | — | — | — | — |
| weak | 4 | T1574.001 | — | — | — | — | — | — | — | — | — |

## False positives

Not part of the pilot (protocol section 10).

## Deviations from the protocol

None recorded.
