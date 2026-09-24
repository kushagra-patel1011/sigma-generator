# Sample outputs

These files were generated against MITRE ATT&CK Enterprise v19.2 and SigmaHQ release r2026-07-01, with deterministic IDs and a TLP:CLEAR marking.

**Single techniques, with correlation rules:**

```bash
python -m src.main generate T1059.001 T1547.001 T1003.001 T1218.011 T1053.005 T1078.004 T1110.003 T1021.006 --chains --deterministic --tlp clear --output-dir examples/sample_outputs
```

**One rule per analytic, across three operating systems:**

```bash
python -m src.main generate T1003 --all-analytics --deterministic --tlp clear --output-dir examples/sample_outputs
```

**A detection pack for Mimikatz:**

```bash
python -m src.main generate --software Mimikatz --chains --deterministic --tlp clear --output-dir examples/sample_outputs
```

Every rule states its quality tier in its banner, and the samples deliberately include every tier:

| Tier | Meaning | What the generator does |
|---|---|---|
| strong | two or more independent behavioural signals | normal level for the tactic |
| moderate | one behavioural signal | level lowered one step - review for noise |
| weak | matches broad activity | tagged `detection.threat-hunting`, level capped at `low` |

## `sigma/` and `stix/` - single techniques

| Technique | File | Quality | What it demonstrates |
|---|---|---|---|
| T1003.001 LSASS Memory | `t1003_001_process_access_*.yml` | strong | `lsass.exe` as the *target*, with dumping tools and the access mask as indicators |
| T1003.001 LSASS Memory | `mr_t1003_001_an1030_*.yml` | strong | **Attack chain**: lsass access, a dumping command line (`comsvcs.dll`, `Invoke-Mimikatz`) and a security-package registry change on one host within ATT&CK's own 5-minute window. No two steps share a value, and ATT&CK's dump-file step is left out because its only values were a Windows DLL's path and a generic folder. |
| T1059.001 PowerShell | `t1059_001_process_creation_*.yml` | strong | An image plus command-line indicators |
| T1053.005 Scheduled Task | `t1053_005_process_creation_*.yml`, `mr_t1053_005_*.yml` | strong / moderate | A process rule, and a chain pairing the task-creation event (4698) with execution |
| T1547.001 Run Keys | `t1547_001_registry_set_*.yml`, `mr_t1547_001_*.yml` | moderate | Registry telemetry chosen over process creation; hive-less key paths; the writing process is not required |
| T1218.011 Rundll32 | `t1218_011_process_creation_*.yml` | moderate | DLL names and arguments placed in the command line |
| T1021.006 WinRM | `t1021_006_conn_*.yml` | moderate | Ports 5985/5986 mined from ATT&CK and placed on Zeek `conn` logs |
| T1110.003 Password Spraying | `mr_t1110_003_*_count_*.yml` | moderate | **Count rule** (`value_count`): 5 or more distinct `TargetUserName`s failing from one `IpAddress` within 10 minutes |
| T1110.003 Password Spraying | `t1110_003_security_*.yml` | weak | The counted base event on its own - a hunting query, clearly marked as such |
| T1078.004 Cloud Accounts | `t1078_004_cloudtrail_*.yml`, `mr_t1078_004_*_count_*.yml` | weak / moderate | Cloud API operations merged from several ATT&CK log-source entries, plus an `event_count` threshold per identity |
| T1003 OS Credential Dumping | 3 rules | strong / moderate / weak | `--all-analytics`: one rule each for Windows, Linux (auditd) and macOS |

Files starting with `mr_` are Sigma correlation rules: one multi-document YAML file with the correlation first, then the base rules it references, as the Sigma correlation specification lays out. `_count_` in the name marks a threshold rule rather than an attack chain. Each `stix/*.json` bundle carries every rule for its technique, and each indicator is labelled with its quality tier (`quality.strong`).

## `packs/s0002_mimikatz/` - a detection pack

For each of the 17 techniques ATT&CK attributes to Mimikatz, the pack contains:

- a rule mined from Mimikatz's own documented procedures first (tagged `attack.s0002`)
- a correlation rule wherever ATT&CK describes multi-step behaviour or volume
- a SigmaHQ coverage verdict

ATT&CK lists Mimikatz as a Windows tool, so every rule in the pack watches Windows telemetry, even where a Linux analytic would have scored higher. The pack's `README.md` shows the quality split (11 strong, 3 moderate, 9 weak across rules and correlations) and a tier for every file. `s0002_mimikatz_bundle.json` is ready for a threat-intel platform: the tool, its techniques, MITRE's `uses` relationships, an indicator per rule and a `report` tying them together.

## Checking and regenerating

Every file passes this check (with pySigma when it is installed):

```bash
python -m src.main validate examples/sample_outputs
```

Rule `date` fields, STIX timestamps and SigmaHQ counts reflect when the files were generated. Re-running the commands later changes only those values, unless ATT&CK or SigmaHQ data has changed.
