# Case study: sigma-generator

## Problem

Detection engineers start a new detection by reading MITRE ATT&CK for a technique, deciding which telemetry would
show it, and writing a Sigma rule by hand. For one technique that is an afternoon. For the 66 techniques ATT&CK
attributes to a single group such as APT29, it is weeks. The community rule set, SigmaHQ, covers part of that
ground. In its r2026-07-01 release it contains no correlation rules at all, so multi-step behaviour ("opens LSASS,
then writes a dump file") is left to each team.

sigma-generator turns ATT&CK's own detection strategies and analytics into draft Sigma rules, correlation rules
and STIX 2.1 bundles. It grades each draft by how much real detection content it has, and shows where SigmaHQ
already has coverage.

## Constraints

- **Deterministic and explainable.** No AI model at runtime. Every decision is written into a banner on the rule,
  so a reviewer can see where each value came from.
- **Small footprint.** Runtime dependencies are PyYAML and requests only. Python 3.9 and newer.
- **Safe to run locally.** The web UI is localhost-only, under a strict Content-Security-Policy, with CSRF and
  DNS-rebinding protection.
- **Honest output.** A technique with no concrete values gets no rule, rather than a keyword search of prose
  presented as a detection.

## What was built

| Piece | What it does |
|---|---|
| Generator | Ranks ATT&CK analytics, maps their log sources to Sigma logsources with a confidence, mines concrete values, and writes rules, `temporal` attack chains and `event_count` / `value_count` rules |
| Quality model | Grades every rule strong, moderate or weak by its detection block. Weak rules are tagged as hunting queries and capped at level `low` |
| Packs and gaps | Detection packs per threat group, software or campaign, mining that actor's documented procedures first. A gap check against SigmaHQ |
| Front ends | CLI, a local web UI, and a browser build that runs the same Python in WebAssembly with no server |
| Corpus snapshot | Generates all 697 active techniques from a pinned ATT&CK release, reduces each to a digest of detection content, and compares it with a committed baseline in CI. Any change is reported technique by technique |
| Static checks | ruff and mypy, run against Python 3.9, locally (`make lint`) and in CI |
| Validation protocol | A pre-registered plan to test the quality tiers against Atomic Red Team and benign telemetry, with a seeded sample, an exact definition of "detected", and falsification criteria fixed before any data |
| Lab tooling | A runner for VirtualBox or Hyper-V, a telemetry acceptance test, and a daily benign-log export, all in Windows PowerShell 5.1 |
| Detection scoring | Converts the rules under test with the pinned converter, traces every converted rule back to its original through a manifest, runs the pinned Hayabusa per test, and applies the protocol's definition of "detected", including the null window |

## Problems caught before they shipped

Each of these was caught by a test, a type checker, or a review of the code against the tools it drives. None of
them reached a user.

| Problem | Effect if it had shipped | How it was caught |
|---|---|---|
| **Silent rule drift.** A one-line change to the list of values that are too common to alert on would have changed 16 techniques, including switching T1218's default rule from Windows to macOS, with every unit test still passing | Rules quietly change platform or lose their specific values | The corpus snapshot. It was demonstrated with a deliberate change, which was then reverted |
| **Windows PowerShell 5.1 and stderr.** Redirecting a native command's stderr while errors are set to stop turns the first stderr line into a terminating error. `VBoxManage` writes its progress to stderr | The first snapshot restore would abort the lab run; `net use` and `Sysmon64 -c` in the telemetry check would fail the same way | Reviewing the runner against PowerShell 5.1 behaviour |
| **Host-day rule.** The first definition of a usable benign day excluded any day on which Sysmon stopped | On a machine shut down every night, almost no day would count, while a day the machine stayed off would count as quiet | Reviewing the rule against how the real endpoint is used |
| **Null window order.** The control window for background activity was defined to match the length of an execution window that had not happened yet | The procedure could not be carried out as written | Reviewing the protocol step by step before committing it |
| **Guest networking.** The build sheet assigned static addresses to adapters that start on DHCP | VM setup would fail with "address already exists" | Reviewing the build steps |
| **Python 3.9 crash in the browser build.** `Path.write_text(newline=...)` only exists from Python 3.10 | `tools/webapp.py` raised `TypeError` on the oldest supported Python | mypy, then reproduced on Python 3.9 |
| **PowerShell list arguments.** `powershell -File script.ps1 -Technique A,B` passes `"A,B"` as one string | The pilot command would select **0** tests and appear to succeed | Running the plan mode both ways |
| **Unavailable type stubs.** The newest stub packages no longer install on Python 3.9 | The Python 3.9 CI job would fail while installing dependencies | Installing the dev requirements into a fresh Python 3.9 environment before pushing |

## Results

**Pending.** The validation protocol is pre-registered and has not been executed. No Atomic Red Team test has run,
and no benign telemetry has been evaluated. The quality tiers describe how much content a rule has, not how well it
detects. [RESULTS.md](validation/RESULTS.md) is an empty template until the lab runs.

What is measured today is the generator's output: 556 rules over 697 techniques (130 strong, 195 moderate, 231
weak), 232 correlation rules with `--all-analytics`, and zero files failing Sigma or pySigma validation (see the
[README](../README.md#measured-against-attck-enterprise-v192-and-sigmahq-r2026-07-01)).

## Limitations

- The rules are drafts mined from ATT&CK's data and prose, not from any organisation's telemetry.
- The tiers are untested against attacks until the validation runs.
- Validation round 1 covers Windows only. Only rules whose technique has automated Atomic Red Team tests are
  eligible, which favours strong rules: 83% of strong rules are eligible against 49% of weak ones.
- The benign data planned for round 1 is one real endpoint plus lab VMs: a lower bound on false positives.
- Detection scoring is tested on synthetic records, and on a real Hayabusa run over a public sample log, but not
  yet on lab output. False-positive scoring over benign host-days has no script yet.
- The lab scripts are checked for syntax and against a simulated `VBoxManage`, but have not run on real hardware.

## Next steps

1. Build the lab ([lab-build.md](validation/lab-build.md)) and pass the smoke test.
2. Run the pilot ([pilot-plan.md](validation/pilot-plan.md)): 12 rules, 125 tests.
3. Score the pilot with `tools/score.py`, and write the false-positive scoring over benign host-days.
4. Collect at least 7 complete benign days, run the full sample, and publish the results, including if they show
   the tiers are wrong.
