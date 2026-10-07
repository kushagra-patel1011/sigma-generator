# Validation pilot, round 1

**Status: planned, not executed. No ART test has run.**

The pilot is the first slice of the pre-registered round 1 run described in
[the protocol](../validation-protocol.md): 12 of the 50 sampled rules, run first to prove the lab end to end
before committing the full ~70 hours. How to run it, and what to copy back, is in [RESULTS.md](RESULTS.md).

## What the pilot is, and is not

- **It is part of the protocol run, not a separate experiment.** It uses the same sample, pins, procedure
  (protocol section 8) and runner. Its records go where the full run's records go, and the full run resumes
  from them instead of repeating them.
- **Running it closes the amendment window.** Protocol section 14 allows amendments only before any ART test is
  executed. Once the pilot starts, nothing in the protocol can change. Anything learned is reported as a deviation
  in the results. So the smoke test must pass first (`RESULTS.md`, step 2).
- **Its numbers are not tier results.** Four rules per tier cannot support a claim about a tier. Pilot rules appear
  in the full run's per-rule table, and tier measures are computed only over the full sample.
- **It does not score detections yet.** Scoring needs the protocol's conversion and Hayabusa steps (sections 7
  and 8), and this repository has no script for them yet. The pilot produces the execution records and event logs
  those steps will read.
- **It does not measure false positives.** That is the benign collection (protocol section 10), which is separate.

## Selection rule

From [`sample.json`](sample.json): in each tier, take the sampled rules (`"selected": true`) with the **lowest
draw `rank`**, 4 per tier.

The draw order is already the protocol's seeded random order (`sha256("<seed>:<technique ID>")`), so the pilot
is a random subset of the sample. Sorting by technique ID instead would favour old, low-numbered techniques.
`python -m tools.pilot` prints the selection, and a test keeps the Makefile's lists in step with it.

| Tier | Rank | Technique | Name | Logsource | ART tests |
|---|---|---|---|---|---|
| strong | 1 | T1003.004 | LSA Secrets | `category:process_creation` | 2 |
| strong | 2 | T1056.001 | Keylogging | `category:process_access` | 1 |
| strong | 3 | T1218.002 | Control Panel | `category:process_creation` | 1 |
| strong | 4 | T1574.011 | Services Registry Permissions Weakness | `service:security` | 2 |
| moderate | 1 | T1003.005 | Cached Domain Credentials | `service:security` | 1 |
| moderate | 2 | T1112 | Modify Registry | `category:registry_set` | 92 |
| moderate | 3 | T1556.002 | Password Filter DLL | `service:security` | 2 |
| moderate | 4 | T1546.008 | Accessibility Features | `category:file_event` | 10 |
| weak | 1 | T1025 | Data from Removable Media | `service:security` | 1 |
| weak | 2 | T1518 | Software Discovery | `category:process_creation` | 5 |
| weak | 3 | T1552 | Unsecured Credentials | `category:file_event` | 1 |
| weak | 4 | T1574.001 | DLL | `category:file_event` | 7 |

**125 ART tests in total.** Every eligible test of each rule runs (protocol section 5), and the rule files under
test are in [`rules/`](rules/).

## Run order and lab time

Each test takes about 15 minutes: snapshot restore and boot, 5 minutes of settling, prerequisites, a 5-minute
quiet period, the test, 60 seconds of window, cleanup, and log export.

| Phase | Rules | ART tests | Time |
|---|---|---|---|
| 1 | the 11 rules other than T1112 | 33 | about 8 hours |
| 2 | T1112 | 92 | about 23 hours |

T1112 alone has 92 of the 125 tests, so it runs last. The runner skips tests it has already recorded, so you can
stop after phase 1, review its records, and run phase 2 later.

## Substitution

If every test of a pilot rule fails its prerequisites, protocol section 4 replaces the rule with the next one in
its tier's substitution queue, and the replacement joins the pilot. The first replacements are **T1560** (strong),
**T1048.003** (moderate) and **T1219** (weak). Round 1 has no domain, so T1003.005 (Cached Domain Credentials) is
the likeliest candidate. Run a replacement with `-Execute -Technique <ID>`, and record the substitution in
`RESULTS.md`.

## Before running

- [ ] The lab is built per [lab-build.md](lab-build.md), and the telemetry acceptance test passed on the attack
  VM.
- [ ] The snapshot `round1-clean` exists and has not been booted outside the runner.
- [ ] If the lab host is your real endpoint: the dates the runner runs are added to
  `output/round1/lab-record/lab-days.txt`, because those days are excluded from benign host-days.
- [ ] The smoke test passed.
