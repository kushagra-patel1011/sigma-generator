# Architecture

sigma-generator is one Python engine behind three front ends. It is rule-based and deterministic: no model is
called at runtime, and every decision is written into the banner of the rule it produced.

## Generation

```mermaid
flowchart LR
    subgraph inputs["Inputs"]
        ATTACK["ATT&CK Enterprise bundle<br/>techniques, detection strategies,<br/>analytics, groups, procedures"]
        HQIDX["SigmaHQ release index"]
    end

    subgraph frontends["Front ends"]
        CLI["CLI<br/>src/main.py"]
        UI["Local web UI<br/>src/web/"]
        WASM["Browser build<br/>tools/webapp.py + Pyodide"]
    end

    SERVICE["src/service.py<br/>shared service layer"]
    FETCH["src/attack_fetcher.py<br/>index and resolve"]
    MAP["src/mappings.py<br/>log source to Sigma logsource,<br/>with a confidence"]
    GEN["src/sigma_generator.py<br/>rank analytics, mine values,<br/>place artefacts, grade quality"]
    GAPS["src/sigmahq.py<br/>coverage and gaps"]
    PACKS["src/packs.py<br/>group, software and<br/>campaign packs"]
    STIX["src/stix_builder.py<br/>STIX 2.1 bundles"]

    subgraph outputs["Outputs"]
        RULES["Sigma rules and<br/>correlation rules"]
        BUNDLES["STIX bundles"]
        REPORTS["Gap and quality reports"]
    end

    CLI --> SERVICE
    UI --> SERVICE
    WASM --> SERVICE
    ATTACK --> FETCH
    SERVICE --> FETCH --> MAP --> GEN
    HQIDX --> GAPS
    SERVICE --> GAPS
    GAPS --> GEN
    GEN --> PACKS
    GEN --> RULES
    PACKS --> RULES
    GEN --> STIX --> BUNDLES
    GAPS --> REPORTS
```

| Module | Responsibility |
|---|---|
| `src/attack_fetcher.py` | Downloads and indexes ATT&CK: techniques, detection strategies, analytics, groups, software, campaigns, procedures |
| `src/mappings.py` | ATT&CK log source to Sigma logsource, with a confidence and per-field roles |
| `src/sigma_generator.py` | Candidate ranking, artefact placement, quality grading, rules and correlation rules, validation |
| `src/sigmahq.py` | SigmaHQ release index, and coverage and gap analysis |
| `src/packs.py` | Threat detection packs |
| `src/stix_builder.py` | STIX 2.1 bundles and reports |
| `src/service.py` | The layer every front end calls, so a rule from the browser is the rule the CLI writes |

## How correctness is guarded

```mermaid
flowchart LR
    CHANGE["A code change"] --> UNIT["Unit tests<br/>offline fixtures,<br/>one behaviour each"]
    CHANGE --> LINT["make lint<br/>ruff and mypy,<br/>against Python 3.9"]
    CHANGE --> CORPUS["Corpus snapshot<br/>all 697 techniques from a<br/>pinned ATT&CK release"]
    CORPUS --> DIGEST["Digest per technique:<br/>tier, logsource, selections,<br/>correlation parameters"]
    DIGEST --> COMPARE{"Same as<br/>tests/corpus/baseline.json?"}
    COMPARE -- yes --> PASS["CI passes"]
    COMPARE -- no --> DRIFT["Drift report, technique by technique.<br/>Re-bless only if every line is intended"]
    UNIT --> PASS
    LINT --> PASS
```

CI runs the unit tests and the corpus snapshot on Python 3.9 and 3.13, and ruff and mypy on Python 3.11.

## Validation (pre-registered, not executed)

Dashed boxes are not built yet.

```mermaid
flowchart TB
    PROTO["docs/validation-protocol.md<br/>committed first"] --> SEED["Seed = hash of that commit<br/>9eb1930"]
    BASE["Corpus baseline<br/>no drift allowed"] --> DRAW
    ART["Pinned Atomic Red Team index"] --> DRAW
    SEED --> DRAW["tools/validation.py draw<br/>sha256(seed:technique) order,<br/>17 / 17 / 16 per tier"]
    DRAW --> SAMPLE["docs/validation/sample.json<br/>and 50 frozen rule files"]
    SAMPLE --> PILOT["tools/pilot.py<br/>first 12 rules by draw rank"]
    SAMPLE --> RUNNER
    PILOT --> RUNNER["tools/lab/Invoke-Round1.ps1<br/>per test: restore snapshot, settle,<br/>prerequisites, quiet period,<br/>execute, export logs"]
    RUNNER --> RECORDS["result.json and .evtx per test"]
    RECORDS --> SCORE["Scoring: Sigma to Hayabusa,<br/>conversion manifest,<br/>detection and null windows"]
    BENIGN["tools/lab/Export-BenignDay.ps1<br/>daily benign logs and host-day evidence"] --> SCORE
    SCORE --> RESULTS["docs/validation/RESULTS.md"]

    classDef pending stroke-dasharray: 5 5
    class SCORE pending
```

The protocol fixes the sample, the meaning of "detected" and the criteria that would show the tiers are wrong
before any test runs. The pilot is the first slice of that same run. [RESULTS.md](validation/RESULTS.md) lists
the commands for the Windows lab host and the files to copy back.

## Related

- [README](../README.md): usage, features and measured output
- [Case study](case-study.md): problem, constraints, and problems caught before they shipped
- [Validation protocol](validation-protocol.md), [pilot plan](validation/pilot-plan.md),
  [lab build sheet](validation/lab-build.md)
