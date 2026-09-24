# Project guide

sigma-generator turns MITRE ATT&CK techniques, groups, software and campaigns into draft Sigma
detection rules, Sigma correlation rules and STIX 2.1 bundles. Everything is rule-based and
deterministic: no model is called at runtime, and every decision is written into the output banner.

## Commands

```bash
python -m pytest                       # 361 offline tests, ~10s
python -m src.main generate T1003.001 --chains
python -m src.main quality --group APT29
python -m src.main gaps T1621
python -m src.main ui                  # local web interface on 127.0.0.1:8765
python -m src.main update              # download ATT&CK (~55 MB) and the SigmaHQ index (~3 MB)
```

`pip install -r requirements-dev.txt` installs pytest and pySigma. Without pySigma the suite still
passes; the tests that need it skip themselves.

## Layout

| Path | Responsibility |
|---|---|
| `src/attack_fetcher.py` | Downloads and indexes ATT&CK: techniques, detection strategies, analytics, groups, software, campaigns, procedures |
| `src/mappings.py` | ATT&CK log source -> Sigma logsource, with a confidence and per-field roles |
| `src/sigma_generator.py` | Candidate ranking, artefact placement, quality grading, rules and correlation rules, validation |
| `src/sigmahq.py` | SigmaHQ release index and coverage/gap analysis |
| `src/packs.py` | Threat detection packs (group/software/campaign) |
| `src/stix_builder.py` | STIX 2.1 bundles and reports |
| `src/service.py` | Shared layer used by both the CLI and the web UI |
| `src/web/` | Standard-library HTTP server plus a dependency-free single-page app |
| `src/main.py` | The CLI |
| `src/data/tools.yml` | Curated tool vocabulary used when mining ATT&CK prose |

## Data

`data/*.json` (the ATT&CK bundle and the SigmaHQ index) is **not** in the repository: it is large and
re-downloadable with `update`. Nothing in the test suite needs it. The tests run against
`tests/fixtures/mini-attack.json` and `tests/fixtures/mini-sigmahq-index.json` with `--offline`, so a
fresh clone can run everything immediately.

Generated output goes to `output/` and is ignored by git.

## Conventions

- **Python 3.9+.** No syntax or standard-library feature newer than 3.9 (checked with vermin).
- **Runtime dependencies are PyYAML and requests only.** The web UI adds none: no framework, no build
  step, no external fonts or scripts. Keep it that way.
- **The web page is served under a strict Content-Security-Policy** (`default-src 'self'`). Inline
  `style="..."` attributes, inline `<script>` and anything loaded from another origin are blocked.
  Styling belongs in `styles.css`, and the page must insert text with `textContent`, never `innerHTML`.
- **Files are written with LF line endings** (`.gitattributes` enforces it) so runs on Windows, Linux
  and macOS produce byte-identical rules.
- **Rules must stay valid.** `validate_rule` and, when installed, pySigma check every generated file.
  A change that alters generated content should be checked across the whole corpus, not one technique.
- **Paths given on the command line are relative to the working directory**; only the built-in
  defaults resolve against the checkout (see `resolve_path` in `src/utils.py`).

## Rule quality model

Every rule, chain step and count rule is graded by what its detection block contains:

- **strong** - two or more selections with specific values
- **moderate** - one subject selection (registry key, target process, file, port), or several specific
  values in one selection
- **weak** - only an event type, a single value, or values common in normal activity; tagged
  `detection.threat-hunting` and capped at level `low`
- **placeholder** - nothing concrete, so no rule is written unless `--include-skeletons` is passed

Grading rules to preserve when changing the generator:

- Values common in normal activity (`powershell.exe`, `/bin/bash`, `C:\Windows\Temp`) are dropped from
  a list of alternatives unless another part of the rule is specific.
- Attack-chain steps never repeat a value already claimed by another step.
- Count rules are only written where ATT&CK describes an amount of countable activity, and only over a
  weak base event unless that log source's own text mentions volume.
- A software pack stays on the platforms ATT&CK lists for that software.

## Testing

`tests/test_generator.py` covers the core engine, `tests/test_features.py` the packs, gaps, service
layer and web UI, and `tests/test_quality.py` the quality model, mostly against small synthetic ATT&CK
analytics so each behaviour is pinned down on its own. Add tests in the file that matches the area, and
prefer a synthetic analytic over a real technique when testing one behaviour: real ATT&CK data changes
between versions.
