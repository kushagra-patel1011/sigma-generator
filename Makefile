PYTHON ?= python

.PHONY: test lint typecheck corpus-fetch corpus corpus-bless pilot-plan pilot-smoke pilot score

# Offline unit tests (~10s).
test:
	$(PYTHON) -m pytest -q

# Static checks: ruff (pyflakes and pycodestyle errors) and mypy. Configured in pyproject.toml.
lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m mypy

typecheck:
	$(PYTHON) -m mypy

# Download the pinned ATT&CK bundle the corpus snapshot is generated from.
corpus-fetch:
	$(PYTHON) -m tools.corpus fetch

# Compare the full corpus with tests/corpus/baseline.json.
corpus: corpus-fetch
	$(PYTHON) -m pytest -q -m corpus

# Print the drift and accept it as the new baseline. Commit the result.
corpus-bless: corpus-fetch
	$(PYTHON) -m tools.corpus bless

# --- Validation pilot -------------------------------------------------------- #
# Windows lab host only, from an elevated prompt, after building the lab with
# docs/validation/lab-build.md. See docs/validation/pilot-plan.md. The phases are
# `python -m tools.pilot --ids`; a test keeps these lists in step with it.
HYPERVISOR ?= VirtualBox
PILOT_PHASE1 = T1003.004,T1056.001,T1218.002,T1574.011,T1003.005,T1556.002,T1546.008,T1025,T1518,T1552,T1574.001
PILOT_PHASE2 = T1112
# -Command, not -File: only -Command turns `-Technique A,B` into an array.
round1 = powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& ./tools/lab/Invoke-Round1.ps1 $(1)"

# List the pilot's tests and the time estimate. Runs nothing.
pilot-plan:
	$(call round1,-Technique $(PILOT_PHASE1)$(comma)$(PILOT_PHASE2))

# One full cycle with a harmless command and no ART test: proves the lab works.
pilot-smoke:
	$(call round1,-Hypervisor $(HYPERVISOR) -SmokeTest)

# Executes the pilot: phase 1 (33 ART tests, ~8 h), then phase 2 (T1112, 92 tests, ~23 h).
# Resumable: tests already recorded are skipped, so it can be stopped after phase 1.
pilot:
	$(call round1,-Hypervisor $(HYPERVISOR) -Execute -Technique $(PILOT_PHASE1))
	$(call round1,-Hypervisor $(HYPERVISOR) -Execute -Technique $(PILOT_PHASE2))

comma := ,

# Scoring (protocol sections 7-8): pinned converter and Hayabusa, the conversion manifest, one Hayabusa run per
# executed test, and the per-rule detection table. Run where the runner's .evtx files are.
RESULTS ?= output/round1
SCORES ?= output/round1-scores
score:
	$(PYTHON) -m tools.score all --results $(RESULTS) --out $(SCORES)
