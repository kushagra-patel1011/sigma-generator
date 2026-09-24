PYTHON ?= python

.PHONY: test corpus-fetch corpus corpus-bless

# Offline unit tests (~10s).
test:
	$(PYTHON) -m pytest -q

# Download the pinned ATT&CK bundle the corpus snapshot is generated from.
corpus-fetch:
	$(PYTHON) -m tools.corpus fetch

# Compare the full corpus with tests/corpus/baseline.json.
corpus: corpus-fetch
	$(PYTHON) -m pytest -q -m corpus

# Print the drift and accept it as the new baseline. Commit the result.
corpus-bless: corpus-fetch
	$(PYTHON) -m tools.corpus bless
