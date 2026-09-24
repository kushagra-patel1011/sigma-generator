"""Shared test configuration.

Every test runs against the fixtures in ``tests/fixtures`` and must never read
the real ``data/`` caches or reach the network.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ATTACK_FIXTURE = FIXTURES / "mini-attack.json"
SIGMAHQ_FIXTURE = FIXTURES / "mini-sigmahq-index.json"


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path_factory, monkeypatch):
    """Point every default data path somewhere empty, so a missing ``--data`` or
    ``--sigmahq`` flag fails loudly instead of silently using local caches."""
    empty = tmp_path_factory.mktemp("no-data")
    monkeypatch.setenv("ATTACK_DATA_PATH", str(empty / "enterprise-attack.json"))
    monkeypatch.setenv("SIGMAHQ_INDEX_PATH", str(empty / "sigmahq-index.json"))
    monkeypatch.setenv("SIGMAHQ_RELEASE_URL", "http://127.0.0.1:9/unreachable.zip")
    monkeypatch.setenv("ATTACK_INDEX_URL", "http://127.0.0.1:9/unreachable.json")
    for name in ("SIGMA_AUTHOR", "SIGMA_STATUS", "SIGMA_OUTPUT_DIR", "STIX_TLP", "STIX_IDENTITY_NAME"):
        monkeypatch.delenv(name, raising=False)
