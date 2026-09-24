"""Corpus snapshot: the digest and diff logic (fast, on the fixture) and the
full-corpus check against the committed baseline (``-m corpus``, needs the
pinned ATT&CK bundle from ``python -m tools.corpus fetch``)."""

from __future__ import annotations

import copy
import json

import pytest

from conftest import ATTACK_FIXTURE
from src.attack_fetcher import AttackDataset
from tools import corpus


@pytest.fixture(scope="module")
def fixture_digest():
    return corpus.build_digest(AttackDataset.from_file(ATTACK_FIXTURE), source_sha256="fixture")


def _first_generated(digest):
    return next(tid for tid, entry in digest["techniques"].items() if entry["rules"])


def test_digest_is_deterministic_and_carries_no_volatile_fields(fixture_digest):
    again = corpus.build_digest(AttackDataset.from_file(ATTACK_FIXTURE), source_sha256="fixture")
    assert corpus.dump_digest(again) == corpus.dump_digest(fixture_digest)
    text = corpus.dump_digest(fixture_digest)
    for volatile in ('"id"', '"date"', '"title"', '"description"'):
        assert volatile not in text
    statuses = {entry["status"] for entry in fixture_digest["techniques"].values()}
    assert statuses <= {"generated", "insufficient", "unmappable"}
    assert any(entry["correlations"] for entry in fixture_digest["techniques"].values())


def test_identical_digests_have_no_drift(fixture_digest):
    assert corpus.compare(fixture_digest, copy.deepcopy(fixture_digest)) == []


def test_drift_reports_tier_change_and_lost_values(fixture_digest):
    changed = copy.deepcopy(fixture_digest)
    technique_id = _first_generated(changed)
    rule = changed["techniques"][technique_id]["rules"][0]
    old_tier = rule["tier"]
    rule["tier"] = "placeholder"
    selection, block = next((name, block) for name, block in rule["detection"].items()
                            if name != "condition" and isinstance(block, dict))
    field, values = next(iter(block.items()))
    lost = values.pop(0)

    report = "\n".join(corpus.compare(fixture_digest, changed))
    assert "1 technique(s) changed" in report
    assert f"{old_tier} -> placeholder x1" in report
    assert technique_id in report
    assert f"{selection} {field} lost {json.dumps([lost], ensure_ascii=False)}" in report


def test_drift_refuses_a_baseline_from_another_release(fixture_digest):
    other = copy.deepcopy(fixture_digest)
    other["attack"]["sha256"] = "something-else"
    report = corpus.compare(other, fixture_digest)
    assert len(report) == 1 and "re-bless" in report[0]


@pytest.mark.corpus
def test_corpus_matches_baseline():
    try:
        dataset = corpus.load_pinned_dataset()
        baseline = corpus.load_baseline()
    except corpus.CorpusError as exc:
        pytest.fail(str(exc))
    drift = corpus.compare(baseline, corpus.build_digest(dataset, source_sha256=corpus.PINNED_ATTACK["sha256"]))
    if drift:
        pytest.fail("\n".join(drift) + "\n\nIf this change is intended: python -m tools.corpus bless", pytrace=False)
