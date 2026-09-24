"""The validation sample draw (tools/validation.py), on synthetic data: the
protocol fixes eligibility, ordering and quotas, so each is pinned down here."""

from __future__ import annotations

import subprocess

import pytest

from tools import validation


def _index():
    return {
        "execution": {
            "T1059.001": {"atomic_tests": [
                {"name": "a", "auto_generated_guid": "g1", "supported_platforms": ["windows"],
                 "executor": {"name": "powershell", "elevation_required": True}},
                {"name": "manual", "auto_generated_guid": "g2", "supported_platforms": ["windows"],
                 "executor": {"name": "manual"}},
                {"name": "linux", "auto_generated_guid": "g3", "supported_platforms": ["linux"],
                 "executor": {"name": "sh"}},
            ]},
        },
        "persistence": {
            # The same test filed under a second tactic must not be counted twice.
            "T1059.001": {"atomic_tests": [
                {"name": "a", "auto_generated_guid": "g1", "supported_platforms": ["windows"],
                 "executor": {"name": "powershell"}},
            ]},
            "T1547": {"atomic_tests": [
                {"name": "b", "auto_generated_guid": "g4", "supported_platforms": ["Windows"],
                 "executor": {"name": "command_prompt"}},
            ]},
        },
    }


def _rule(technique_id, tier, logsource="category:process_creation"):
    return {"technique_id": technique_id, "technique_name": technique_id, "tier": tier,
            "analytic": "AN0001", "logsource": logsource, "level": "medium"}


def test_art_tests_are_windows_automated_and_deduplicated():
    tests = validation.art_tests_by_technique(_index())
    assert [t["guid"] for t in tests["T1059.001"]] == ["g1"]
    assert tests["T1059.001"][0]["elevation_required"] is True
    assert [t["guid"] for t in tests["T1547"]] == ["g4"]


def test_population_keeps_the_default_windows_rule_only():
    digest = {"techniques": {
        "T1": {"name": "one", "rules": [
            {"logsource": {"product": "windows", "category": "process_creation"}, "tier": "strong",
             "analytic": "AN1", "level": "high"},
            {"logsource": {"product": "linux", "category": "process_creation"}, "tier": "strong",
             "analytic": "AN2", "level": "high"},
        ]},
        "T2": {"name": "two", "rules": [
            {"logsource": {"product": "linux", "category": "process_creation"}, "tier": "weak",
             "analytic": "AN3", "level": "low"},
            {"logsource": {"product": "windows", "service": "security"}, "tier": "weak",
             "analytic": "AN4", "level": "low"},
        ]},
        "T3": {"name": "three", "rules": []},
    }}
    rules = validation.population(digest)
    assert [(r["technique_id"], r["analytic"], r["logsource"]) for r in rules] == [
        ("T1", "AN1", "category:process_creation")]


def test_eligibility_needs_exact_technique_tests_and_a_recorded_logsource():
    tests = validation.art_tests_by_technique(_index())
    rules = [
        _rule("T1059.001", "strong"),
        _rule("T1059", "strong"),                         # parent does not borrow sub-technique tests
        _rule("T1547", "weak", logsource="category:not_recorded"),
        _rule("T1547", "weak"),
    ]
    chosen = validation.eligible(rules, tests)
    assert [(r["technique_id"], r["logsource"]) for r in chosen] == [
        ("T1059.001", "category:process_creation"), ("T1547", "category:process_creation")]
    assert chosen[0]["art_tests"][0]["guid"] == "g1"


def test_draw_orders_by_seeded_hash_and_fills_quotas():
    candidates = [_rule(f"T{n:04d}", tier) for n, tier in
                  enumerate(["strong"] * 5 + ["moderate"] * 3 + ["weak"] * 1)]
    quota = {"strong": 2, "moderate": 3, "weak": 2}
    strata = validation.draw(candidates, "seed-a", quota)

    strong = strata["strong"]
    assert [r["order_key"] for r in strong] == sorted(validation.order_key("seed-a", r["technique_id"])
                                                      for r in strong)
    assert [r["selected"] for r in strong] == [True, True, False, False, False]
    assert [r["rank"] for r in strong] == [1, 2, 3, 4, 5]
    assert all(r["selected"] for r in strata["moderate"])
    assert len(strata["weak"]) == 1 and strata["weak"][0]["selected"]   # a short tier takes everything

    again = validation.draw(candidates, "seed-a", quota)
    assert [r["technique_id"] for r in again["strong"]] == [r["technique_id"] for r in strong]
    other = validation.draw(candidates, "seed-b", quota)
    assert [r["technique_id"] for r in other["strong"]] != [r["technique_id"] for r in strong]


def test_order_key_is_sha256_of_seed_and_technique():
    import hashlib

    assert validation.order_key("abc", "T1003.001") == hashlib.sha256(b"abc:T1003.001").hexdigest()


def _git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                          cwd=str(cwd), check=True, capture_output=True, text=True).stdout.strip()


def test_seed_is_the_commit_that_first_added_the_protocol(tmp_path):
    _git(tmp_path, "init", "-q")
    (tmp_path / "other.txt").write_text("x\n")
    _git(tmp_path, "add", "other.txt")
    _git(tmp_path, "commit", "-q", "-m", "before")
    with pytest.raises(validation.ValidationError):
        validation.protocol_seed(tmp_path)

    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "validation-protocol.md").write_text("v1\n")
    _git(tmp_path, "add", "docs")
    _git(tmp_path, "commit", "-q", "-m", "protocol")
    added = _git(tmp_path, "rev-parse", "HEAD")

    (tmp_path / "docs" / "validation-protocol.md").write_text("v1\namendment\n")
    _git(tmp_path, "commit", "-q", "-am", "amend")
    assert validation.protocol_seed(tmp_path) == added
