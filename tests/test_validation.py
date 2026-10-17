"""The validation sample draw (tools/validation.py), on synthetic data: the
protocol fixes eligibility, ordering and quotas, so each is pinned down here."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone

import pytest

from tools import population, substitute, validation


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


# --------------------------------------------------------------------------- #
# Pilot (tools/pilot.py, docs/validation/pilot-plan.md)
# --------------------------------------------------------------------------- #
def test_pilot_takes_the_lowest_draw_ranks_in_each_tier():
    from tools import pilot

    sample = pilot.load_sample()
    chosen = pilot.select(sample)
    for tier in pilot.TIERS:
        ranks = sorted(rule["rank"] for rule in sample["strata"][tier] if rule["selected"])
        assert [rule["rank"] for rule in chosen[tier]] == ranks[:pilot.PER_TIER]
        assert all(rule["selected"] for rule in chosen[tier])


def test_pilot_runs_the_largest_rule_last():
    from tools import pilot

    def rule(technique_id, tests):
        return {"technique_id": technique_id, "art_tests": [{}] * tests}

    chosen = {"strong": [rule("T2", 3)], "moderate": [rule("T1", 9), rule("T3", 1)], "weak": [rule("T4", 9)]}
    assert pilot.phases(chosen) == (["T2", "T1", "T3"], ["T4"])


def test_makefile_and_plan_list_the_pilot():
    from tools import pilot

    first, second = pilot.phases(pilot.select(pilot.load_sample()))
    makefile = (pilot.ROOT / "Makefile").read_text(encoding="utf-8")
    assert f"PILOT_PHASE1 = {','.join(first)}\n" in makefile
    assert f"PILOT_PHASE2 = {','.join(second)}\n" in makefile
    plan = (pilot.ROOT / "docs" / "validation" / "pilot-plan.md").read_text(encoding="utf-8")
    for technique_id in first + second:
        assert f"| {technique_id} |" in plan


# --------------------------------------------------------------------------- #
# The frozen population (amendment 4) and substitution (protocol section 4)
# --------------------------------------------------------------------------- #
def test_frozen_population_matches_its_manifest_and_the_drawn_files():
    assert population.check_frozen() == []


def test_frozen_population_has_the_protocols_counts_and_every_queued_rule():
    frozen, sample = population.load_population(), population.load_sample()
    assert frozen["generated_at_commit"] == sample["seed"]
    assert frozen["counts"]["rules"] == {tier: c["default_rules"] for tier, c in sample["population"].items()}
    assert frozen["counts"]["correlations"] == population.EXPECTED_CORRELATIONS
    by_technique = population.rules_by_technique(frozen)
    for rules in sample["strata"].values():
        for rule in rules:
            entry = by_technique[rule["technique_id"]]
            assert (entry["tier"], entry["analytic"], entry["logsource"], entry["level"]) == \
                (rule["tier"], rule["analytic"], rule["logsource"], rule["level"])
            assert entry["sample"] == ("sampled" if rule["selected"] else "queued")


def _drawn(sample, tier, rank):
    return next(r for r in sample["strata"][tier] if r["rank"] == rank)


def _write_record(results, tier, rule, rule_id, guid, met):
    folder = results / f"{tier}-{int(rule['rank']):02d}-{rule['technique_id']}" / guid
    folder.mkdir(parents=True)
    (folder / "result.json").write_text(json.dumps({
        "tier": tier, "rank": rule["rank"], "technique_id": rule["technique_id"], "rule_id": rule_id,
        "test_guid": guid, "test_name": "t", "prereq_status": "met" if met else "failed",
        "prereq_check_output": "Prerequisites not met"}), encoding="utf-8")


def test_substitution_takes_the_next_queued_rule_once_every_test_failed_prerequisites(tmp_path):
    sample, frozen = population.load_sample(), population.load_population()
    rule = _drawn(sample, "moderate", 1)                      # T1003.005, one ART test
    assert substitute.apply(sample, frozen, tmp_path) == []
    _write_record(tmp_path, "moderate", rule, rule["rule_id"], rule["art_tests"][0]["guid"], met=False)

    added = substitute.apply(sample, frozen, tmp_path, now=datetime(2026, 10, 20, tzinfo=timezone.utc))

    queued = _drawn(sample, "moderate", 18)
    assert [(e["replaced"]["technique_id"], e["replacement"]["technique_id"]) for e in added] == \
        [(rule["technique_id"], queued["technique_id"])]
    assert added[0]["replacement"]["rule_file"].startswith("population/rules/")
    assert added[0]["failed_tests"][0]["prereq_check_output"] == "Prerequisites not met"
    current = substitute.current_sample(sample, substitute.load_substitutions(tmp_path), frozen)
    assert current["moderate"][0]["technique_id"] == queued["technique_id"]
    assert len(current["moderate"]) == 17
    assert substitute.apply(sample, frozen, tmp_path) == []           # nothing further is due


def test_substitution_is_not_due_while_a_test_ran_or_is_unrecorded(tmp_path):
    sample, frozen = population.load_sample(), population.load_population()
    rule = _drawn(sample, "moderate", 2)                      # T1112, 92 ART tests
    for test in rule["art_tests"][:-1]:
        _write_record(tmp_path, "moderate", rule, rule["rule_id"], test["guid"], met=False)
    assert not any(row["due"] for row in substitute.status(sample, [], frozen, tmp_path))
    _write_record(tmp_path, "moderate", rule, rule["rule_id"], rule["art_tests"][-1]["guid"], met=True)
    assert substitute.apply(sample, frozen, tmp_path) == []


def test_a_replacement_that_also_fails_is_replaced_by_the_next_in_queue(tmp_path):
    sample, frozen = population.load_sample(), population.load_population()
    first, second, third = _drawn(sample, "moderate", 1), _drawn(sample, "moderate", 18), _drawn(sample, "moderate", 19)
    _write_record(tmp_path, "moderate", first, first["rule_id"], first["art_tests"][0]["guid"], met=False)
    substitute.apply(sample, frozen, tmp_path)
    second_id = population.rules_by_technique(frozen)[second["technique_id"]]["rule_id"]
    for test in second["art_tests"]:
        _write_record(tmp_path, "moderate", second, second_id, test["guid"], met=False)

    added = substitute.apply(sample, frozen, tmp_path)

    assert [e["replacement"]["technique_id"] for e in added] == [third["technique_id"]]
    assert [e["replaced"]["technique_id"] for e in substitute.load_substitutions(tmp_path)] == \
        [first["technique_id"], second["technique_id"]]


def test_a_substitution_out_of_queue_order_or_with_another_rule_is_refused(tmp_path):
    sample, frozen = population.load_sample(), population.load_population()
    first, skipped = _drawn(sample, "moderate", 1), _drawn(sample, "moderate", 19)
    entry = {"tier": "moderate", "replaced": {"technique_id": first["technique_id"]},
             "replacement": {"technique_id": skipped["technique_id"],
                             "rule_id": population.rules_by_technique(frozen)[skipped["technique_id"]]["rule_id"]}}
    with pytest.raises(substitute.SubstitutionError, match="next moderate rule"):
        substitute.current_sample(sample, [entry], frozen)
    entry["replacement"] = {"technique_id": _drawn(sample, "moderate", 18)["technique_id"], "rule_id": "made-up"}
    with pytest.raises(substitute.SubstitutionError, match="frozen population"):
        substitute.current_sample(sample, [entry], frozen)
    entry["replaced"] = {"technique_id": _drawn(sample, "strong", 1)["technique_id"]}
    with pytest.raises(substitute.SubstitutionError, match="not in the moderate sample"):
        substitute.current_sample(sample, [entry], frozen)
