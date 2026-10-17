"""Validation scoring (tools/score.py): the protocol's "detected" definition, on synthetic runner records
and synthetic Hayabusa alerts shaped like the JSONL that Hayabusa v4.1.0 writes with ``-U``."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from tools import score

HOST = "ROUND1-ATK"
RULE = "3215070d-085c-5aed-bbcd-cba61620e191"
DERIVED = {"aaaaaaaa-0000-0000-0000-000000000001", "aaaaaaaa-0000-0000-0000-000000000002"}


def _record(**overrides):
    record = {
        "technique_id": "T1056.001", "rule_id": RULE, "test_guid": "test-1", "test_name": "Input Capture",
        "preflight": {"computer": HOST}, "prereq_status": "met", "execution_status": "executed",
        "quiet_start_utc": "2026-10-07T10:00:00.0000000Z",
        "t0_utc": "2026-10-07T10:05:00.0000000Z",    # execution window: 10:04:55 .. 10:06:10
        "t1_utc": "2026-10-07T10:05:10.0000000Z",    # null window:      10:03:40 .. 10:04:55
    }
    record.update(overrides)
    return record


def _alert(timestamp, computer=HOST, rule_id="aaaaaaaa-0000-0000-0000-000000000001"):
    return {"Timestamp": timestamp, "RuleTitle": "x", "Level": "med", "Computer": computer,
            "Channel": "Sysmon", "EventID": 10, "RecordID": 1, "RuleID": rule_id}


# --------------------------------------------------------------------------- #
# The four required cases
# --------------------------------------------------------------------------- #
def test_alert_from_the_rule_on_the_host_inside_the_window_is_detected():
    result = score.score_test(_record(), [_alert("2026-10-07 10:05:03.250 +00:00")], DERIVED, None, HOST)
    assert result.outcome == "detected"
    assert (result.in_execution_window, result.in_null_window) == (1, 0)


def test_alert_outside_the_execution_window_is_not_a_detection():
    late = _alert("2026-10-07 10:06:10.001 +00:00")        # 1 ms after t1 + 60 s
    result = score.score_test(_record(), [late], DERIVED, None, HOST)
    assert result.outcome == "missed"
    assert result.alerts_for_rule == 1 and result.in_execution_window == 0


def test_alert_from_another_host_is_not_a_detection():
    other = _alert("2026-10-07 10:05:03.250 +00:00", computer="WORKSTATION7")
    result = score.score_test(_record(), [other], DERIVED, None, HOST)
    assert result.outcome == "missed"
    assert result.other_host == 1


def test_conversion_failure_scores_zero_even_with_matching_alerts(tmp_path):
    alerts = [_alert("2026-10-07 10:05:03.250 +00:00")]
    result = score.score_test(_record(), alerts, DERIVED, "the converter produced no rule", HOST)
    assert result.outcome == "conversion_failure"

    rows = score.score_rules(_sample(), [result], {RULE: "the converter produced no rule"}, {})
    assert rows[0].executed == 1 and rows[0].detected == 0
    assert rows[0].detection_rate == 0.0
    assert rows[0].conversion.startswith("failed")


# --------------------------------------------------------------------------- #
# The rest of the definition
# --------------------------------------------------------------------------- #
def test_alert_from_an_unrelated_rule_is_ignored():
    unrelated = _alert("2026-10-07 10:05:03.250 +00:00", rule_id="ffffffff-0000-0000-0000-000000000000")
    result = score.score_test(_record(), [unrelated], DERIVED, None, HOST)
    assert result.outcome == "missed" and result.alerts_for_rule == 0


def test_null_window_alert_makes_a_detection_confounded():
    alerts = [_alert("2026-10-07 10:05:03.250 +00:00"), _alert("2026-10-07 10:04:00.000 +00:00")]
    result = score.score_test(_record(), alerts, DERIVED, None, HOST)
    assert result.outcome == "confounded"
    assert (result.in_execution_window, result.in_null_window) == (1, 1)


def test_null_window_alert_alone_is_a_miss():
    result = score.score_test(_record(), [_alert("2026-10-07 10:04:00.000 +00:00")], DERIVED, None, HOST)
    assert result.outcome == "missed" and result.in_null_window == 1


def test_window_edges_execution_inclusive_null_half_open():
    windows = score.windows_for(_record())
    assert windows.in_execution(score.parse_time("2026-10-07 10:04:55.000 +00:00"))
    assert windows.in_execution(score.parse_time("2026-10-07 10:06:10.000 +00:00"))
    assert not windows.in_null(score.parse_time("2026-10-07 10:04:55.000 +00:00"))
    assert windows.in_null(score.parse_time("2026-10-07 10:03:40.000 +00:00"))


def test_null_window_is_clipped_to_the_quiet_period_and_flagged():
    long_test = _record(t1_utc="2026-10-07T10:12:00.0000000Z")    # L = 12 min 5 s > 5 min quiet period
    windows = score.windows_for(long_test)
    assert windows.null_truncated
    assert windows.null_start == score.parse_time("2026-10-07T10:00:00Z")


def test_several_alerts_in_the_window_are_one_detection():
    alerts = [_alert(f"2026-10-07 10:05:0{i}.000 +00:00") for i in range(3)]
    result = score.score_test(_record(), alerts, DERIVED, None, HOST)
    assert result.outcome == "detected" and result.in_execution_window == 3


def test_any_derived_rule_counts():
    alert = _alert("2026-10-07 10:05:03.250 +00:00", rule_id="aaaaaaaa-0000-0000-0000-000000000002")
    assert score.score_test(_record(), [alert], DERIVED, None, HOST).outcome == "detected"


def test_host_match_ignores_case_and_domain():
    assert score.same_host("round1-atk.lab.local", HOST)
    assert not score.same_host("ROUND1-ATK2", HOST)
    assert not score.same_host("", HOST)


def test_failed_prerequisites_leave_the_denominator():
    failed = score.score_test(_record(prereq_status="failed"), [], DERIVED, None, HOST)
    executed = score.score_test(_record(test_guid="test-2", execution_status="execution_failed"),
                                [_alert("2026-10-07 10:05:03.250 +00:00")], DERIVED, None, HOST)
    rows = score.score_rules(_sample(), [failed, executed], {RULE: None}, {})
    assert (rows[0].prerequisites_failed, rows[0].executed, rows[0].execution_failed) == (1, 1, 1)
    assert rows[0].detection_rate == 1.0


def test_rule_whose_tests_all_failed_prerequisites_is_marked_for_substitution():
    failed = score.score_test(_record(prereq_status="failed"), [], DERIVED, None, HOST)
    row = score.score_rules(_sample(), [failed], {RULE: None}, {})[0]
    assert row.detection_rate is None
    assert any("substitute" in note for note in row.notes)


def test_times_from_runner_and_hayabusa_are_both_utc():
    assert score.parse_time("2026-10-07T10:05:00.1234567Z") == score.parse_time("2026-10-07 10:05:00.123 +00:00") \
        .replace(microsecond=123456)
    assert score.parse_time("2026-10-07 15:35:00.000 +05:30") == score.parse_time("2026-10-07T10:05:00Z")
    with pytest.raises(score.ScoreError):
        score.parse_time("2026-10-07 10:05:00")          # no zone: refused, not guessed


def test_hayabusa_summary_parsing_survives_escape_codes():
    # Hayabusa writes reset codes even with -K (no colour).
    loaded = "\x1b[0mTotal detection rules: \x1b[0m2\n"
    assert score.parse_hayabusa_summary(loaded) == {"rule_parsing_errors": None, "total_detection_rules": 2}
    assert score.refused(score.parse_hayabusa_summary(loaded), 2) is None
    broken = "\x1b[38;2;255;0;0mRule parsing errors: 1\n\x1b[0mTotal detection rules: \x1b[0m0\n"
    assert "parsing error" in score.refused(score.parse_hayabusa_summary(broken), 1)
    assert "loaded 1 of 2" in score.refused({"total_detection_rules": 1}, 2)


# --------------------------------------------------------------------------- #
# Manifest and report, end to end on files
# --------------------------------------------------------------------------- #
def _sample():
    return {"strata": {
        "strong": [{"rank": 2, "technique_id": "T1056.001", "rule_id": RULE, "selected": True,
                    "art_tests": [{"guid": "test-1"}, {"guid": "test-2"}]}],
        "moderate": [], "weak": [],
    }}


def test_manifest_traces_converted_rules_by_related_id(tmp_path):
    staged, converted = tmp_path / "rules", tmp_path / "converted"
    staged.mkdir()
    (staged / "rule.yml").write_text(f"title: t\nid: {RULE}\n", encoding="utf-8")
    for flavour, derived in (("sysmon", "aaaaaaaa-0000-0000-0000-000000000001"),
                             ("builtin", "aaaaaaaa-0000-0000-0000-000000000002")):
        (converted / flavour).mkdir(parents=True)
        (converted / flavour / "rule.yml").write_text(
            f"title: t\nid: {derived}\nrelated:\n  - id: {RULE}\n    type: derived\n", encoding="utf-8")
    (converted / "sysmon" / "other.yml").write_text(
        "title: o\nid: bbbbbbbb-0000-0000-0000-000000000000\nrelated:\n  - id: someone-else\n    type: derived\n",
        encoding="utf-8")
    manifest = score.build_manifest(staged, converted)
    assert {item["id"] for item in manifest[RULE]["converted"]} == DERIVED


def test_report_writes_the_tables(tmp_path):
    results = tmp_path / "round1"
    folder = results / "strong-02-T1056.001" / "test-1"
    folder.mkdir(parents=True)
    (folder / "result.json").write_text(json.dumps(_record()), encoding="utf-8")
    (folder / "hayabusa.json").write_text(json.dumps({"expected_rules": 2, "total_detection_rules": 2}),
                                          encoding="utf-8")
    (folder / "alerts.jsonl").write_text(
        json.dumps(_alert("2026-10-07 10:05:03.250 +00:00")) + "\n"
        + json.dumps(_alert("2026-10-07 10:05:03.250 +00:00", computer="ELSEWHERE")) + "\n", encoding="utf-8")
    smoke = results / "smoke-00-SMOKE" / "smoke-1"
    smoke.mkdir(parents=True)
    (smoke / "result.json").write_text(json.dumps({"smoke_test": True}), encoding="utf-8")
    manifest = {"rules": {RULE: {"rule_file": "r.yml", "converted": [{"id": d} for d in sorted(DERIVED)]}}}

    rows = score.report(results, tmp_path / "scores", sample=_sample(), manifest=manifest)

    assert len(rows) == 1 and rows[0].detected == 1 and rows[0].executed == 1
    assert any("1 mapped test(s) not run yet" in note for note in rows[0].notes)
    with open(tmp_path / "scores" / "alerts.csv", encoding="utf-8") as handle:
        placements = sorted(row["placement"] for row in csv.DictReader(handle))
    assert placements == ["execution window", "other host"]
    assert "| strong | 2 | T1056.001 |" in (tmp_path / "scores" / "rules.md").read_text(encoding="utf-8")


def test_report_treats_a_hayabusa_refusal_as_a_conversion_failure(tmp_path):
    folder = tmp_path / "round1" / "strong-02-T1056.001" / "test-1"
    folder.mkdir(parents=True)
    (folder / "result.json").write_text(json.dumps(_record()), encoding="utf-8")
    (folder / "hayabusa.json").write_text(
        json.dumps({"expected_rules": 2, "rule_parsing_errors": 1, "total_detection_rules": 1}), encoding="utf-8")
    (folder / "alerts.jsonl").write_text(json.dumps(_alert("2026-10-07 10:05:03.250 +00:00")) + "\n",
                                         encoding="utf-8")
    manifest = {"rules": {RULE: {"rule_file": "r.yml", "converted": [{"id": d} for d in sorted(DERIVED)]}}}
    row = score.report(tmp_path / "round1", tmp_path / "scores", sample=_sample(), manifest=manifest)[0]
    assert row.conversion.startswith("failed") and row.detected == 0 and row.detection_rate == 0.0


def test_report_refuses_a_rule_missing_from_the_manifest(tmp_path):
    folder = tmp_path / "round1" / "strong-02-T1056.001" / "test-1"
    folder.mkdir(parents=True)
    (folder / "result.json").write_text(json.dumps(_record()), encoding="utf-8")
    with pytest.raises(score.ScoreError):
        score.report(tmp_path / "round1", tmp_path / "scores", sample=_sample(), manifest={"rules": {}})


def test_pins_match_the_protocol():
    protocol = (Path(score.ROOT) / "docs" / "validation-protocol.md").read_text(encoding="utf-8")
    assert score.CONVERTER_COMMIT in protocol
    assert score.HAYABUSA_TAG_COMMIT in protocol and f"v{score.HAYABUSA_VERSION}" in protocol
    for _, digest, _ in score.HAYABUSA_ASSETS.values():
        assert digest in protocol


def test_manifest_reads_correlation_files_by_their_first_document(tmp_path):
    staged, converted = tmp_path / "rules", tmp_path / "converted" / "sysmon"
    staged.mkdir()
    converted.mkdir(parents=True)
    (staged / "mr_chain.yml").write_text(
        f"title: chain\nid: {RULE}\ncorrelation:\n  type: temporal\n---\nname: step1\nid: base-0001\n", encoding="utf-8")
    (converted / "mr_chain.yml").write_text(
        f"title: chain\nid: aaaaaaaa-0000-0000-0000-000000000001\nrelated:\n  - id: {RULE}\n    type: derived\n"
        "---\nname: step1\nid: aaaaaaaa-0000-0000-0000-000000000009\nrelated:\n  - id: base-0001\n    type: derived\n",
        encoding="utf-8")
    manifest = score.build_manifest(staged, tmp_path / "converted")
    assert [item["id"] for item in manifest[RULE]["converted"]] == ["aaaaaaaa-0000-0000-0000-000000000001"]


REPLACEMENT = "cccccccc-0000-0000-0000-000000000000"
REPLACEMENT_DERIVED = "dddddddd-0000-0000-0000-000000000001"


def _sample_with_queue():
    sample = _sample()
    sample["strata"]["strong"][0]["art_tests"] = [{"guid": "test-1"}]
    sample["strata"]["strong"].append({"rank": 18, "technique_id": "T1560", "selected": False,
                                       "art_tests": [{"guid": "test-9"}]})
    return sample


def _replacement_run(tmp_path, substituted=True):
    results = tmp_path / "round1"
    failed = results / "strong-02-T1056.001" / "test-1"
    failed.mkdir(parents=True)
    (failed / "result.json").write_text(json.dumps(_record(prereq_status="failed", execution_status=None)),
                                        encoding="utf-8")
    ran = results / "strong-18-T1560" / "test-9"
    ran.mkdir(parents=True)
    (ran / "result.json").write_text(json.dumps(_record(technique_id="T1560", rule_id=REPLACEMENT,
                                                        test_guid="test-9")), encoding="utf-8")
    (ran / "hayabusa.json").write_text(json.dumps({"expected_rules": 1, "total_detection_rules": 1}), encoding="utf-8")
    (ran / "alerts.jsonl").write_text(
        json.dumps(_alert("2026-10-07 10:05:03.250 +00:00", rule_id=REPLACEMENT_DERIVED)) + "\n", encoding="utf-8")
    if substituted:
        (results / "substitutions.json").write_text(json.dumps({"substitutions": [{
            "tier": "strong", "replaced": {"technique_id": "T1056.001", "rank": 2, "rule_id": RULE},
            "replacement": {"technique_id": "T1560", "rank": 18, "rule_id": REPLACEMENT,
                            "rule_file": "population/rules/t1560.yml"}}]}), encoding="utf-8")
    manifest = {"rules": {RULE: {"rule_file": "r.yml", "converted": [{"id": d} for d in sorted(DERIVED)]},
                          REPLACEMENT: {"rule_file": "t1560.yml", "converted": [{"id": REPLACEMENT_DERIVED}]}}}
    population = {"rules": [{"technique_id": "T1560", "rule_id": REPLACEMENT, "rule_file": "rules/t1560.yml"}],
                  "correlations": []}
    return results, manifest, population


def test_report_scores_a_replacement_and_marks_the_rule_it_replaced(tmp_path):
    results, manifest, population = _replacement_run(tmp_path)
    rows = score.report(results, tmp_path / "scores", sample=_sample_with_queue(), manifest=manifest,
                        population=population)
    replaced, replacement = rows
    assert (replaced.technique_id, replaced.sample_status, replaced.executed) == ("T1056.001", "substituted", 0)
    assert "substituted by T1560" in replaced.notes[0]
    assert (replacement.technique_id, replacement.sample_status, replacement.detected) == ("T1560", "replacement", 1)
    with open(tmp_path / "scores" / "rules.csv", encoding="utf-8") as handle:
        assert [row["sample_status"] for row in csv.DictReader(handle)] == ["substituted", "replacement"]


def test_report_refuses_a_queued_rule_no_substitution_brought_in(tmp_path):
    results, manifest, population = _replacement_run(tmp_path, substituted=False)
    with pytest.raises(score.ScoreError, match="neither sampled nor"):
        score.report(results, tmp_path / "scores", sample=_sample_with_queue(), manifest=manifest,
                     population=population)


def test_queued_rules_are_converted_from_the_frozen_population():
    from tools import population

    sample = population.load_sample()
    files = score.rules_under_test(sample)
    assert len(files) == sum(len(rules) for rules in sample["strata"].values()) == 203
    assert all(path.is_file() for path in files)
    assert sum("population" in path.parts for path in files) == 153
