"""Round 1 evaluation (tools/evaluate.py): the interval methods against published values, and the
falsification rules of protocol section 12 on synthetic tiers."""

from __future__ import annotations

import csv

import pytest

from tools import evaluate


# --------------------------------------------------------------------------- #
# Interval methods
# --------------------------------------------------------------------------- #
def test_wilson_matches_the_published_value():
    low, high = evaluate.wilson(8, 10)
    assert (round(low, 4), round(high, 4)) == (0.4902, 0.9433)
    assert evaluate.wilson(0, 0) is None


@pytest.mark.parametrize("x1, n1, x2, n2, expected", [
    (56, 70, 48, 80, (0.0524, 0.3339)),     # Newcombe (1998), Statistics in Medicine 17:873, example (a)
    (9, 10, 3, 10, (0.1705, 0.8090)),       # example (e)
])
def test_newcombe_hybrid_score_matches_the_published_examples(x1, n1, x2, n2, expected):
    low, high = evaluate.newcombe(x1, n1, x2, n2)
    assert (round(low, 4), round(high, 4)) == expected


def test_percentile_is_linear_between_closest_ranks():
    assert evaluate.percentile([1, 2, 3, 4], 0.5) == 2.5
    assert evaluate.percentile([4, 1, 3, 2], 0.9) == pytest.approx(3.7)
    assert evaluate.percentile([7], 0.9) == 7


def test_bootstrap_is_seeded_and_the_same_on_every_python_version():
    # Pinned values: random.Random(str) and Random.choices are stable across versions, and means use
    # math.fsum because sum() of floats rounds differently from Python 3.12 on.
    rates = [0.0, 1.0, 0.5, 0.25, 1.0, 0.0, 0.333, 0.9, 0.1, 0.75]
    seed = "9eb19300d089bf6766b9090407225a64fda3176e"
    assert evaluate.bootstrap_mean(rates, seed, resamples=2000) == (0.25325749999999997, 0.7232999999999999)
    assert evaluate.bootstrap_difference(rates, rates[::-1][:7], seed, resamples=2000) == \
        (-0.3631396428571429, 0.37104285714285695)
    assert evaluate.bootstrap_mean(rates, "another seed", resamples=2000) != (0.25325749999999997, 0.7232999999999999)
    assert evaluate.bootstrap_mean([0.5, 0.5], "s", resamples=100) == (0.5, 0.5)
    low, high = evaluate.bootstrap_difference([1.0] * 5, [0.0] * 5, "s", resamples=100)
    assert (low, high) == (1.0, 1.0)


# --------------------------------------------------------------------------- #
# Section 12
# --------------------------------------------------------------------------- #
def _tier(rates):
    return evaluate.DetectionTier(
        tier="t", drawn=len(rates), substituted=0, in_sample=len(rates), evaluated=len(rates), eligible=0,
        population=0, tests_mapped=len(rates), executed=len(rates), prerequisites_failed=0, execution_failed=0,
        confounded=0, conversion_failures=0, rates=list(rates), detecting_rules=sum(1 for r in rates if r),
        detected_tests=0, complete=True)


def _noise(zero, measured):
    return evaluate.NoiseGroup("t", measured, 0, measured, zero, [0.0] * measured)


def test_weak_detecting_as_well_as_strong_falsifies_on_detection():
    result = evaluate.detection_criterion(_tier([0.5, 0.5]), _tier([0.5, 0.5]), "seed")
    assert result["outcome"] == "falsified"            # "greater than or equal to"


def test_detection_supported_only_when_the_interval_excludes_zero():
    clear = evaluate.detection_criterion(_tier([1.0] * 17), _tier([0.0] * 16), "seed")
    assert clear["outcome"] == "supported" and clear["interval"][0] > 0
    close = evaluate.detection_criterion(_tier([1.0, 0.0, 1.0, 0.0, 0.6]), _tier([1.0, 0.0, 1.0, 0.0, 0.5]), "seed")
    assert close["outcome"] == "inconclusive"


def test_noise_criterion_uses_the_zero_alert_day_share():
    assert evaluate.noise_criterion(_noise(30, 76), _noise(60, 123))["outcome"] == "falsified"   # 0.39 <= 0.49
    assert evaluate.noise_criterion(_noise(5, 10), _noise(5, 10))["outcome"] == "falsified"     # equal is falsified
    assert evaluate.noise_criterion(_noise(70, 76), _noise(30, 123))["outcome"] == "supported"
    assert evaluate.noise_criterion(_noise(5, 10), _noise(4, 10))["outcome"] == "inconclusive"
    assert evaluate.noise_criterion(_noise(0, 0), _noise(4, 10))["outcome"] == "not evaluated"


def test_verdict_puts_falsification_first_and_needs_a_complete_run():
    detection = {"outcome": "falsified", "weak_mean": 0.6, "strong_mean": 0.5}
    noise = {"outcome": "supported", "strong_zero_share": 0.9, "weak_zero_share": 0.4}
    assert evaluate.verdict(detection, noise, noise, complete=False)["verdict"] == "no verdict"
    result = evaluate.verdict(detection, noise, noise, complete=True)
    assert result["verdict"] == "falsified" and result["headline"].startswith("The grading model is falsified on detection")
    changed = evaluate.verdict({"outcome": "supported"}, noise, {"outcome": "inconclusive"}, complete=True)
    assert changed["verdict"] == "supported" and "inconclusive instead of supported" in changed["sensitivity"]


# --------------------------------------------------------------------------- #
# From the tables, end to end
# --------------------------------------------------------------------------- #
def _write(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def test_evaluate_reads_the_score_tables_and_withholds_the_verdict_until_complete(tmp_path):
    sample = {"seed": "seed", "quota": {"strong": 1, "moderate": 0, "weak": 1},
              "population": {t: {"default_rules": 2, "eligible": 1} for t in ("strong", "moderate", "weak")},
              "strata": {"strong": [{"technique_id": "T1", "rank": 1, "selected": True, "rule_id": "s1",
                                     "art_tests": [{"guid": "a"}, {"guid": "b"}]}],
                         "moderate": [],
                         "weak": [{"technique_id": "T2", "rank": 1, "selected": True, "rule_id": "w1",
                                   "art_tests": [{"guid": "c"}]}]}}
    base = {"sample_status": "sampled", "conversion": "ok", "confounded": 0, "harness_errors": 0,
            "prerequisites_failed": 0, "execution_failed": 0}
    _write(tmp_path / "scores" / "rules.csv", [
        dict(base, tier="strong", rule_id="s1", recorded=2, executed=2, detected=2),
        dict(base, tier="weak", rule_id="w1", recorded=1, executed=1, detected=0)])
    noise_base = {"kind": "rule", "type": "", "conversion": "ok", "real_endpoint_primary_host_days": 7,
                  "real_endpoint_without_minimum_host_days": 8}
    _write(tmp_path / "benign" / "rules.csv", [
        dict(noise_base, tier="strong", real_endpoint_primary_alert_days=0, real_endpoint_primary_rate="0.0",
             real_endpoint_without_minimum_alert_days=0, real_endpoint_without_minimum_rate="0.0",
             lab_vm_primary_alert_days="", lab_vm_primary_rate="", lab_vm_without_minimum_alert_days="",
             lab_vm_without_minimum_rate=""),
        dict(noise_base, tier="weak", real_endpoint_primary_alert_days=3, real_endpoint_primary_rate="0.4286",
             real_endpoint_without_minimum_alert_days=3, real_endpoint_without_minimum_rate="0.375",
             lab_vm_primary_alert_days="", lab_vm_primary_rate="", lab_vm_without_minimum_alert_days="",
             lab_vm_without_minimum_rate="")])
    population = {"rules": [], "correlations": []}

    summary = evaluate.evaluate(tmp_path / "scores", tmp_path / "benign", tmp_path / "round1",
                                sample=sample, population=population)

    assert summary["detection_complete"] is True
    assert summary["detection"]["strong"]["mean_rate"] == 1.0 and summary["detection"]["weak"]["mean_rate"] == 0.0
    assert summary["noise_criterion"]["strong_zero_share"] == 1.0
    assert summary["verdict"]["verdict"] in ("supported", "inconclusive")     # one rule per tier: wide intervals
    assert summary["markdown"].startswith("**")

    _write(tmp_path / "scores" / "rules.csv", [
        dict(base, tier="strong", rule_id="s1", recorded=1, executed=1, detected=1),
        dict(base, tier="weak", rule_id="w1", recorded=1, executed=1, detected=0)])
    partial = evaluate.evaluate(tmp_path / "scores", tmp_path / "benign", tmp_path / "round1",
                                sample=sample, population=population)
    assert partial["verdict"]["verdict"] == "no verdict"
    assert partial["detection"]["strong"]["pending"] == ["T1: 1 of 2 test(s) recorded"]
