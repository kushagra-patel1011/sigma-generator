"""Round 1 evaluation: the measures per tier (protocol section 11) and the falsification test (section 12).

Reads the tables the scoring steps write, never the raw logs, so every number here can be recomputed from
published files:

* detection: ``rules.csv`` from ``python -m tools.score report`` (default ``output/round1-scores``), with
  the sample and the recorded substitutions (``<results>/substitutions.json``);
* false positives: ``rules.csv`` from ``python -m tools.benign report`` (default ``output/benign-scores``).

    python -m tools.evaluate            # writes output/round1-evaluation/summary.md and summary.json

Either input may be missing, for example after the pilot, which has no benign data. The verdict of section
12 is only given when the detection run is complete (every mapped test of every rule in the sample
recorded, no substitution pending, no harness error) and the real endpoint has host-days. Until then the
measures are printed with "no verdict". The statistical choices the protocol leaves open are fixed in its
amendment 4.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import sys
from dataclasses import dataclass, field
from pathlib import Path
from statistics import NormalDist
from typing import Any, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.utils import write_text  # noqa: E402
from tools import population as pop  # noqa: E402
from tools import substitute  # noqa: E402

TIERS = ("strong", "moderate", "weak")
CORRELATION_TYPES = ("temporal", "event_count", "value_count")
ROLES = ("real_endpoint", "lab_vm")
DAY_SETS = ("primary", "without_minimum")
RESAMPLES = 10_000
Z95 = NormalDist().inv_cdf(0.975)

DEFAULT_SCORES = ROOT / "output" / "round1-scores"
DEFAULT_BENIGN_SCORES = ROOT / "output" / "benign-scores"
DEFAULT_OUT = ROOT / "output" / "round1-evaluation"

Interval = Optional[tuple[float, float]]


class EvaluationError(Exception):
    """An input table is missing a column or contradicts the sample."""


# --------------------------------------------------------------------------- #
# Statistics (amendment 4 fixes each definition)
# --------------------------------------------------------------------------- #
def percentile(values: Sequence[float], q: float) -> float:
    """Linear interpolation between the closest ranks (Hyndman and Fan type 7, as numpy's default)."""
    if not values:
        raise ValueError("percentile of no values")
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    low = math.floor(position)
    high = min(low + 1, len(ordered) - 1)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def wilson(successes: int, n: int, z: float = Z95) -> Interval:
    """Wilson score interval for a proportion."""
    if n == 0:
        return None
    p = successes / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(0.0, centre - half), min(1.0, centre + half)


def newcombe(x1: int, n1: int, x2: int, n2: int, z: float = Z95) -> Interval:
    """Newcombe's hybrid score interval for p1 - p2 (Newcombe 1998, method 10), from two Wilson intervals."""
    first, second = wilson(x1, n1, z), wilson(x2, n2, z)
    if first is None or second is None:
        return None
    p1, p2 = x1 / n1, x2 / n2
    (l1, u1), (l2, u2) = first, second
    difference = p1 - p2
    return (difference - math.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2),
            difference + math.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2))


def mean(values: Sequence[float]) -> float:
    """``math.fsum`` is correctly rounded, so a mean is the same on every Python version (``sum`` of floats
    changed its rounding in 3.12)."""
    return math.fsum(values) / len(values)


def bootstrap_mean(values: Sequence[float], seed: str, resamples: int = RESAMPLES) -> Interval:
    """95% percentile bootstrap interval of the mean, resampling rules with replacement."""
    if not values:
        return None
    rng = random.Random(seed)
    means = [mean(rng.choices(values, k=len(values))) for _ in range(resamples)]
    return percentile(means, 0.025), percentile(means, 0.975)


def bootstrap_difference(first: Sequence[float], second: Sequence[float], seed: str,
                         resamples: int = RESAMPLES) -> Interval:
    """95% percentile bootstrap interval of mean(first) - mean(second), each tier resampled on its own."""
    if not first or not second:
        return None
    rng = random.Random(seed)
    differences = []
    for _ in range(resamples):
        a = rng.choices(first, k=len(first))
        b = rng.choices(second, k=len(second))
        differences.append(mean(a) - mean(b))
    return percentile(differences, 0.025), percentile(differences, 0.975)


# --------------------------------------------------------------------------- #
# Reading the tables
# --------------------------------------------------------------------------- #
def read_csv(path: Path, required: Sequence[str]) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    missing = [c for c in required if rows and c not in rows[0]]
    if missing:
        raise EvaluationError(f"{path}: missing column(s) {', '.join(missing)}")
    return rows


def _int(row: dict[str, str], column: str) -> int:
    return int(row[column] or 0)


# --------------------------------------------------------------------------- #
# Detection (the sample)
# --------------------------------------------------------------------------- #
@dataclass
class DetectionTier:
    tier: str
    drawn: int
    substituted: int
    in_sample: int
    evaluated: int
    eligible: int
    population: int
    tests_mapped: int
    executed: int
    prerequisites_failed: int
    execution_failed: int
    confounded: int
    conversion_failures: int
    rates: list[float]
    detecting_rules: int
    detected_tests: int
    complete: bool
    pending: list[str] = field(default_factory=list)

    @property
    def mean_rate(self) -> Optional[float]:
        return mean(self.rates) if self.rates else None


def detection_tiers(rows: Sequence[dict[str, str]], sample: dict[str, Any],
                    current: dict[str, list[dict[str, Any]]]) -> dict[str, DetectionTier]:
    by_rule = {row["rule_id"]: row for row in rows}
    tiers = {}
    for tier in TIERS:
        rules = current[tier]
        scored = [by_rule[r["rule_id"]] for r in rules if r["rule_id"] in by_rule]
        evaluated = [row for row in scored if _int(row, "executed")]
        pending = []
        for rule in rules:
            row = by_rule.get(rule["rule_id"])
            mapped = len(rule["art_tests"])
            if row is None:
                pending.append(f"{rule['technique_id']}: no test recorded")
            elif _int(row, "recorded") < mapped or _int(row, "harness_errors"):
                pending.append(f"{rule['technique_id']}: {_int(row, 'recorded')} of {mapped} test(s) recorded")
            elif not _int(row, "executed"):
                pending.append(f"{rule['technique_id']}: substitution due")
        tiers[tier] = DetectionTier(
            tier=tier, drawn=int(sample["quota"][tier]),
            substituted=sum(1 for row in rows if row["tier"] == tier and row.get("sample_status") == "substituted"),
            in_sample=len(rules), evaluated=len(evaluated),
            eligible=int(sample["population"][tier]["eligible"]),
            population=int(sample["population"][tier]["default_rules"]),
            tests_mapped=sum(len(r["art_tests"]) for r in rules),
            executed=sum(_int(row, "executed") for row in scored),
            prerequisites_failed=sum(_int(row, "prerequisites_failed") for row in scored),
            execution_failed=sum(_int(row, "execution_failed") for row in scored),
            confounded=sum(_int(row, "confounded") for row in scored),
            conversion_failures=sum(1 for row in scored if row["conversion"] != "ok"),
            rates=[_int(row, "detected") / _int(row, "executed") for row in evaluated],
            detecting_rules=sum(1 for row in evaluated if _int(row, "detected")),
            detected_tests=sum(_int(row, "detected") for row in evaluated),
            complete=not pending, pending=pending,
        )
    return tiers


# --------------------------------------------------------------------------- #
# False positives (the whole Windows population)
# --------------------------------------------------------------------------- #
@dataclass
class NoiseGroup:
    label: str
    rules: int
    conversion_failures: int
    measured: int                  # rules that converted, over a role with host-days
    zero: int
    rates: list[float]


def noise_groups(rows: Sequence[dict[str, str]], role: str, day_set: str) -> dict[str, NoiseGroup]:
    """Per tier for rules, and per type for correlation rules."""
    groups: dict[str, list[dict[str, str]]] = {tier: [] for tier in TIERS}
    groups.update({kind: [] for kind in CORRELATION_TYPES})
    for row in rows:
        key = row["tier"] if row["kind"] == "rule" else row["type"]
        groups.setdefault(key, []).append(row)
    result = {}
    for label, members in groups.items():
        rate_column = f"{role}_{day_set}_rate"
        measured = [row for row in members if row["conversion"] == "ok" and row[rate_column] != ""]
        result[label] = NoiseGroup(
            label=label, rules=len(members), conversion_failures=sum(1 for r in members if r["conversion"] != "ok"),
            measured=len(measured), zero=sum(1 for r in measured if _int(r, f"{role}_{day_set}_alert_days") == 0),
            rates=[float(r[rate_column]) for r in measured])
    return result


# --------------------------------------------------------------------------- #
# Section 12
# --------------------------------------------------------------------------- #
def detection_criterion(strong: DetectionTier, weak: DetectionTier, seed: str) -> dict[str, Any]:
    if strong.mean_rate is None or weak.mean_rate is None:
        return {"outcome": "not evaluated", "reason": "a tier has no evaluated rule"}
    interval = bootstrap_difference(strong.rates, weak.rates, seed)
    if weak.mean_rate >= strong.mean_rate:
        outcome = "falsified"
    elif interval is not None and interval[0] > 0:
        outcome = "supported"
    else:
        outcome = "inconclusive"
    return {"outcome": outcome, "strong_mean": strong.mean_rate, "weak_mean": weak.mean_rate,
            "difference": strong.mean_rate - weak.mean_rate, "interval": interval}


def noise_criterion(strong: NoiseGroup, weak: NoiseGroup) -> dict[str, Any]:
    if not strong.measured or not weak.measured:
        return {"outcome": "not evaluated", "reason": "no real-endpoint host-days, or no rule measured in a tier"}
    strong_share, weak_share = strong.zero / strong.measured, weak.zero / weak.measured
    interval = newcombe(strong.zero, strong.measured, weak.zero, weak.measured)
    if strong_share <= weak_share:
        outcome = "falsified"
    elif interval is not None and interval[0] > 0:
        outcome = "supported"
    else:
        outcome = "inconclusive"
    return {"outcome": outcome, "strong_zero_share": strong_share, "weak_zero_share": weak_share,
            "difference": strong_share - weak_share, "interval": interval}


def verdict(detection: dict[str, Any], noise: dict[str, Any], noise_without_minimum: dict[str, Any],
            complete: bool) -> dict[str, Any]:
    if not complete:
        return {"verdict": "no verdict", "headline": "No verdict: the detection run is not complete, so these are "
                "not tier results (protocol sections 11 and 12)."}
    if "not evaluated" in (detection["outcome"], noise["outcome"]):
        return {"verdict": "no verdict", "headline": "No verdict: "
                + (detection.get("reason") or noise.get("reason") or "a criterion could not be evaluated") + "."}
    falsified = []
    if detection["outcome"] == "falsified":
        falsified.append(f"on detection: weak rules' mean per-rule detection rate ({detection['weak_mean']:.2f}) "
                         f"is at least the strong rules' ({detection['strong_mean']:.2f})")
    if noise["outcome"] == "falsified":
        falsified.append(f"on noise: on the real endpoint, the share of strong rules with zero alert-days "
                         f"({noise['strong_zero_share']:.2f}) is at most the weak rules' ({noise['weak_zero_share']:.2f})")
    if falsified:
        result, headline = "falsified", "The grading model is falsified " + "; and ".join(falsified) + "."
    elif detection["outcome"] == "supported" and noise["outcome"] == "supported":
        result = "supported"
        headline = ("The grading model is supported: strong rules detect more and are quiet more often than weak "
                    "rules, and both 95% intervals of the differences exclude zero.")
    else:
        result = "inconclusive"
        headline = ("The comparison is inconclusive: strong rules are not shown to be better than weak rules on both "
                    "measures with intervals that exclude zero. This is not support.")
    sensitivity = ""
    if noise_without_minimum["outcome"] != noise["outcome"]:
        sensitivity = (f"Without the 4-active-hour minimum the noise criterion is {noise_without_minimum['outcome']} "
                       f"instead of {noise['outcome']} (protocol section 11).")
    return {"verdict": result, "headline": headline, "sensitivity": sensitivity}


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def _pct(value: Optional[float]) -> str:
    return "—" if value is None else f"{value:.2f}"


def _ci(interval: Interval) -> str:
    return "—" if interval is None else f"[{interval[0]:.2f}, {interval[1]:.2f}]"


def evaluate(scores: Optional[Path], benign_scores: Optional[Path], results: Path,
             sample: Optional[dict[str, Any]] = None, population: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    sample = sample if sample is not None else pop.load_sample()
    population = population if population is not None else pop.load_population()
    seed = str(sample["seed"])
    summary: dict[str, Any] = {"seed": seed, "resamples": RESAMPLES}
    lines: list[str] = []

    detection_rows = []
    if scores is not None and (scores / "rules.csv").is_file():
        detection_rows = read_csv(scores / "rules.csv", ["tier", "rule_id", "sample_status", "conversion", "recorded",
                                                          "executed", "detected", "confounded", "harness_errors"])
    current = substitute.current_sample(sample, substitute.load_substitutions(results), population)
    tiers = detection_tiers(detection_rows, sample, current)
    complete = bool(detection_rows) and all(t.complete for t in tiers.values())

    noise_rows = []
    if benign_scores is not None and (benign_scores / "rules.csv").is_file():
        noise_rows = read_csv(benign_scores / "rules.csv", ["kind", "tier", "type", "conversion"])
    noise = {(role, day_set): noise_groups(noise_rows, role, day_set) for role in ROLES for day_set in DAY_SETS}

    det = detection_criterion(tiers["strong"], tiers["weak"], seed)
    nz = noise_criterion(noise[("real_endpoint", "primary")]["strong"], noise[("real_endpoint", "primary")]["weak"])
    nz_all = noise_criterion(noise[("real_endpoint", "without_minimum")]["strong"],
                             noise[("real_endpoint", "without_minimum")]["weak"])
    outcome = verdict(det, nz, nz_all, complete)
    summary.update({"verdict": outcome, "detection_criterion": det, "noise_criterion": nz,
                    "noise_criterion_without_minimum": nz_all, "detection_complete": complete})

    lines += [f"**{outcome['headline']}**", ""]
    if outcome.get("sensitivity"):
        lines += [outcome["sensitivity"], ""]
    lines += ["## Detection (the sample; the rule is the unit)", "",
              "| Tier | Drawn | Substituted | Evaluated | Eligible / population | ART tests mapped | Executed "
              "| Prerequisites failed | Execution failed | Confounded | Telemetry absent | Conversion failures "
              "| Mean per-rule detection rate [95% bootstrap] | Rules detecting ≥1 test [Wilson 95%] "
              "| Pooled test detection rate [Wilson 95%] |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    summary["detection"] = {}
    for tier, t in tiers.items():
        rate_ci = bootstrap_mean(t.rates, seed)
        share = t.detecting_rules / t.evaluated if t.evaluated else None
        pooled = t.detected_tests / t.executed if t.executed else None
        summary["detection"][tier] = {
            "drawn": t.drawn, "substituted": t.substituted, "evaluated": t.evaluated, "eligible": t.eligible,
            "population": t.population, "tests_mapped": t.tests_mapped, "executed": t.executed,
            "prerequisites_failed": t.prerequisites_failed, "execution_failed": t.execution_failed,
            "confounded": t.confounded, "telemetry_absent": "not computed (amendment 3)",
            "conversion_failures": t.conversion_failures, "mean_rate": t.mean_rate, "mean_rate_interval": rate_ci,
            "rules_detecting": t.detecting_rules, "rules_detecting_share": share,
            "rules_detecting_interval": wilson(t.detecting_rules, t.evaluated),
            "pooled_rate": pooled, "pooled_interval": wilson(t.detected_tests, t.executed), "pending": t.pending}
        lines.append(
            f"| {tier} | {t.drawn} | {t.substituted} | {t.evaluated} | {t.eligible} / {t.population} | {t.tests_mapped} "
            f"| {t.executed} | {t.prerequisites_failed} | {t.execution_failed} | {t.confounded} | not computed "
            f"| {t.conversion_failures} | {_pct(t.mean_rate)} {_ci(rate_ci)} "
            f"| {t.detecting_rules}/{t.evaluated} {_ci(wilson(t.detecting_rules, t.evaluated))} "
            f"| {_pct(pooled)} {_ci(wilson(t.detected_tests, t.executed))} |")
    lines += ["", "Eligibility favours strong rules: 83% of strong rules were eligible against 49% of weak ones "
              "(protocol section 3). Correlation rules are untested for detection in round 1.", ""]
    pending = [p for t in tiers.values() for p in t.pending]
    if pending:
        lines += [f"Not complete ({len(pending)} rule(s)): " + "; ".join(pending), ""]

    summary["false_positives"] = {}
    lines += ["## False positives (every Windows rule; a lower bound, 1 real endpoint + N lab VMs)", ""]
    if not noise_rows:
        lines += ["No benign data scored yet.", ""]
    for role in ROLES:
        for day_set in DAY_SETS:
            title = f"{role.replace('_', ' ')}, " + ("primary" if day_set == "primary"
                                                     else "without the 4-active-hour minimum (sensitivity)")
            lines += [f"### {title}", "",
                      "| Rules | Count | Conversion failures | Measured | Zero alert-days [Wilson 95%] "
                      "| Alert-days per host-day: median | 90th percentile | maximum |",
                      "|---|---|---|---|---|---|---|---|"]
            block = {}
            for label, group in noise[(role, day_set)].items():
                share = group.zero / group.measured if group.measured else None
                interval = wilson(group.zero, group.measured)
                median = percentile(group.rates, 0.5) if group.rates else None
                p90 = percentile(group.rates, 0.9) if group.rates else None
                top = max(group.rates) if group.rates else None
                block[label] = {"rules": group.rules, "conversion_failures": group.conversion_failures,
                                "measured": group.measured, "zero": group.zero, "zero_share": share,
                                "zero_interval": interval, "median": median, "p90": p90, "max": top}
                lines.append(f"| {label} | {group.rules} | {group.conversion_failures} | {group.measured} "
                             f"| {_pct(share)} {_ci(interval)} | {_pct(median)} | {_pct(p90)} | {_pct(top)} |")
            summary["false_positives"][f"{role}/{day_set}"] = block
            lines.append("")

    lines += ["## Falsification criteria (protocol section 12)", "",
              f"- Detection: {det['outcome']}" + (
                  f". Strong mean {det['strong_mean']:.3f}, weak mean {det['weak_mean']:.3f}, difference "
                  f"{det['difference']:.3f}, 95% bootstrap interval {_ci(det['interval'])}." if "difference" in det
                  else f" ({det.get('reason')})."),
              f"- Noise on the real endpoint: {nz['outcome']}" + (
                  f". Zero-alert-day share strong {nz['strong_zero_share']:.3f}, weak {nz['weak_zero_share']:.3f}, "
                  f"difference {nz['difference']:.3f}, Newcombe 95% interval {_ci(nz['interval'])}." if "difference" in nz
                  else f" ({nz.get('reason')})."),
              f"- Noise without the 4-active-hour minimum: {nz_all['outcome']}.", ""]
    summary["markdown"] = "\n".join(lines) + "\n"
    return summary


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.evaluate", description=__doc__.split("\n\n")[0])
    parser.add_argument("--scores", type=Path, default=DEFAULT_SCORES,
                        help="tools.score report output (default: output/round1-scores)")
    parser.add_argument("--benign-scores", type=Path, default=DEFAULT_BENIGN_SCORES,
                        help="tools.benign report output (default: output/benign-scores)")
    parser.add_argument("--results", type=Path, default=substitute.DEFAULT_RESULTS,
                        help="the runner's results folder, for substitutions.json (default: output/round1)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="default: output/round1-evaluation")
    args = parser.parse_args(argv)
    try:
        summary = evaluate(args.scores, args.benign_scores, args.results)
    except (EvaluationError, substitute.SubstitutionError, pop.PopulationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    write_text(args.out / "summary.md", summary["markdown"])
    write_text(args.out / "summary.json", json.dumps({k: v for k, v in summary.items() if k != "markdown"},
                                                     indent=1) + "\n")
    print(summary["markdown"], end="")
    print(f"Wrote summary.md and summary.json to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
